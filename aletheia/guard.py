"""Runtime enforcement: verify at admission, enforce at import.

The scanner tells you a bundle is lying. The guard makes the lie
unexecutable:

  ADMIT     A bundle is admitted only when every module's bytecode
            matches its source. A signed manifest records the trusted
            reference hash of each module. Traps are refused at the door.

  ENFORCE   A meta_path hook runs inside the agent's own process. Every
            import from a guarded bundle is re-verified against the
            manifest: source changed, module unlisted, or bytecode that
            doesn't match the admission reference raises ImportError
            before a single instruction executes.

This is the difference between an antivirus that finds malware and a
runtime that cannot run it.
"""
from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import json
import marshal
import os
import sys
from dataclasses import dataclass, field

from .differ import diff_code_objects

MANIFEST_DIR = ".aletheia"
MANIFEST_NAME = "manifest.json"
MANIFEST_VERSION = 1


def code_object_hash(code) -> str:
    """Deterministic hash of a code object's semantics."""
    return hashlib.sha256(marshal.dumps(code)).hexdigest()


def source_hash(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _iter_sources(bundle: str):
    for dirpath, dirnames, filenames in os.walk(bundle):
        dirnames[:] = [d for d in dirnames
                       if d not in ("__pycache__", ".git", MANIFEST_DIR,
                                    ".venv", "node_modules")]
        for fn in sorted(filenames):
            if fn.endswith(".py"):
                yield os.path.join(dirpath, fn)


def _iter_pycs(bundle: str):
    for dirpath, dirnames, filenames in os.walk(bundle):
        if os.path.basename(dirpath) != "__pycache__":
            continue
        for fn in sorted(filenames):
            if fn.endswith(".pyc"):
                yield os.path.join(dirpath, fn)


def _executed_code(src: str):
    """Return the code object the LOADER would actually execute for src.

    Uses SourceFileLoader.get_code, which consults the .pyc cache exactly
    like import does: a valid cache is executed without recompiling.
    Returns None when the cache cannot be loaded by this interpreter.
    """
    loader = importlib.machinery.SourceFileLoader("__aletheia_probe__", src)
    try:
        return loader.get_code("__aletheia_probe__")
    except Exception:
        return None


@dataclass
class AdmissionResult:
    bundle: str
    admitted: bool
    refused: list = field(default_factory=list)  # [(relpath, reason)]
    modules: int = 0
    manifest_path: str | None = None


def admit(bundle: str) -> AdmissionResult:
    """Verify every module and write the admission manifest.

    Fails closed: any mismatch, stray/sourceless bytecode, or bytecode
    compiled for a different interpreter refuses the whole bundle.
    """
    bundle = os.path.abspath(bundle)
    refused: list[tuple[str, str]] = []
    entries: dict[str, dict] = {}

    sources = list(_iter_sources(bundle))

    # 1. bytecode must be loadable by THIS interpreter and match source
    for src in sources:
        rel = os.path.relpath(src, bundle)
        with open(src, "rb") as f:
            source_bytes = f.read()
        reference = compile(source_bytes, src, "exec", dont_inherit=True)

        executed = _executed_code(src)
        if executed is None:
            pyc = importlib.util.cache_from_source(src)
            if os.path.isfile(pyc):
                refused.append((rel, "bytecode cache cannot be loaded by this "
                                     "interpreter (compiled for another version)"))
            continue
        diffs = diff_code_objects(reference, executed)
        if diffs:
            refused.append((rel, f"executed bytecode differs from source in "
                                 f"{len(diffs)} place(s) — PyCache Trap pattern"))
            continue
        entries[rel] = {
            "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
            "code_sha256": code_object_hash(reference),
        }

    # 2. no sourceless or stray bytecode anywhere
    for pyc in _iter_pycs(bundle):
        stem = os.path.basename(pyc).split(".")[0]
        parent = os.path.dirname(os.path.dirname(pyc))
        if not os.path.isfile(os.path.join(parent, stem + ".py")):
            refused.append((os.path.relpath(pyc, bundle),
                            "sourceless bytecode: no source to verify against"))
            continue
        try:
            with open(pyc, "rb") as f:
                importlib.util  # noqa
                magic_ok = f.read(4) == importlib.util.MAGIC_NUMBER
        except Exception:
            magic_ok = False
        if not magic_ok:
            refused.append((os.path.relpath(pyc, bundle),
                            "bytecode compiled for a different interpreter"))

    if refused or not sources:
        if not sources and not refused:
            refused.append((".", "no Python modules found in bundle"))
        return AdmissionResult(bundle, False, refused, 0, None)

    manifest = {
        "version": MANIFEST_VERSION,
        "bundle": os.path.basename(bundle),
        "interpreter": f"{sys.version_info.major}.{sys.version_info.minor}",
        "modules": entries,
    }
    mdir = os.path.join(bundle, MANIFEST_DIR)
    os.makedirs(mdir, exist_ok=True)
    mpath = os.path.join(mdir, MANIFEST_NAME)
    with open(mpath, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return AdmissionResult(bundle, True, [], len(entries), mpath)


class AletheiaGuard:
    """Meta-path hook: refuses to execute unverified code from a bundle.

    Install into an agent's process, then every import from the bundle is
    re-verified against the admission manifest before execution.
    """

    def __init__(self, manifest_path: str):
        with open(manifest_path, encoding="utf-8") as f:
            self.manifest = json.load(f)
        # <bundle>/.aletheia/manifest.json -> <bundle>
        self.root = os.path.dirname(os.path.dirname(os.path.abspath(manifest_path)))
        self.blocked: list[tuple[str, str]] = []
        self.checked = 0
        self._installed = False

    # -- meta_path finder protocol -------------------------------------

    def find_spec(self, fullname, path=None, target=None):
        src = self._locate(fullname)
        if src is None:
            return None
        self.checked += 1
        rel = os.path.relpath(src, self.root)

        entry = self.manifest["modules"].get(rel)
        if entry is None:
            return self._refuse(fullname, "module is not in the admission manifest")
        if source_hash(src) != entry["source_sha256"]:
            return self._refuse(fullname, "source file changed since admission")
        loader = importlib.machinery.SourceFileLoader(fullname, src)
        try:
            code = loader.get_code(fullname)
        except Exception as e:
            return self._refuse(fullname, f"bytecode unloadable: {e}")
        if code is None or code_object_hash(code) != entry["code_sha256"]:
            return self._refuse(
                fullname,
                "executed bytecode does not match the admission manifest — "
                "post-admission tampering")

        # verified: hand the module to the standard loader machinery
        spec = importlib.util.spec_from_file_location(fullname, src, loader=loader)
        return spec

    def _refuse(self, fullname: str, reason: str):
        self.blocked.append((fullname, reason))
        raise ImportError(
            f"ALETHEIA BLOCKED: import of {fullname!r} refused — {reason}")

    def _locate(self, fullname: str) -> str | None:
        parts = fullname.split(".")
        base = os.path.join(self.root, *parts)
        if os.path.isfile(base + ".py"):
            return base + ".py"
        pkg_init = os.path.join(base, "__init__.py")
        if os.path.isfile(pkg_init):
            return pkg_init
        return None

    # -- lifecycle ------------------------------------------------------

    def install(self) -> "AletheiaGuard":
        if not self._installed:
            sys.meta_path.insert(0, self)
            self._installed = True
        return self

    def uninstall(self) -> "AletheiaGuard":
        if self._installed and self in sys.meta_path:
            sys.meta_path.remove(self)
            self._installed = False
        return self

    def report(self) -> dict:
        return {
            "bundle": self.manifest.get("bundle"),
            "root": self.root,
            "imports_checked": self.checked,
            "imports_blocked": [{"module": m, "reason": r}
                                for m, r in self.blocked],
        }
