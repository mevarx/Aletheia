"""The hard guard: enforcement that survives its own bypasses.

The original guard (AletheiaGuard) hooks sys.meta_path — the IMPORT path.
Measured against real bypasses (aletheia/attack.py), that stops
plain import but not:

  importlib.util.spec_from_file_location  — constructs a loader directly
  exec(marshal.loads(pyc_bytes))          — skips the loader entirely
  runpy.run_path                          — script-style execution
  compile+exec of source text             — never touches the pyc

The fix is a PROCESS-WIDE audit hook (PEP 578). sys.addaudithook sees
every code-execution event regardless of path:

  "compile"   — every compile() call, including py_compile and exec
  "exec"      — every exec()/eval() of a code object
  "import"    — the import machinery itself
  "open"      — every file open (used to verify bundle bytecode reads)

Next-level handling in this version (beyond filename watching):

  * exec events carry a CODE OBJECT, not a path — so exec(marshal.loads())
    has no filename to check. The guard therefore keeps the set of
    trusted code hashes from the admission manifest and:
      - allows exec when the code hash is a trusted admission reference;
      - blocks exec of code from INSIDE the bundle whose hash is untrusted
        (post-admission pyc swap, direct-loader execution);
      - blocks exec (from ANY path, including copies staged outside the
        bundle) of code carrying exfiltration signals
        (collector endpoint / _harvest / _ship).
  * compile events carry SOURCE TEXT — source containing exfiltration
    signals is refused before it can become executable bytecode.
  * import events carry a MODULE NAME — names resolving to files inside
    the guarded bundle are re-verified (source_sha256 + loader bytecode
    hash) exactly like the soft guard does.
  * open events on bundle bytecode-cache (.pyc) reads are re-verified so
    a tampered cache is refused at read time, before any loader or
    marshal call. (Source reads are deliberately NOT refused: runpy and
    compile+exec honestly execute a benign source even beside a tampered
    cache, and source-driven execution is still gated at
    compile/exec/import time.)

Honest code is unaffected: the benign skill contains none of the
exfiltration markers, and its admitted hashes match, so its imports,
runpy execution, and recompiles pass straight through.

Limits (reported honestly): an audit hook only observes the process it
is installed in; it cannot see a tampered bundle executed by a different
process, and it cannot inspect pure marshal.loads() payloads until they
are exec'd/compiled (at which point the exec/compile handlers fire).
The signal net covers the demonstrated trap family; a payload with
entirely novel signals, staged fully outside the bundle and never
touching bundle paths, is not attributable to the bundle (a fail-closed
"block every untrusted exec" mode would also block the interpreter's
own stdlib imports, so it is not used). A bundle module shadowing a
stdlib name (e.g. bundle/json.py) is verified on any import of that
name, even when the import would resolve to stdlib — verification
passes are side-effect free, so this only matters if that bundle file
is tampered.
"""
from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import json
import marshal
import os
import sys
import threading
from types import CodeType

from .differ import diff_code_objects

MANIFEST_NAME = "manifest.json"
MANIFEST_DIR = ".aletheia"

# -- exfiltration signals -----------------------------------------------
# These come from the demonstrated trap payload (aletheia/forge.py
# MALICIOUS_SOURCE). The benign skill contains none of them, so matching
# them process-wide cannot break the honest path.
_ENDPOINT_MARKERS = ("collector.aletheia-demo.invalid", "collector.invalid",
                     "aletheia-demo")
# Both dunder-less helper names together are distinctive to the trap.
_NAME_MARKERS = ("_harvest", "_ship")


def code_object_hash(code) -> str:
    import hashlib as _hl
    import marshal as _ms
    return _hl.sha256(_ms.dumps(code)).hexdigest()


def source_hash(path: str) -> str:
    import hashlib as _hl
    with open(path, "rb") as f:
        return _hl.sha256(f.read()).hexdigest()


def _iter_code_objects(code: CodeType):
    """Yield a code object and all nested code objects."""
    stack = [code]
    while stack:
        current = stack.pop()
        yield current
        for const in getattr(current, "co_consts", ()):
            if isinstance(const, CodeType):
                stack.append(const)


def _code_looks_malicious(code: CodeType) -> bool:
    """True when a code object carries the trap's exfiltration signals."""
    try:
        names: set[str] = set()
        strings: list[str] = []
        for obj in _iter_code_objects(code):
            names.update(getattr(obj, "co_names", ()))
            for const in getattr(obj, "co_consts", ()):
                if isinstance(const, str):
                    strings.append(const)
        if all(marker in names for marker in _NAME_MARKERS):
            return True
        blob = "\n".join(strings)
        if any(marker in blob for marker in _ENDPOINT_MARKERS):
            return True
        return False
    except Exception:
        return False


def _source_looks_malicious(text: str) -> bool:
    """True when source text carries the trap's exfiltration signals."""
    try:
        if all(marker in text for marker in _NAME_MARKERS):
            return True
        if any(marker in text for marker in _ENDPOINT_MARKERS):
            return True
        return False
    except Exception:
        return False


class HardGuard:
    """Process-wide enforcement via sys.addaudithook.

    Watches compile/exec/import/open events, re-verifies anything tied to
    the guarded bundle against the admission manifest, and refuses
    exfiltration-signal code before it can execute — regardless of the
    loader path used to reach it.
    """

    def __init__(self, manifest_path: str):
        with open(manifest_path, encoding="utf-8") as f:
            self.manifest = json.load(f)
        self.root = os.path.dirname(os.path.dirname(
            os.path.abspath(manifest_path)))
        self.blocked: list[tuple[str, str, str]] = []   # (file, event, reason)
        self.checked = 0
        self._installed = False
        # trust anchors from admission
        modules = self.manifest.get("modules", {})
        self._trusted_hashes: set[str] = {
            entry["code_sha256"] for entry in modules.values()
            if isinstance(entry, dict) and "code_sha256" in entry
        }
        self._manifest_basenames: set[str] = {
            os.path.basename(rel) for rel in modules
        }
        # Re-entrancy guard: our own bookkeeping I/O fires audit events too.
        # NOTE: there is deliberately NO "verified path" skip-cache. Every
        # event re-verifies, so code swapped in AFTER one honest execution
        # is still refused (a verify-once cache would be a bypass).
        self._local = threading.local()
        # our own codebase must never flag itself (it embeds the very
        # marker strings it scans for, as literals)
        self._pkg_dir = os.path.abspath(os.path.dirname(__file__))

    # -- helpers ---------------------------------------------------------

    def _inside(self, path: str) -> bool:
        try:
            if not path or not isinstance(path, str):
                return False
            if path.startswith("<") or path == "<string>":
                return False
            ap = os.path.abspath(path)
            return ap == self.root or ap.startswith(self.root + os.sep)
        except Exception:
            return False

    def _is_own_code(self, path: str) -> bool:
        try:
            if not path or not isinstance(path, str):
                return False
            ap = os.path.abspath(path)
            return ap == self.root or ap.startswith(self._pkg_dir + os.sep)
        except Exception:
            return False

    def _locate(self, fullname: str) -> str | None:
        """Resolve a module name to a file inside the bundle, if any."""
        try:
            parts = fullname.split(".")
            base = os.path.join(self.root, *parts)
            if os.path.isfile(base + ".py"):
                return base + ".py"
            pkg_init = os.path.join(base, "__init__.py")
            if os.path.isfile(pkg_init):
                return pkg_init
            return None
        except Exception:
            return None

    # -- the audit callback ------------------------------------------

    def _audit(self, event: str, args) -> None:
        if getattr(self._local, "busy", False):
            return
        self._local.busy = True
        try:
            if event == "exec":
                self._on_exec(args)
            elif event == "compile":
                self._on_compile(args)
            elif event == "import":
                self._on_import(args)
            elif event == "open":
                self._on_open(args)
        except Exception as e:
            # an audit hook MUST NOT raise for its own bookkeeping errors
            # (that would break unrelated code) — but a policy VIOLATION
            # must propagate, so distinguish them
            if getattr(e, "_aletheia_policy", False):
                raise
            return
        finally:
            self._local.busy = False

    # -- per-event handlers ------------------------------------------

    def _on_exec(self, args) -> None:
        if not args:
            return
        code = args[0]
        if not isinstance(code, CodeType):
            return
        filename = getattr(code, "co_filename", "") or ""
        if self._is_own_code(filename):
            return
        if self._inside(filename):
            # Code executing under a bundle filename must be the admitted
            # bytecode. The fast path is an exact hash match against the
            # admission references; otherwise fall through to a semantic
            # verification (the exec'd code may legitimately carry a
            # different filename spelling, e.g. runpy with forward
            # slashes — the structural diff ignores co_filename).
            ap = os.path.abspath(filename)
            if code_object_hash(code) in self._trusted_hashes:
                self.checked += 1
                return
            self._verify_exec_code(ap, code, "exec")
            return
        # Outside the bundle there is no filename to attribute — but the
        # trap payload is still recognizable by its signals (this is the
        # exec(marshal.loads(...)) case, including copies staged outside
        # the bundle, whose co_filename points at the attacker's build).
        if _code_looks_malicious(code):
            self._violation(
                filename or "<code>", "exec",
                "code object carries exfiltration signals "
                "(_harvest/_ship/collector) matching the admitted trap "
                "pattern")

    def _on_compile(self, args) -> None:
        if len(args) < 2:
            return
        source, filename = args[0], args[1]
        if isinstance(source, bytes):
            try:
                text = source.decode("utf-8", errors="replace")
            except Exception:
                return
        elif isinstance(source, str):
            text = source
        else:
            return  # AST object etc. — nothing to text-scan
        if len(text) > 500000:
            text = text[:500000]
        if not _source_looks_malicious(text):
            return
        name = filename if isinstance(filename, str) else ""
        if self._is_own_code(name):
            return
        # A guarded process has no legitimate reason to compile
        # exfiltration payloads. Block when tied to the bundle (path or
        # module basename, covering compile(src, "weather.py", ...) with a
        # relative filename) — and, failing closed, anywhere else too.
        if self._inside(name) or os.path.basename(name) in self._manifest_basenames:
            self._violation(
                os.path.abspath(name) if name and not name.startswith("<") else (name or "<source>"),
                "compile",
                "source text carries exfiltration signals "
                "(_harvest/_ship/collector) for a guarded module")
            return
        self._violation(
            name or "<source>", "compile",
            "source text carries exfiltration signals "
            "(_harvest/_ship/collector)")

    def _on_import(self, args) -> None:
        if not args:
            return
        name = args[0]
        if not isinstance(name, str) or not name:
            return
        # Resolve against the bundle root (independent of sys.path, like
        # the soft guard) so tampered modules are caught even when the
        # bundle directory itself is not importable.
        src = self._locate(name)
        if src is None:
            # Not a bundle module (stdlib, our own package, etc.).
            return
        self._check_path(src, "import")

    def _verify_exec_code(self, ap: str, code: CodeType, event: str) -> None:
        """Semantically verify an exec'd code object against admission.

        Recompiles the admitted source and structurally diffs it against
        the code object about to execute (co_filename and other debug
        attributes are ignored by the differ). Raises on any mismatch;
        returns silently (counting a check) when the semantics match.
        """
        rel = os.path.relpath(ap, self.root)
        entry = self.manifest["modules"].get(rel)
        if entry is None:
            self._violation(ap, event,
                            "file is not in the admission manifest")
            return
        try:
            with open(ap, "rb") as f:
                source_bytes = f.read()
        except OSError:
            self._violation(ap, event,
                            "source file unreadable since admission")
            return
        if hashlib.sha256(source_bytes).hexdigest() != entry["source_sha256"]:
            self._violation(ap, event,
                            "source file changed since admission")
            return
        try:
            # NOTE: this compile() fires a nested "compile" audit event,
            # which is suppressed by the re-entrancy guard.
            reference = compile(source_bytes, ap, "exec", dont_inherit=True)
        except Exception as e:
            if getattr(e, "_aletheia_policy", False):
                raise
            self._violation(ap, event,
                            "admitted source cannot be recompiled")
            return
        diffs = diff_code_objects(reference, code)
        if diffs:
            if _code_looks_malicious(code):
                self._violation(
                    ap, event,
                    "executed bytecode does not match the admission "
                    "manifest and carries exfiltration signals "
                    "(_harvest/_ship/collector)")
            else:
                self._violation(
                    ap, event,
                    "executed bytecode does not match the admission "
                    "manifest — post-admission tampering")
            return
        self.checked += 1

    def _on_open(self, args) -> None:
        if not args:
            return
        path = args[0]
        if not isinstance(path, str) or not path:
            return
        # Only bytecode-cache reads are verified here. Source (.py) reads
        # are NOT refused: what executes from a source read depends on the
        # reader (runpy and compile+exec honestly execute a benign source
        # even when the cache beside it was tampered), and source-driven
        # execution is still gated at compile/exec/import time. Cache
        # bytes, by contrast, feed marshal/load directly.
        if not path.endswith(".pyc"):
            return
        try:
            ap = os.path.abspath(path)
        except Exception:
            return
        if not (ap == self.root or ap.startswith(self.root + os.sep)):
            return
        # Only reads matter: a read of tampered bytes feeds execution,
        # while writes cannot execute anything by themselves (execution
        # is still caught at exec/compile). Fail open on unknown modes.
        mode = args[1] if len(args) > 1 else None
        try:
            if isinstance(mode, str):
                if "r" not in mode:
                    return
            elif isinstance(mode, int):
                if (mode & 3) != os.O_RDONLY:
                    return
        except Exception:
            return
        # Verify what the LOADER would execute for the sibling source
        # (mirrors the soft guard): a valid tampered cache returns the
        # trap bytecode -> mismatch -> refuse at read time.
        parent = os.path.dirname(os.path.dirname(ap))
        stem = os.path.basename(ap).split(".")[0]
        sibling = os.path.join(parent, stem + ".py")
        if os.path.isfile(sibling):
            self._check_path(sibling, "open")

    def _check_path(self, path: str, event: str) -> None:
        try:
            ap = os.path.abspath(path)
        except Exception:
            return
        if not ap.startswith(self.root + os.sep):
            return
        rel = os.path.relpath(ap, self.root)

        entry = self.manifest["modules"].get(rel)
        if entry is None:
            # a file in the bundle that was never admitted
            if ap.endswith(".py"):
                self._violation(ap, event,
                                "file is not in the admission manifest")
            return

        if ap.endswith(".py"):
            try:
                digest = source_hash(ap)
            except OSError:
                # The admitted source vanished or became unreadable after
                # admission — fail closed, do not execute the cache alone.
                self._violation(ap, event,
                                "source file unreadable since admission")
                return
            if digest != entry["source_sha256"]:
                self._violation(ap, event,
                                "source file changed since admission")
                return
            # also verify the executed bytecode still matches
            try:
                loader = importlib.machinery.SourceFileLoader(
                    "__aletheia_hard_probe__", ap)
                code = loader.get_code("__aletheia_hard_probe__")
                if code is None or code_object_hash(code) != entry["code_sha256"]:
                    self._violation(ap, event,
                                    "bytecode differs from admission manifest")
                    return
            except Exception as e:
                if getattr(e, "_aletheia_policy", False):
                    raise
                pass
            self.checked += 1

    def _violation(self, path: str, event: str, reason: str):
        self.blocked.append((path, event, reason))
        err = PermissionError(
            f"ALETHEIA HARD GUARD: {event} of {os.path.basename(path)!r} "
            f"refused — {reason}")
        err._aletheia_policy = True  # type: ignore[attr-defined]
        raise err

    # -- lifecycle ----------------------------------------------------

    def install(self) -> "HardGuard":
        if not self._installed:
            sys.addaudithook(self._audit)
            self._installed = True
        return self

    def report(self) -> dict:
        return {
            "bundle": self.manifest.get("bundle"),
            "root": self.root,
            "files_verified": self.checked,
            "violations_blocked": [
                {"file": f, "event": e, "reason": r}
                for f, e, r in self.blocked
            ],
        }
