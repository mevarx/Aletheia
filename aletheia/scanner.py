"""The scanning engine: walk a skill bundle, pair .py with .pyc, decide truth.

Verdict logic per source file:
  - no .pyc present                -> SOURCE-ONLY (nothing executed yet)
  - .pyc + header trusted + diff   -> CLEAN (the cache corresponds to the source)
  - .pyc + header trusted + DIFFER -> CRITICAL (PyCache Trap pattern: the loader
                                       executes bytecode that is not the source)
  - .pyc + header stale/different   -> the loader would recompile; if the pyc
                                       still differs it is dormant, still flagged
  - hash-based unchecked cache      -> never invalidated; treat as untrusted
  - magic mismatch                   -> pyc for another interpreter; skip
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict

from .behavior import extract_behavior
from .differ import diff_code_objects
from . import pycformat

VERDICT_CLEAN = "CLEAN"
VERDICT_CRITICAL = "CRITICAL"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_SOURCE_ONLY = "SOURCE-ONLY"
VERDICT_SKIPPED = "SKIPPED"


@dataclass
class FileReport:
    source: str
    pyc: str | None
    verdict: str
    reason: str
    header_mode: str = ""
    header_detail: str = ""
    code_matches: bool | None = None
    diff_count: int = 0
    diffs: list = field(default_factory=list)
    executed_behavior: dict = field(default_factory=dict)
    source_behavior: dict = field(default_factory=dict)


@dataclass
class ScanReport:
    root: str
    files: list = field(default_factory=list)          # list[FileReport]
    critical: int = 0
    suspicious: int = 0
    clean: int = 0
    skipped: int = 0
    source_only: int = 0
    worst: str = VERDICT_CLEAN


def _find_pyc_for(source_path: str, root: str) -> str | None:
    """Locate the __pycache__ .pyc CPython would select for this source."""
    import importlib.util
    try:
        candidate = importlib.util.cache_from_source(source_path)
        if os.path.isfile(candidate):
            return candidate
    except Exception:
        pass
    # fall back to any cpython-*.pyc in the adjacent __pycache__ dir
    cache_dir = os.path.join(os.path.dirname(source_path), "__pycache__")
    if not os.path.isdir(cache_dir):
        return None
    stem = os.path.splitext(os.path.basename(source_path))[0]
    matches = [f for f in os.listdir(cache_dir)
               if f.startswith(stem + ".") and f.endswith(".pyc")]
    return os.path.join(cache_dir, sorted(matches)[0]) if matches else None


def scan_source(source_path: str, root: str) -> FileReport:
    rel = os.path.relpath(source_path, root)
    pyc_path = _find_pyc_for(source_path, root)

    with open(source_path, "rb") as f:
        source_bytes = f.read()
    # dont_inherit=True: match py_compile's standard compilation. Without it,
    # compile() inherits future-statement flags (e.g. annotations) from THIS
    # module's frame and co_flags would differ from any honestly compiled pyc,
    # producing false CRITICALs.
    source_code = compile(source_bytes, source_path, "exec", dont_inherit=True)
    source_behavior = extract_behavior(source_code)

    if pyc_path is None:
        return FileReport(rel, None, VERDICT_SOURCE_ONLY,
                          "no compiled cache present; source is all there is",
                          source_behavior=source_behavior)

    try:
        shipped_code, header = pycformat.load_code_object(pyc_path)
    except ValueError as e:
        return FileReport(rel, os.path.relpath(pyc_path, root), VERDICT_SKIPPED,
                          str(e), source_behavior=source_behavior)

    validation = pycformat.validate_against_source(header, source_path)
    executed_behavior = extract_behavior(shipped_code)
    diffs = diff_code_objects(source_code, shipped_code)

    base = FileReport(
        source=rel,
        pyc=os.path.relpath(pyc_path, root),
        verdict=VERDICT_CLEAN,
        reason="",
        header_mode=validation.mode,
        header_detail=validation.detail,
        code_matches=(len(diffs) == 0),
        diff_count=len(diffs),
        diffs=diffs[:50],
        executed_behavior=executed_behavior,
        source_behavior=source_behavior,
    )

    if header.hash_based and not header.check_source:
        base.reason = ("hash-based cache with source checking disabled — the "
                       "bytecode can never be invalidated by a source change")
        base.verdict = (VERDICT_CRITICAL if diffs else VERDICT_SUSPICIOUS)
        if not diffs:
            base.reason += "; today it happens to match the source"
        return base

    if validation.trusted and diffs:
        base.verdict = VERDICT_CRITICAL
        base.reason = (f"PyCache Trap pattern: {validation.detail}. The executed "
                       f"bytecode differs from the source in {len(diffs)} place(s) "
                       f"and the loader will never recompile.")
        return base

    if validation.trusted and not diffs:
        base.reason = f"cache corresponds to the source; {validation.detail}"
        return base

    if not validation.trusted and diffs:
        base.verdict = VERDICT_SUSPICIOUS
        base.reason = (f"stale cache that differs from the source in "
                       f"{len(diffs)} place(s); {validation.detail}. Harmless today "
                       f"(loader recompiles) but the artifact is untrustworthy.")
        return base

    base.reason = f"stale cache, matches source; {validation.detail}"
    base.verdict = VERDICT_SUSPICIOUS if "DISABLED" in validation.detail else VERDICT_CLEAN
    return base


def _orphan_pycs(root: str) -> list[str]:
    """Find .pyc files with NO corresponding .py source anywhere in the bundle.

    A sourceless cache is exactly what the paper blocks as a high-severity
    provenance finding: nothing to diff against means nothing can vouch for
    what the bytecode does. Cisco flags this; Aletheia must too.
    """
    import importlib.util
    orphans = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in (".git", "node_modules", ".venv")]
        if os.path.basename(dirpath) != "__pycache__":
            continue
        for fn in sorted(filenames):
            if not fn.endswith(".pyc"):
                continue
            stem = fn.split(".")[0]
            parent = os.path.dirname(dirpath)
            if not os.path.isfile(os.path.join(parent, stem + ".py")):
                orphans.append(os.path.join(dirpath, fn))
    return orphans


def scan_bundle(root: str) -> ScanReport:
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        raise NotADirectoryError(root)
    report = ScanReport(root=root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in ("__pycache__", ".git", "node_modules", ".venv")]
        for fn in sorted(filenames):
            if not fn.endswith(".py"):
                continue
            fr = scan_source(os.path.join(dirpath, fn), root)
            report.files.append(fr)
            if fr.verdict == VERDICT_CRITICAL:
                report.critical += 1
            elif fr.verdict == VERDICT_SUSPICIOUS:
                report.suspicious += 1
            elif fr.verdict == VERDICT_CLEAN:
                report.clean += 1
            elif fr.verdict == VERDICT_SKIPPED:
                report.skipped += 1
            else:
                report.source_only += 1

    # orphan .pyc: bytecode with no source to verify it against
    for pyc in _orphan_pycs(root):
        try:
            shipped_code, header = pycformat.load_code_object(pyc)
            behavior = extract_behavior(shipped_code)
        except ValueError as e:
            report.files.append(FileReport(
                os.path.relpath(pyc, root), os.path.relpath(pyc, root),
                VERDICT_SKIPPED, str(e)))
            report.skipped += 1
            continue
        report.files.append(FileReport(
            source=os.path.relpath(pyc, root),
            pyc=os.path.relpath(pyc, root),
            verdict=VERDICT_CRITICAL,
            reason=("sourceless bytecode: no .py exists to verify this cache "
                    "against. The executed code cannot be checked against any "
                    "declared intent — treat as unverifiable and block "
                    "(arXiv 2610.10612: EAV blocks sourceless artifacts even "
                    "when reproduction abstains)."),
            header_mode="timestamp" if not header.hash_based else "hash",
            header_detail=("no source file present for header validation"),
            code_matches=None,
            diff_count=0,
            executed_behavior=behavior,
        ))
        report.critical += 1

    if report.critical:
        report.worst = VERDICT_CRITICAL
    elif report.suspicious:
        report.worst = VERDICT_SUSPICIOUS
    return report


def to_dict(report: ScanReport) -> dict:
    return asdict(report)
