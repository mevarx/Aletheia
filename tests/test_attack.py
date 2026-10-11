"""Tests for the bypass-attack harness and HardGuard.

Run: python -m pytest tests/test_attack.py -v

Pattern follows tests/test_guard.py: forge a clean skill into tmp_path,
admit it, tamper the .pyc after admission, then attack in a subprocess
with the guard installed. Paths travel via env vars so Windows
backslashes can't corrupt the generated script.
"""
import importlib.util
import os
import py_compile
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, PKG_ROOT)

from aletheia.forge import MALICIOUS_SOURCE, _patch_header, forge_clean_skill
from aletheia.guard import admit


def _tamper_pyc_after_admit(clean_dir: str) -> str:
    """Admit is done by the caller; swap malicious bytecode into the cache
    slot and header-patch it so the loader treats it as valid. Returns pyc."""
    src = os.path.join(clean_dir, "weather.py")
    pyc = importlib.util.cache_from_source(src)
    with tempfile.TemporaryDirectory() as tmp:
        mal = os.path.join(tmp, "weather.py")
        with open(mal, "w", encoding="utf-8") as f:
            f.write(MALICIOUS_SOURCE)
        py_compile.compile(mal, cfile=pyc)
    _patch_header(pyc, src)
    return pyc


def test_soft_guard_blocks_plain_import(tmp_path):
    """Soft (meta_path) guard must stop the plain-import path."""
    from aletheia.attack import run_attack

    clean = forge_clean_skill(str(tmp_path / "clean"))
    r = admit(clean)
    assert r.admitted is True
    pyc = _tamper_pyc_after_admit(clean)
    result = run_attack("plain-import", clean, pyc, use_guard="soft")
    assert result.guard_blocked is True, result
    assert result.malicious_executed is False, result


def test_hardguard_imports_ok():
    """HardGuard must be importable with its install()/report() API."""
    from aletheia.hardguard import HardGuard

    assert callable(HardGuard)
    assert hasattr(HardGuard, "install")
    assert hasattr(HardGuard, "report")
    # attack.py's own imports must work too
    import aletheia.attack  # noqa: F401  (checks `from .guard import admit`)
    from aletheia.guard import admit as _admit  # noqa: F401
    assert callable(_admit)


def test_hardguard_blocks_exec_marshal(tmp_path):
    """HardGuard must block exec(marshal.loads(pyc)) — no loader involved."""
    from aletheia.attack import run_attack

    clean = forge_clean_skill(str(tmp_path / "clean"))
    r = admit(clean)
    assert r.admitted is True
    pyc = _tamper_pyc_after_admit(clean)
    result = run_attack("exec-marshal-pyc", clean, pyc, use_guard="hard")
    assert result.guard_blocked is True, result
    assert result.malicious_executed is False, result


def test_hardguard_honest_import_succeeds(tmp_path):
    """Clean skill + HardGuard install + import weather must succeed."""
    clean = forge_clean_skill(str(tmp_path / "clean"))
    r = admit(clean)
    assert r.admitted is True
    manifest = os.path.join(clean, ".aletheia", "manifest.json")
    script = "\n".join([
        "import sys, os, json",
        "sys.path.insert(0, os.environ['ALETHEIA_BUNDLE'])",
        "sys.path.insert(0, os.environ['ALETHEIA_PKG_ROOT'])",
        "from aletheia.hardguard import HardGuard",
        "guard = HardGuard(os.environ['ALETHEIA_MANIFEST']).install()",
        "try:",
        "    import weather",
        "    print('IMPORT_OK', weather.get_conditions('X'))",
        "except Exception as e:",
        "    print('IMPORT_BLOCKED', type(e).__name__, e)",
        "print('REPORT', json.dumps(guard.report()))",
    ])
    env = {**os.environ,
           "PYTHONDONTWRITEBYTECODE": "1",
           "ALETHEIA_BUNDLE": clean,
           "ALETHEIA_PKG_ROOT": PKG_ROOT,
           "ALETHEIA_MANIFEST": manifest}
    p = subprocess.run([sys.executable, "-c", script],
                       capture_output=True, text=True, env=env)
    out = p.stdout + p.stderr
    assert "IMPORT_OK" in out, out
    assert "IMPORT_BLOCKED" not in out, out
