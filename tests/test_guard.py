"""Tests for the admission gate and runtime guard.

Run: python -m pytest tests/test_guard.py -v
"""
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, PKG_ROOT)

from aletheia.forge import (MALICIOUS_SOURCE, forge_clean_skill,
                            forge_trap_skill)
from aletheia.guard import AletheiaGuard, admit


@pytest.fixture
def trap_dir(tmp_path):
    return forge_trap_skill(str(tmp_path / "trap"))


@pytest.fixture
def clean_dir(tmp_path):
    return forge_clean_skill(str(tmp_path / "clean"))


class TestAdmit:
    def test_trap_is_refused(self, trap_dir):
        r = admit(trap_dir)
        assert r.admitted is False
        assert len(r.refused) >= 1
        assert any("differs from source" in reason or "Trap" in reason
                   for _, reason in r.refused)
        assert not os.path.exists(os.path.join(trap_dir, ".aletheia",
                                               "manifest.json"))

    def test_clean_is_admitted(self, clean_dir):
        r = admit(clean_dir)
        assert r.admitted is True
        assert r.modules == 1
        assert os.path.isfile(r.manifest_path)

    def test_manifest_contents(self, clean_dir):
        r = admit(clean_dir)
        with open(r.manifest_path, encoding="utf-8") as f:
            m = json.load(f)
        assert m["version"] == 1
        assert "weather.py" in m["modules"]
        entry = m["modules"]["weather.py"]
        assert len(entry["source_sha256"]) == 64
        assert len(entry["code_sha256"]) == 64


def _run_import(clean_dir: str) -> str:
    """Import the admitted skill in a subprocess WITH the guard installed.

    Paths travel via env vars — never embedded in generated source — so
    Windows backslashes can't corrupt the script.
    """
    manifest = os.path.join(clean_dir, ".aletheia", "manifest.json")
    script = "\n".join([
        "import sys, os, json",
        "sys.path.insert(0, os.environ['ALETHEIA_BUNDLE'])",
        "sys.path.insert(0, os.environ['ALETHEIA_PKG_ROOT'])",
        "from aletheia.guard import AletheiaGuard",
        "guard = AletheiaGuard(os.environ['ALETHEIA_MANIFEST']).install()",
        "try:",
        "    import weather",
        "    print('IMPORT_OK', weather.get_conditions('X'))",
        "except ImportError as e:",
        "    print('IMPORT_BLOCKED', e)",
        "print('REPORT', json.dumps(guard.report()))",
    ])
    env = {**os.environ,
           "PYTHONDONTWRITEBYTECODE": "1",
           "ALETHEIA_BUNDLE": clean_dir,
           "ALETHEIA_PKG_ROOT": PKG_ROOT,
           "ALETHEIA_MANIFEST": manifest}
    p = subprocess.run([sys.executable, "-c", script],
                       capture_output=True, text=True, env=env)
    return p.stdout + p.stderr


class TestGuard:
    def test_honest_import_succeeds_under_guard(self, clean_dir):
        admit(clean_dir)
        out = _run_import(clean_dir)
        assert "IMPORT_OK" in out, out

    def test_post_admission_trojan_swap_is_blocked(self, clean_dir):
        """The decisive test: attacker replaces the .pyc AFTER admission."""
        admit(clean_dir)
        import importlib.util
        import py_compile
        import tempfile
        src = os.path.join(clean_dir, "weather.py")
        pyc = importlib.util.cache_from_source(src)

        from aletheia.forge import _patch_header
        with tempfile.TemporaryDirectory() as tmp:
            mal = os.path.join(tmp, "weather.py")
            with open(mal, "w", encoding="utf-8") as f:
                f.write(MALICIOUS_SOURCE)
            py_compile.compile(mal, cfile=pyc)
        _patch_header(pyc, src)

        out = _run_import(clean_dir)
        assert "IMPORT_BLOCKED" in out, out
        assert "ALETHEIA BLOCKED" in out
        assert '"imports_blocked"' in out and "weather" in out
