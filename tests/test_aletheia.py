"""Aletheia test suite.

Run: python -m pytest tests/ -v
"""
import json
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aletheia.differ import diff_code_objects
from aletheia.forge import forge_trap_skill, BENIGN_SOURCE, MALICIOUS_SOURCE
from aletheia.scanner import (VERDICT_CLEAN, VERDICT_CRITICAL, VERDICT_SOURCE_ONLY,
                              scan_bundle, scan_source)
from aletheia import pycformat


@pytest.fixture
def trap_dir(tmp_path):
    return forge_trap_skill(str(tmp_path / "trap-skill"))


@pytest.fixture
def clean_dir(tmp_path):
    """A bundle whose .pyc is honestly compiled from its own source."""
    d = tmp_path / "clean-skill"
    d.mkdir()
    (d / "SKILL.md").write_text("# clean\n\nan honest skill\n", encoding="utf-8")
    src = d / "utils.py"
    src.write_text(BENIGN_SOURCE, encoding="utf-8")
    import py_compile
    py_compile.compile(str(src))  # real compile: cache matches source
    return str(d)


class TestDiffer:
    def test_identical_compile_has_no_diffs(self):
        code = compile("x = 1\ndef f():\n    return x\n", "<s>", "exec")
        self_diffs = diff_code_objects(code, code)
        assert self_diffs == []

    def test_different_source_produces_diffs(self):
        a = compile("x = 1\n", "<a>", "exec")
        b = compile("y = 2\n", "<b>", "exec")
        diffs = diff_code_objects(a, b)
        assert len(diffs) > 0
        attrs = {d["attr"] for d in diffs}
        assert "co_names" in attrs or "co_consts" in attrs


class TestHeader:
    def test_header_magic_matches_current_interpreter(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "m.py")
            with open(src, "w") as f:
                f.write("v = 1\n")
            import py_compile
            py_compile.compile(src)
            pyc = pycformat.load_code_object(
                __import__("importlib.util", fromlist=["util"]).cache_from_source(src))
            assert pyc[1].magic_matches is True

    def test_untrusted_header_detected(self, tmp_path):
        src = tmp_path / "s.py"
        src.write_text("v = 1\n", encoding="utf-8")
        import struct
        # hand-build a timestamp pyc header with a bogus mtime/size
        header = pycformat.MAGIC + struct.pack("<I", 0) + struct.pack("<II", 1, 2)
        v = pycformat.validate_against_source(
            pycformat.parse_header(header + b"\x00" * 32), str(src))
        assert v.trusted is False
        assert "stale" in v.detail


class TestTrap:
    def test_loader_actually_executes_malicious_bytecode(self, trap_dir):
        """The decisive test: importing the module runs the hidden code."""
        script = (
            "import sys, os, json, urllib.request\n"
            f"sys.path.insert(0, {trap_dir!r})\n"
            'os.environ["DEMO_API_KEY"] = "sk-canary-12345"\n'
            "import weather\n"
            "captured = []\n"
            "def spy(req, *a, **k):\n"
            '    captured.append(getattr(req, "full_url", ""))\n'
            '    raise RuntimeError("blocked")\n'
            "urllib.request.urlopen = spy\n"
            "try:\n"
            '    weather.get_conditions("Chennai")\n'
            "except Exception:\n"
            "    pass\n"
            "print(json.dumps(captured))\n"
        )
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        out = subprocess.run([sys.executable, "-c", script],
                             capture_output=True, text=True, env=env)
        captured = json.loads(out.stdout.strip()) if out.stdout.strip() else []
        assert captured, "loader did not execute the malicious bytecode"

    def test_aletheia_flags_trap_critical(self, trap_dir):
        rep = scan_bundle(trap_dir)
        assert rep.worst == VERDICT_CRITICAL
        assert rep.critical == 1
        fr = rep.files[0]
        assert fr.code_matches is False
        assert fr.diff_count > 0
        assert fr.executed_behavior.get("exfiltration_signature") is True


class TestClean:
    def test_honest_cache_passes_clean(self, clean_dir):
        rep = scan_bundle(clean_dir)
        assert rep.worst == VERDICT_CLEAN
        assert rep.critical == 0
        fr = rep.files[0]
        assert fr.code_matches is True
        assert fr.verdict == VERDICT_CLEAN

    def test_sourceless_pyc_is_critical(self, trap_dir):
        """A .pyc with no .py beside it is unverifiable bytecode — must flag."""
        import importlib.util, os
        src = os.path.join(trap_dir, "weather.py")
        pyc = importlib.util.cache_from_source(src)
        os.remove(src)  # remove the source; only the cache remains
        rep = scan_bundle(trap_dir)
        assert rep.worst == VERDICT_CRITICAL
        fr = rep.files[0]
        assert "sourceless" in fr.reason.lower()
        assert fr.executed_behavior.get("exfiltration_signature") is True

    def test_source_only_bundle(self, tmp_path):
        d = tmp_path / "src-only"
        d.mkdir()
        (d / "a.py").write_text("x = 1\n", encoding="utf-8")
        rep = scan_bundle(str(d))
        assert rep.source_only == 1
        assert rep.worst == VERDICT_CLEAN


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
