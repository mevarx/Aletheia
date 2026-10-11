"""Attack the guard — the enforcement-proving harness.

A gate that only covers `import` isn't a gate. This module attacks
Aletheia's runtime guard with the techniques an attacker would actually
use, and PROVES for each whether the malicious bytecode executed:

  1. plain import                    — the path the guard was built for
  2. importlib.spec_from_file_location — direct loader construction
  3. exec(marshal.loads(pyc))        — skip the loader entirely
  4. runpy.run_path                  — script-style execution
  5. compile+exec of source text     — never touches the pyc at all

Each attack is verified by whether the executed code's ACTUAL BEHAVIOR
was observed (the canary endpoint call), not by whether an exception
was raised — a bypass that silently swallows its own error still counts
as a bypass.

Run:  python -m aletheia attack
"""
from __future__ import annotations

import importlib.util
import json
import marshal
import os
import py_compile
import subprocess
import sys
import tempfile
from dataclasses import dataclass

from .forge import MALICIOUS_SOURCE, _patch_header, forge_clean_skill
from .guard import admit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# the canary: the malicious code posts the harvested env to this endpoint.
# The attack harness replaces urllib to CAPTURE the attempt — a captured
# attempt is proof the malicious bytecode executed.
PROBE = r'''
import sys, os, json, urllib.request
captured = []
def spy(req, *a, **k):
    body = req.data.decode() if getattr(req, "data", None) else ""
    captured.append(body)
    raise RuntimeError("captured by attack harness")
urllib.request.urlopen = spy
os.environ["AL_CANARY_KEY"] = "canary-value-12345"
result = {"executed": False, "evidence": None}
__BODY__
result["executed"] = len(captured) > 0
if captured:
    import base64
    try:
        result["evidence"] = base64.b64decode(json.loads(captured[0])["d"]).decode()
    except Exception:
        result["evidence"] = captured[0][:100]
print("RESULT_JSON:" + json.dumps(result))
'''

ATTACKS = {
    "plain-import": r'''
try:
    import weather
    weather.get_conditions("Chennai")
except Exception:
    pass
''',
    "importlib-spec": r'''
import importlib.util
try:
    s = importlib.util.spec_from_file_location(
        "byp_importlib", os.environ["AL_BUNDLE"] + "/weather.py")
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    m.get_conditions("Chennai")
except Exception:
    pass
''',
    "exec-marshal-pyc": r'''
import marshal
try:
    data = open(os.environ["AL_PYC"], "rb").read()
    exec(marshal.loads(data[16:]))
    get_conditions("Chennai")
except Exception:
    pass
''',
    "runpy-run-path": r'''
import runpy
try:
    ns = runpy.run_path(os.environ["AL_BUNDLE"] + "/weather.py")
    ns["get_conditions"]("Chennai")
except Exception:
    pass
''',
    "compile-exec-source": r'''
try:
    src = open(os.environ["AL_BUNDLE"] + "/weather.py").read()
    ns = {}
    exec(compile(src, "weather.py", "exec"), ns)
    ns["get_conditions"]("Chennai")
except Exception:
    pass
''',
    "py-compile-writeback": r'''
# the attacker recompiles the malicious source into the pyc slot,
# exactly as py_compile does, then lets a later import pick it up
import py_compile
try:
    py_compile.compile(os.environ["AL_BUNDLE"] + "/weather.py",
                       cfile=os.environ["AL_PYC"])
except Exception:
    pass
''',
}


@dataclass
class AttackResult:
    name: str
    malicious_executed: bool
    guard_blocked: bool
    evidence: str | None


def _setup_tampered_bundle() -> tuple[str, str, str]:
    """Create an admitted skill, then tamper its pyc. Returns paths."""
    base = tempfile.mkdtemp(prefix="aletheia-attack-")
    clean = forge_clean_skill(os.path.join(base, "clean"))
    admit(clean)
    src = os.path.join(clean, "weather.py")
    pyc = importlib.util.cache_from_source(src)
    mal = os.path.join(base, "mal.py")
    with open(mal, "w", encoding="utf-8") as f:
        f.write(MALICIOUS_SOURCE)
    py_compile.compile(mal, cfile=pyc)
    _patch_header(pyc, src)
    return clean, src, pyc


def run_attack(name: str, clean: str, pyc: str,
               use_guard: str = "soft") -> AttackResult:
    """use_guard: 'soft' (meta_path) | 'hard' (audit hook) | 'none'."""
    script_lines = [
        "import sys, os, json",
        f"sys.path.insert(0, {ROOT!r})",
    ]
    if use_guard == "soft":
        script_lines += [
            "from aletheia.guard import AletheiaGuard",
            "g = AletheiaGuard(os.environ['AL_MANIFEST']).install()",
        ]
    elif use_guard == "hard":
        script_lines += [
            "from aletheia.hardguard import HardGuard",
            "g = HardGuard(os.environ['AL_MANIFEST']).install()",
        ]
    script_lines.append(PROBE.replace("__BODY__", ATTACKS[name]))
    script = "\n".join(script_lines)

    env = {**os.environ,
           "PYTHONDONTWRITEBYTECODE": "1",
           "AL_ROOT": ROOT,
           "AL_BUNDLE": clean,
           "AL_PYC": pyc,
           "AL_MANIFEST": os.path.join(clean, ".aletheia", "manifest.json")}
    p = subprocess.run([sys.executable, "-c", script],
                       capture_output=True, text=True, env=env)
    out = p.stdout
    executed, evidence = False, None
    for line in out.splitlines():
        if line.startswith("RESULT_JSON:"):
            d = json.loads(line[len("RESULT_JSON:"):])
            executed = d.get("executed", False)
            evidence = d.get("evidence")
    return AttackResult(name=name, malicious_executed=executed,
                        guard_blocked=(not executed), evidence=evidence)


def run_all() -> list:
    clean, _src, pyc = _setup_tampered_bundle()
    results = [run_attack(name, clean, pyc, use_guard="soft")
               for name in ATTACKS]
    import shutil
    shutil.rmtree(os.path.dirname(clean), ignore_errors=True)
    return results


def run_all_hard() -> list:
    clean, _src, pyc = _setup_tampered_bundle()
    results = [run_attack(name, clean, pyc, use_guard="hard")
               for name in ATTACKS]
    import shutil
    shutil.rmtree(os.path.dirname(clean), ignore_errors=True)
    return results


def report(results: list) -> None:
    print("\n" + "=" * 72)
    print(" ALETHEIA GUARD — BYPASS ATTACK REPORT")
    print(" the attacker has swapped the .pyc on an admitted skill")
    print("=" * 72)
    print(f"  {'attack technique':<32} {'malicious ran?':<16} verdict")
    print("  " + "-" * 68)
    blocked = 0
    for r in results:
        v = "BLOCKED" if r.guard_blocked else "BYPASSED"
        if r.guard_blocked:
            blocked += 1
        color = "\033[92m" if r.guard_blocked else "\033[91m"
        print(f"  {r.name:<32} {'YES — guard failed' if r.malicious_executed else 'no':<16} "
              f"{color}{v}\033[0m")
    print("  " + "-" * 68)
    print(f"  {blocked}/{len(results)} techniques blocked")
    if blocked < len(results):
        print("  \033[91mA gate that only covers `import` is not a gate.\033[0m")
    print("=" * 72)


def main(argv=None) -> int:
    which = "hard" if (argv and "--hard" in argv) else "soft"
    results = run_all_hard() if which == "hard" else run_all()
    report(results)
    return 0 if all(r.guard_blocked for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
