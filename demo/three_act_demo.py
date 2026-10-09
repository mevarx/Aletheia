"""The three-act demo — the full trust-gate story in one run.

  ACT 1  VERIFY   the scanner catches the trap (deterministic)
  ACT 2  ADMIT    the admission gate refuses the trap at the door,
                  and admits the honest skill
  ACT 3  ENFORCE  a live trojan-swap on the ADMITTED skill is blocked
                  mid-import by the runtime guard — the code never runs

Run: python demo/three_act_demo.py
"""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from aletheia.forge import forge_trap_skill, forge_clean_skill  # noqa: E402
from aletheia.guard import admit  # noqa: E402
from aletheia.scanner import scan_bundle  # noqa: E402

BAR = "=" * 64


def hr(title: str) -> None:
    print(f"\n{BAR}\n {title}\n{BAR}")


def act1_verify(trap: str) -> None:
    hr("ACT 1 — VERIFY: the scanner catches the trap")
    rep = scan_bundle(trap)
    fr = rep.files[0]
    print(f"  verdict: {rep.worst}")
    print(f"  {fr.reason[:200]}")
    print("  -> deterministic, no model involved")


def act2_admit(trap: str, clean: str) -> None:
    hr("ACT 2 — ADMIT: the gate refuses the trap, admits the honest skill")
    print("  admitting the TRAP skill:")
    r = admit(trap)
    print(f"    result: {'ADMITTED' if r.admitted else 'REFUSED'}")
    for rel, reason in r.refused:
        print(f"    - {rel}: {reason[:120]}")
    print()
    print("  admitting the HONEST skill:")
    r2 = admit(clean)
    print(f"    result: {'ADMITTED' if r2.admitted else 'REFUSED'} "
          f"({r2.modules} module(s))")
    assert r2.admitted, "honest skill must be admitted"
    print("  -> traps never reach an admitted manifest")


def act3_enforce(clean: str) -> None:
    hr("ACT 3 — ENFORCE: a live trojan-swap is blocked mid-import")

    # swap in malicious bytecode AFTER admission, exactly like an attacker
    # who compromised the installed copy
    import importlib.util
    src = os.path.join(clean, "weather.py")
    pyc = importlib.util.cache_from_source(src)
    backup = pyc + ".bak"
    shutil.copy2(pyc, backup)

    # build a malicious .pyc and header-patch it onto the admitted skill
    from aletheia.forge import MALICIOUS_SOURCE, _patch_header
    import py_compile
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        mal = os.path.join(tmp, "weather.py")
        with open(mal, "w", encoding="utf-8") as f:
            f.write(MALICIOUS_SOURCE)
        py_compile.compile(mal, cfile=pyc)
    _patch_header(pyc, src)

    script = "\n".join([
        "import sys, os, json",
        "sys.path.insert(0, os.environ['ALETHEIA_PKG_ROOT'])",
        "sys.path.insert(0, os.environ['ALETHEIA_BUNDLE'])",
        "from aletheia.guard import AletheiaGuard",
        "guard = AletheiaGuard(os.environ['ALETHEIA_MANIFEST']).install()",
        "os.environ['DEMO_API_KEY'] = 'sk-canary-12345'",
        "try:",
        "    import weather",
        "    print('IMPORT SUCCEEDED — GUARD FAILED')",
        "    weather.get_conditions('Chennai')",
        "except ImportError as e:",
        "    print('BLOCKED:', e)",
        "print(json.dumps(guard.report()))",
    ])
    env = {**os.environ,
           "PYTHONDONTWRITEBYTECODE": "1",
           "ALETHEIA_PKG_ROOT": ROOT,
           "ALETHEIA_BUNDLE": clean,
           "ALETHEIA_MANIFEST": os.path.join(clean, ".aletheia",
                                             "manifest.json")}
    proc = subprocess.run([sys.executable, "-c", script],
                          capture_output=True, text=True, env=env)
    out = proc.stdout.strip()
    print(f"  attacker swapped the .pyc on the admitted skill...")
    for line in out.splitlines():
        print(f"  {line}")
    shutil.move(backup, pyc)  # restore for reruns

    if "BLOCKED" in out and "GUARD FAILED" not in out:
        print("  -> the malicious bytecode was refused BEFORE executing;")
        print("     the agent's import failed safe")
    else:
        print("  !! GUARD DID NOT BLOCK — investigate")
        return False
    return True


def main() -> int:
    trap = os.path.join(HERE, "trap-skill")
    clean = os.path.join(HERE, "clean-skill")
    forge_trap_skill(trap)
    forge_clean_skill(clean)

    print(BAR)
    print(" ALETHEIA — READ WHAT RUNS, NOT WHAT IS SHOWN")
    print(" the trust gate for the agent skill ecosystem")
    print(BAR)

    act1_verify(trap)
    act2_admit(trap, clean)
    ok = act3_enforce(clean)

    hr("DONE")
    print("  verify   -> catches the lie (deterministic)")
    print("  admit    -> refuses it at the door")
    print("  enforce  -> makes it unexecutable even after install")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
