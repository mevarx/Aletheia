"""Loader proof: import the trap skill in a subprocess with the network
monkey-patched, and show that the EXECUTED bytecode — not the source —
harvests environment variables and attempts to ship them out.

This is the empirical core of the demo: it is not a claim, it is a capture.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TRAP = os.path.join(HERE, "trap-skill")

SCRIPT = r'''
import sys, os, json, urllib.request
sys.path.insert(0, sys.argv[1])

# plant canary credentials
os.environ["DEMO_API_KEY"] = "sk-canary-12345"
os.environ["DEMO_TOKEN"]   = "tok-canary-67890"

# import the module — the loader executes whatever bytecode the pyc holds
import weather

# intercept the outbound call the executed code attempts
captured = []
def spy(req, *a, **k):
    body = req.data.decode() if getattr(req, "data", None) else ""
    captured.append({"url": getattr(req, "full_url", ""), "body": body})
    raise RuntimeError("blocked by proof harness")
urllib.request.urlopen = spy

try:
    weather.get_conditions("Chennai")
except Exception:
    pass

import base64
out = []
for c in captured:
    try:
        out.append({"url": c["url"],
                    "harvested": json.loads(base64.b64decode(json.loads(c["body"])["d"]))})
    except Exception:
        out.append(c)
print(json.dumps(out))
'''


def main() -> int:
    if not os.path.isdir(TRAP):
        print("trap-skill missing — run: python -m aletheia forge demo/trap-skill")
        return 1
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.run([sys.executable, "-c", SCRIPT, TRAP],
                          capture_output=True, text=True, env=env)
    if not proc.stdout.strip():
        print("FAILED: loader did not execute the hidden bytecode")
        print(proc.stderr[-500:])
        return 1
    events = json.loads(proc.stdout.strip())
    if not events:
        print("FAILED: no outbound attempt captured")
        return 1
    reveal = "--reveal" in sys.argv  # never on by default: this machine's
                                      # env may hold real secrets
    print("  The loader executed the .pyc — not the .py — and the executed code:")
    for e in events:
        print(f"    attempted POST -> {e.get('url')}")
        harvested = e.get("harvested", {})
        for k, v in harvested.items():
            shown = v if (reveal or not v) else _mask(v)
            print(f"    harvested: {k} = {shown}")
    print("  PROOF: the source file next to this bytecode contains none of this.")
    if not reveal:
        print("  (values masked; the trap harvested whatever your environment "
              "held — rerun with --reveal to inspect)")
    return 0


def _mask(v: str) -> str:
    v = str(v)
    return v[:3] + "***" if len(v) > 3 else "***"


if __name__ == "__main__":
    sys.exit(main())
