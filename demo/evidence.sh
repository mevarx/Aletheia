#!/usr/bin/env bash
# Regenerate the complete three-scanner comparison evidence.
# Run from the repo root:  bash demo/evidence.sh
# Requires: aletheia installed (pip install -e .), and optionally
# cisco-ai-skill-scanner + NVIDIA skillspector on PATH for the comparison.

set -u
cd "$(dirname "$0")/.."

# IMPORTANT: forge and scan with the SAME interpreter, and ideally the one
# the incumbent scanners were installed under — a .pyc's magic number is
# interpreter-specific, and cross-version scanning degrades to SKIPPED.
PY="${PYTHON:-python}"
command -v "$PY" >/dev/null 2>&1 || PY=python3

echo "============================================================"
echo " ALETHEIA DEMO EVIDENCE — $(date)"
echo "============================================================"
echo
echo ">>> Step 1: forge the trap skill (benign source + malicious bytecode)"
$PY -m aletheia forge demo/trap-skill || exit 1
echo

echo ">>> Step 2: loader proof — what does Python ACTUALLY execute?"
$PY demo/loader_proof.py
echo

echo ">>> Step 3: ALETHEIA verdict"
$PY -m aletheia scan demo/trap-skill --semantic --html demo/aletheia-report.html
echo

echo ">>> Step 4: incumbent scanners (if installed)"
if command -v skill-scanner >/dev/null 2>&1; then
  echo "--- Cisco skill-scanner ---"
  skill-scanner scan demo/trap-skill --format json 2>/dev/null | $PY -c "
import sys, json
d = json.load(sys.stdin)
for f in d.get('findings', []):
    if f.get('severity') in ('CRITICAL', 'HIGH'):
        msg = (f.get('message') or '')[:180]
        print(f\"  [{f['severity']}] {f.get('rule_id')}: {msg}\")
"
else
  echo "  (cisco-ai-skill-scanner not on PATH — install with:"
  echo "   pip install cisco-ai-skill-scanner)"
fi
echo

if command -v skillspector >/dev/null 2>&1; then
  echo "--- NVIDIA SkillSpector ---"
  skillspector scan demo/trap-skill --format json 2>/dev/null | $PY -c "
import sys, json
d = json.load(sys.stdin)
ra = d.get('risk_assessment', {})
print(f\"  score={ra.get('score')} severity={ra.get('severity')} rec={ra.get('recommendation')}\")
for f in d.get('issues', []):
    if f.get('severity') in ('CRITICAL', 'HIGH'):
        print(f\"  [{f['severity']}] {f.get('pattern')}\")
        print(f\"      {(f.get('explanation') or '')[:160]}\")
"
else
  echo "  (nvidia skillspector not on PATH)"
fi
echo

echo ">>> Step 5: test suite"
$PY -m pytest tests/ -q 2>/dev/null || echo "  (pytest not installed: pip install pytest)"
echo
echo "============================================================"
echo " Evidence complete. Reports in demo/"
echo "============================================================"
