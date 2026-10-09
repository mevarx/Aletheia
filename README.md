# Aletheia

**Read what runs, not what is shown.**

A **trust gate for the agent skill ecosystem** — three layers, one idea:
detection is table stakes; *enforcement* is the product.

```
  VERIFY   →  ADMIT   →  ENFORCE
   catch      refuse      make it
   the lie    at the      unexecutable
              door        even after install
```

## The problem

AI agent skills (a `SKILL.md` plus scripts) execute with the user's full
permissions. Every security scanner on the market — Cisco's 2,588★
skill-scanner, NVIDIA SkillSpector, Snyk agent-scan — reads the skill's
documentation and visible `.py` source. But Python never runs the source.
It runs the compiled `.pyc` from `__pycache__/`, selected by a 16-byte
header. A skill can ship innocent source and a swapped bytecode cache that
the loader executes without ever recompiling.

The attack is real, recent, and citable: **arXiv 2610.10612 ("PyCache
Trap")** measured **94–100% attack success across 100 skills and all 7
major scanners** at the time of writing, with "no semantic recognition of
the cache-resident behavior."

## The three layers

**1. VERIFY — the scanner.** Deterministic code-object diff between
compiled source and shipped `.pyc` (no model). The loader's own PEP 552
header decision is reproduced exactly; sourceless bytecode is blocked
outright. Behavior extraction reads the *executed* bytecode — imports,
names accessed, URL constants — and derives an exfiltration signature. An
optional local open-weight model (Gemma 3 4B via Ollama) writes the
plain-language verdict: what the source claims vs. what the bytecode does.

**2. ADMIT — the gate.** A bundle is admitted only when every module's
bytecode matches its source. Admission writes a manifest of trusted
reference hashes. **Traps are refused at the door** — they never reach a
manifest an agent could trust.

**3. ENFORCE — the runtime guard.** A `sys.meta_path` hook inside the
agent's own process re-verifies every import against the manifest: source
changed, module unlisted, or bytecode that doesn't match the admission
reference raises `ImportError` **before a single instruction executes.**
An attacker who swaps the `.pyc` *after* installation still cannot run
their code.

This is the difference between an antivirus that finds malware and a
runtime that cannot run it.

## Head-to-head: what the incumbents report

Benchmarked on the same trap skill (`bash demo/evidence.sh`):

| Scanner | Report on a PyCache Trap skill |
|---|---|
| Cisco skill-scanner | `BYTECODE_SOURCE_MISMATCH` — CRITICAL, "tampered" (structural fact, no explanation) |
| NVIDIA SkillSpector | HIGH, "DO NOT INSTALL" — but the `.pyc` content is *excluded from analysis* |
| **Aletheia** | CRITICAL **+ what the executed code does** + admission refusal + runtime enforcement |

Detection is table stakes; **explanation and enforcement are not.**

## How it works

1. **Deterministic core (no model):** recompile each `.py`, walk both code
   objects recursively (`co_code`, `co_consts`, `co_names`, …), diff them.
   The loader's own PEP 552 header decision (mtime/size or source hash) is
   reproduced exactly. Sourceless `.pyc` artifacts are blocked outright.
2. **Behavior extraction (no model):** read the *executed* bytecode —
   imports, names accessed, URL constants — and derive signals: network
   capability, credential access, exfiltration signature.
3. **Semantic layer (optional):** a local open-weight model (Gemma 3 4B via
   Ollama) writes the plain-language verdict: what the source claims vs.
   what the executed bytecode actually does. The detection does not depend
   on it.

## Quick start

```bash
pip install -e .
ollama pull gemma3:4b          # optional, for semantic verdicts

# the full three-act demo — verify, admit, enforce
python demo/three_act_demo.py

# or the pieces:
python -m aletheia forge demo/trap-skill
python -m aletheia forge --clean demo/clean-skill
python -m aletheia scan demo/trap-skill --semantic --html report.html
python -m aletheia admit demo/trap-skill        # REFUSED
python -m aletheia admit demo/clean-skill       # ADMITTED
bash demo/evidence.sh          # three-scanner comparison
```

Exit code is `1` on any CRITICAL finding or refused admission — usable as
a CI gate.

## The demo, in one breath

```bash
python demo/three_act_demo.py
```

**ACT 1 — VERIFY:** the scanner catches the trap. Deterministic, no model.

**ACT 2 — ADMIT:** the gate refuses the trap at the door and admits the
honest skill, writing its manifest.

**ACT 3 — ENFORCE:** a live trojan-swap on the *admitted* skill — the
attacker replaces the `.pyc` after installation — is blocked mid-import.
The agent's import fails safe; the malicious bytecode never executes.

`demo/evidence.sh` additionally runs Cisco's and NVIDIA's scanners on the
same trap for the head-to-head comparison, and the test suite.

## Why it must run locally

Verifying an untrusted skill by uploading it to someone's cloud API *is*
the attack — you'd be shipping a stranger's potential payload to a third
party to ask if it's safe. And detection logic has to be open, or attackers
stay ahead of it. The whole tool is stdlib Python; the model layer is an
explanation, never the detection.

## Safety

`forge.py` produces a self-contained demo whose collector URL is a
non-resolvable `.invalid` domain and whose payload contains only
demonstration variables. It never contacts a real endpoint.

## Layout

```
aletheia/
  pycformat.py   PEP 552 header parsing + loader-acceptance reproduction
  differ.py      recursive code-object diff (the deterministic core)
  behavior.py    behavior extraction from executed bytecode
  scanner.py     bundle walking + verdict logic (incl. sourceless .pyc)
  semantic.py    optional local open-weight model layer (Ollama/Gemma)
  guard.py       admission gate + runtime meta_path enforcement
  report.py      self-contained HTML report
  cli.py         scan / forge / admit commands
  forge.py       trap + honest skill generators
demo/
  three_act_demo.py   verify → admit → enforce, in one run
  evidence.sh         three-scanner comparison
  loader_proof.py     captures the loader executing hidden bytecode
tests/           14 tests: trap caught, clean passes, admission refusal,
                 post-admission trojan-swap blocked, loader proof
```

## Test suite

```bash
python -m pytest tests/ -v
# 14 passed — including test_post_admission_trojan_swap_is_blocked:
# the empirical proof that enforcement works.
```
