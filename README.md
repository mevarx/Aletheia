# Aletheia

**Read what runs, not what is shown.**

A bytecode-truth scanner for AI agent skills. Every security scanner on the
market — Cisco's 2,588★ skill-scanner, NVIDIA SkillSpector, Snyk agent-scan
— reads a skill's `SKILL.md` and its visible `.py` source. But Python never
runs the source. It runs the compiled `.pyc` from `__pycache__/`, selected
by a 16-byte header. A skill can ship innocent source and a swapped bytecode
cache that the loader executes without ever recompiling.

The attack is real, recent, and citable: **arXiv 2610.10612 ("PyCache
Trap")** measured **94–100% attack success across 100 skills and all 7 major
scanners** at the time of writing, with "no semantic recognition of the
cache-resident behavior."

## What Aletheia does that the incumbents don't

Benchmarked head-to-head (see `bash demo/evidence.sh`):

| Scanner | What it reports on a PyCache Trap skill |
|---|---|
| Cisco skill-scanner | `BYTECODE_SOURCE_MISMATCH` — CRITICAL, "tampered" (structural fact) |
| NVIDIA SkillSpector | HIGH, "DO NOT INSTALL" — but the `.pyc` content is *excluded from analysis* |
| **Aletheia** | CRITICAL **+ what the executed code actually does**: "harvests environment variables, encodes them, transmits over HTTPS to `collector...`" |

Detection is now table stakes; **explanation is not.** The paper's own
finding — "no semantic recognition of the cache-resident behavior" — is
still true of the incumbents. Aletheia closes exactly that gap, locally.

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

python -m aletheia forge demo/trap-skill
python -m aletheia scan demo/trap-skill --semantic --html report.html
bash demo/evidence.sh          # full three-scanner comparison
```

Exit code is `1` on any CRITICAL finding — usable as a CI gate.

## The demo, in one breath

```bash
bash demo/evidence.sh
```

It forges the trap, **proves the loader really executes the hidden bytecode**
(capturing the harvested canary credentials mid-flight), prints Aletheia's
deterministic CRITICAL verdict and the local-model explanation, runs Cisco's
and NVIDIA's scanners on the same folder for comparison, and runs the test
suite. Every claim in this README is reproducible by that one command.

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
  report.py      self-contained HTML report
  cli.py         scan / forge commands
  forge.py       builds the trap skill for demos and tests
demo/            evidence script + loader proof
tests/           pytest suite: trap caught, clean passes, loader proof
```

## Test suite

```bash
python -m pytest tests/ -v
# 9 passed — includes test_loader_actually_executes_malicious_bytecode,
# the empirical proof that the loader runs the hidden code.
```
