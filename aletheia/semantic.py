"""Optional LLM semantic layer. Everything deterministic works without it.

When Ollama is reachable and a model is pulled, Aletheia asks the model to
read the executed bytecode's behavior summary and the source, and write the
plain-language verdict the paper found no scanner produces: what the code
that RUNS does, versus what the code you can READ claims.
"""
from __future__ import annotations

import json
import os
import urllib.request

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
DEFAULT_MODEL = os.environ.get("ALETHEIA_MODEL", "gemma3:4b")

PROMPT_TEMPLATE = """You are a security analyst reviewing an AI agent skill bundle.

A skill ships BOTH Python source AND a compiled bytecode cache. A deterministic
scanner proved the executed bytecode differs from the source. Your job: explain
what the EXECUTED bytecode actually does, versus what the source claims.

SOURCE CODE (what a human reviewer reads):
{source_code}

EXECUTED BYTECODE — extracted behavior (never lies):
- imports: {imports}
- names/attributes accessed: {names}
- URL constants found: {urls}
- behavioral signals: {signals}
- notable string constants: {consts}

STRUCTURAL DIFFS between compiled source and executed bytecode (first 8):
{diffs}

Write a plain-language verdict in under 120 words:
1. What the SOURCE claims to do.
2. What the EXECUTED bytecode actually does.
3. One sentence on why the difference matters for someone installing this skill.
No preamble. No markdown headers."""


def ollama_available(host: str = OLLAMA_HOST) -> bool:
    try:
        with urllib.request.urlopen(f"{host}/api/tags", timeout=3) as r:
            json.loads(r.read())
        return True
    except Exception:
        return False


def model_pulled(model: str = DEFAULT_MODEL, host: str = OLLAMA_HOST) -> bool:
    try:
        with urllib.request.urlopen(f"{host}/api/tags", timeout=3) as r:
            data = json.loads(r.read())
        return any(m.get("name", "").split(":")[0] == model.split(":")[0]
                   for m in data.get("models", []))
    except Exception:
        return False


def status(model: str = DEFAULT_MODEL,
           host: str = OLLAMA_HOST) -> dict:
    """Gemma enablement status for the frontend: availability + model."""
    available = ollama_available(host)
    pulled = model_pulled(model, host) if available else False
    return {
        "host": host,
        "model": model,
        "ollama_available": available,
        "model_pulled": pulled,
        "gemma_enabled": bool(available and pulled),
        "hint": (None if (available and pulled) else
                 f"run: ollama pull {model}  (OLLAMA_HOST={host})"),
    }


def explain_mismatch(source_code: str, executed_behavior: dict,
                     diffs: list, model: str = DEFAULT_MODEL,
                     host: str = OLLAMA_HOST, timeout: int = 90) -> str | None:
    """Ask the local model for the semantic verdict. None if unavailable."""
    chunks = list(explain_mismatch_stream(
        source_code, executed_behavior, diffs,
        model=model, host=host, timeout=timeout))
    return "".join(chunks).strip() or None if chunks else None


def explain_mismatch_stream(source_code: str, executed_behavior: dict,
                            diffs: list, model: str = DEFAULT_MODEL,
                            host: str = OLLAMA_HOST,
                            timeout: int = 90):
    """Yield semantic verdict tokens as they arrive (Ollama stream=True).

    Yields str chunks. Yields nothing when Gemma is not enabled — the
    deterministic detection never depends on it, so callers must treat
    an empty stream as 'semantic unavailable' and continue.
    """
    if not (ollama_available(host) and model_pulled(model, host)):
        return
    prompt = PROMPT_TEMPLATE.format(
        source_code=source_code,
        imports=", ".join(executed_behavior.get("imports", [])) or "none",
        names=", ".join(executed_behavior.get("names_accessed", [])[:20]) or "none",
        urls=", ".join(executed_behavior.get("urls", [])) or "none",
        signals=", ".join(executed_behavior.get("signals", [])) or "none",
        consts=" | ".join(executed_behavior.get("string_constants", [])[:6]) or "none",
        diffs="\n".join(f"- {d['attr']} @ {d['where']}" for d in diffs[:8]) or "none",
    )
    body = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": True,
        "options": {"temperature": 0},
    }).encode()
    req = urllib.request.Request(f"{host}/api/generate", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            for line in r:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                except Exception:
                    continue
                chunk = data.get("response", "")
                if chunk:
                    yield chunk
                if data.get("done"):
                    break
    except Exception:
        return
