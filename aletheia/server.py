"""Aletheia scan server: parse a skill from GitHub with live logs + Gemma.

Run:
  pip install -e .[server]
  python -m aletheia serve --port 8000   # or: uvicorn aletheia.server:app --port 8000

Endpoints:
  GET  /api/health            -> {ok, version}
  GET  /api/ollama/status     -> Gemma enablement (ollama_available, model_pulled)
  POST /api/scan              -> {github_url, semantic} -> full JSON + logs[]
  GET  /api/scan/stream?url=..&semantic=1 -> SSE: `log` events while working,
                               then a `result` event with the verdict.
  GET  /                      -> serves web/dist/index.html when built,
                               else a hint to run the Vite dev server.

The deterministic scan never depends on Gemma: when Ollama is down or
gemma3:4b is not pulled, semantic verdicts are skipped and the scan still
succeeds — the frontend shows the hint `ollama pull gemma3:4b`.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import tempfile

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse
from pydantic import BaseModel

from . import __version__
from .guard import admit
from .scanner import scan_bundle, to_dict
from . import semantic

app = FastAPI(title="Aletheia scan server", version=__version__)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    github_url: str
    semantic: bool = True


def _is_github_url(url: str) -> bool:
    u = url.strip()
    return u.startswith("https://github.com/") or u.startswith("http://github.com/")


async def _clone(url: str, dest: str, logs: list | None = None):
    def emit(msg: str):
        if logs is not None:
            logs.append(msg)
    emit(f"clone {url}")
    proc = await asyncio.create_subprocess_exec(
        "git", "clone", "--depth", "1", url, dest,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    out, _ = await proc.communicate()
    text = out.decode(errors="replace").strip()
    if text:
        emit(text.splitlines()[-1][:300])
    if proc.returncode != 0:
        raise RuntimeError(f"git clone failed: {text[-500:]}")
    emit("clone ok")


def do_scan(bundle: str, want_semantic: bool, logs: list) -> dict:
    logs.append(f"walk {bundle}")
    report = scan_bundle(bundle)
    d = to_dict(report)
    for fr in report.files:
        logs.append(f"verify {fr.source} -> {fr.verdict}: {fr.reason[:140]}")
    logs.append(
        f"verify done: worst={report.worst} "
        f"critical={report.critical} clean={report.clean}")
    # admit gate
    try:
        r = admit(bundle)
        d["admission"] = {
            "admitted": r.admitted, "refused": r.refused,
            "modules": r.modules, "manifest": r.manifest_path}
        if r.admitted:
            logs.append(f"admit ADMITTED ({r.modules} module(s))")
        else:
            logs.append(f"admit REFUSED ({len(r.refused)} finding(s))")
            for rel, reason in r.refused[:5]:
                logs.append(f"  - {rel}: {reason[:140]}")
    except Exception as e:  # admission must never kill the scan
        d["admission"] = {"admitted": False, "error": str(e)[:200]}
        logs.append(f"admit error: {e}")
    # semantic (Gemma) — optional, streamed as logs by the SSE endpoint;
    # here (POST) we collect it synchronously.
    sem: dict = {}
    st = semantic.status()
    d["gemma"] = st
    if want_semantic and report.critical:
        if not st["gemma_enabled"]:
            logs.append(f"semantic skipped ({st['hint']})")
        else:
            for fr in report.files:
                if fr.verdict != "CRITICAL":
                    continue
                src = os.path.join(report.root, fr.source)
                try:
                    with open(src, encoding="utf-8",
                              errors="replace") as f:
                        code = f.read()
                except Exception:
                    continue
                logs.append(f"semantic {fr.source} ...")
                chunks = list(semantic.explain_mismatch_stream(
                    code, fr.executed_behavior, fr.diffs))
                text = "".join(chunks).strip()
                if text:
                    sem[fr.source] = text
                    logs.append(f"semantic {fr.source} done ({len(text)} chars)")
                else:
                    logs.append(f"semantic {fr.source} unavailable")
    d["semantic"] = sem
    d["logs"] = logs
    return d


@app.get("/api/health")
def health():
    return {"ok": True, "version": __version__}


@app.get("/api/ollama/status")
def ollama_status():
    return semantic.status()


@app.post("/api/scan")
async def scan(req: ScanRequest):
    if not _is_github_url(req.github_url):
        return JSONResponse(
            {"error": "github_url must start with https://github.com/"},
            status_code=400)
    logs: list = []
    tmp = tempfile.mkdtemp(prefix="aletheia-web-")
    try:
        await _clone(req.github_url.strip(), os.path.join(tmp, "skill"), logs)
        data = do_scan(os.path.join(tmp, "skill"), req.semantic, logs)
        return data
    except Exception as e:
        logs.append(f"error: {e}")
        return JSONResponse({"error": str(e)[:500], "logs": logs},
                            status_code=500)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@app.get("/api/scan/stream")
async def scan_stream(url: str = Query(...), semantic: bool = True):
    if not _is_github_url(url):
        return JSONResponse(
            {"error": "url must start with https://github.com/"},
            status_code=400)

    async def gen():
        def ev(kind: str, payload: dict):
            return f"event: {kind}\ndata: {json.dumps(payload)}\n\n"

        logs: list = []
        tmp = tempfile.mkdtemp(prefix="aletheia-web-")
        try:
            yield ev("log", {"line": f"clone {url}"})
            proc = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", "1", url,
                os.path.join(tmp, "skill"),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT)
            out, _ = await proc.communicate()
            text = out.decode(errors="replace").strip()
            if text:
                yield ev("log", {"line": text.splitlines()[-1][:300]})
            if proc.returncode != 0:
                yield ev("error", {"message": f"git clone failed"})
                return
            bundle = os.path.join(tmp, "skill")
            yield ev("log", {"line": f"walk {bundle}"})
            # run the blocking scan in a thread so SSE keeps flowing
            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(
                None, do_scan_stream_sync, bundle, semantic, logs)
            for line in logs:
                yield ev("log", {"line": line})
            # stream gemma tokens live when available
            for src, text in data.get("semantic", {}).items():
                yield ev("semantic", {"file": src, "text": text})
            yield ev("result", data)
        except Exception as e:
            yield ev("error", {"message": str(e)[:500]})
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    return StreamingResponse(gen(), media_type="text/event-stream")


def do_scan_stream_sync(bundle: str, want_semantic: bool,
                        logs: list) -> dict:
    """Sync scan used by the SSE endpoint; per-file logs are collected."""
    report = scan_bundle(bundle)
    d = to_dict(report)
    for fr in report.files:
        logs.append(f"verify {fr.source} -> {fr.verdict}: {fr.reason[:140]}")
    logs.append(f"verify done: worst={report.worst} critical={report.critical}")
    try:
        r = admit(bundle)
        d["admission"] = {"admitted": r.admitted, "refused": r.refused,
                          "modules": r.modules}
        logs.append("admit ADMITTED" if r.admitted else "admit REFUSED")
    except Exception as e:
        d["admission"] = {"admitted": False, "error": str(e)[:200]}
    sem: dict = {}
    st = semantic.status()
    d["gemma"] = st
    if want_semantic and report.critical and st["gemma_enabled"]:
        for fr in report.files:
            if fr.verdict != "CRITICAL":
                continue
            src = os.path.join(report.root, fr.source)
            try:
                with open(src, encoding="utf-8", errors="replace") as f:
                    code = f.read()
            except Exception:
                continue
            logs.append(f"semantic {fr.source} ...")
            text = (semantic.explain_mismatch(
                code, fr.executed_behavior, fr.diffs) or "")
            if text:
                sem[fr.source] = text
    else:
        logs.append("semantic skipped" if not want_semantic
                    else f"semantic skipped ({st.get('hint')})"
                    if report.critical else "semantic n/a (no CRITICAL files)")
    d["semantic"] = sem
    return d


@app.get("/")
def index():
    dist = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "web", "dist", "index.html")
    if os.path.isfile(dist):
        return FileResponse(dist)
    return {
        "hint": "web/dist not built — run the Vite dev server: "
                "cd web && npm install && npm run dev",
        "api": ["/api/health", "/api/ollama/status",
                "POST /api/scan", "GET /api/scan/stream?url=.."],
    }


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="aletheia-serve")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args(argv)
    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
