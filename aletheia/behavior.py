"""Deterministic behavior extraction from an ACTUAL code object.

Reads the shipped bytecode — never the source — and extracts what it does:
imports, names/attributes accessed, URL constants, string constants. Then
derives behavioral signals. This is what makes the report meaningful without
any LLM, and what feeds the semantic layer when one is available.
"""
from __future__ import annotations

import dis
import re
from types import CodeType

NETWORK_MODULES = {
    "socket", "ssl", "requests", "httpx", "aiohttp", "urllib", "urllib.request",
    "http", "http.client", "ftplib", "smtplib", "telnetlib", "paramiko", "websocket",
}
OBFUSCATION_MODULES = {"base64", "codecs", "zlib", "binascii", "marshal"}
CREDENTIAL_ATTRS = {"environ", "getenv", "expanduser"}
EXEC_ATTRS = {"system", "popen", "run", "call", "check_output", "Popen", "execv", "spawn"}
DYNAMIC_EXEC = {"eval", "exec", "compile", "__import__"}

_URL_RE = re.compile(r"https?://[^\s\"'<>\\]+")


def _walk(code: CodeType):
    yield code
    for c in code.co_consts:
        if isinstance(c, CodeType):
            yield from _walk(c)


def extract_behavior(code: CodeType) -> dict:
    imports, names_used, string_consts = set(), set(), []
    for co in _walk(code):
        for instr in dis.get_instructions(co):
            if instr.opname == "IMPORT_NAME" and instr.argval:
                imports.add(instr.argval)
            elif instr.opname in ("LOAD_GLOBAL", "LOAD_NAME", "LOAD_ATTR",
                                  "LOAD_METHOD") and instr.argval:
                names_used.add(instr.argval)
            elif instr.opname == "LOAD_CONST" and isinstance(instr.argval, str):
                string_consts.append(instr.argval)

    urls = sorted({u for s in string_consts for u in _URL_RE.findall(s)})
    network = bool(NETWORK_MODULES & imports) or bool(urls)
    credential = bool(CREDENTIAL_ATTRS & names_used)

    signals = []
    if network:
        signals.append("network capability")
    if credential:
        signals.append("credential/environment access")
    if EXEC_ATTRS & names_used:
        signals.append("process execution")
    if DYNAMIC_EXEC & names_used:
        signals.append("dynamic code execution")
    if OBFUSCATION_MODULES & imports:
        signals.append("encoding/obfuscation primitives")

    interesting_consts = sorted(
        {s.strip() for s in string_consts if s.strip() and not s.isspace()},
        key=len, reverse=True)[:12]

    return {
        "imports": sorted(imports),
        "names_accessed": sorted(names_used),
        "urls": urls,
        "string_constants": interesting_consts,
        "signals": signals,
        "exfiltration_signature": network and credential,
    }
