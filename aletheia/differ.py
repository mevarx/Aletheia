"""Deterministic comparison of freshly compiled source against shipped bytecode.

This is the heart of Aletheia. No model, no heuristics: walk both code objects
recursively and report every structural difference. The executed cache either
corresponds to the source, or it does not.
"""
from __future__ import annotations

from types import CodeType

# Positional/debug attributes differ harmlessly between any two compiles of
# the same or different sources. Semantics live in the rest.
IGNORED_ATTRS = frozenset({
    "co_filename", "co_firstlineno", "co_qualname",
    "co_linetable", "co_lnotab", "co_exceptiontable",
})


def diff_code_objects(source_code: CodeType, shipped_code: CodeType,
                      path: str = "<module>") -> list[dict]:
    """Recursively compare two code objects. Returns a list of differences."""
    diffs: list[dict] = []

    for attr in ("co_name", "co_argcount", "co_posonlyargcount", "co_kwonlyargcount",
                 "co_nlocals", "co_flags", "co_code", "co_names", "co_varnames",
                 "co_freevars", "co_cellvars", "co_stacksize"):
        if attr in IGNORED_ATTRS:
            continue
        a = getattr(source_code, attr, None)
        b = getattr(shipped_code, attr, None)
        if a != b:
            diffs.append({"where": path, "attr": attr,
                          "source": _preview(a), "executed": _preview(b)})

    a_consts = getattr(source_code, "co_consts", ())
    b_consts = getattr(shipped_code, "co_consts", ())
    if len(a_consts) != len(b_consts):
        diffs.append({"where": path, "attr": "co_consts.length",
                      "source": str(len(a_consts)), "executed": str(len(b_consts))})
    for i, (ca, cb) in enumerate(zip(a_consts, b_consts)):
        cpath = f"{path}.co_consts[{i}]"
        if isinstance(ca, CodeType) and isinstance(cb, CodeType):
            diffs.extend(diff_code_objects(ca, cb, f"{cpath}({ca.co_name})"))
        elif isinstance(ca, CodeType) != isinstance(cb, CodeType):
            diffs.append({"where": cpath, "attr": "type",
                          "source": type(ca).__name__, "executed": type(cb).__name__})
        elif ca != cb:
            diffs.append({"where": cpath, "attr": "value",
                          "source": _preview(ca), "executed": _preview(cb)})
    return diffs


def _preview(value, limit: int = 110) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."
