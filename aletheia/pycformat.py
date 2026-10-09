"""Parsing and validation of CPython .pyc cache headers (PEP 552).

A .pyc file starts with a 16-byte header: 4 bytes magic, 4 bytes flags, then
either (source mtime, source size) for timestamp-based caches, or an 8-byte
source hash for hash-based caches. The loader decides whether to *execute the
cache* or *recompile the source* purely from this header — which is why a
patched header is the hinge of the whole attack.
"""
from __future__ import annotations

import importlib.util
import os
import struct
from dataclasses import dataclass

MAGIC = importlib.util.MAGIC_NUMBER
HEADER_SIZE = 16

FLAG_HASH_BASED = 0b01
FLAG_CHECK_SOURCE = 0b10


@dataclass
class PycHeader:
    magic: bytes
    magic_matches: bool
    flags: int
    hash_based: bool
    check_source: bool
    source_mtime: int | None
    source_size: int | None
    source_hash: bytes | None


@dataclass
class HeaderValidation:
    """What the loader would DO with this cache for this source."""
    mode: str     # "timestamp" | "hash" | "hash-unchecked" | "unknown"
    trusted: bool  # True => loader executes this cache without recompiling
    detail: str


def parse_header(data: bytes) -> PycHeader:
    if len(data) < HEADER_SIZE:
        raise ValueError("file too small to be a .pyc")
    magic = data[:4]
    flags = struct.unpack("<I", data[4:8])[0]
    hash_based = bool(flags & FLAG_HASH_BASED)
    check_source = bool(flags & FLAG_CHECK_SOURCE)
    if hash_based:
        return PycHeader(magic, magic == MAGIC, flags, hash_based, check_source,
                         None, None, data[8:16])
    mtime, size = struct.unpack("<II", data[8:16])
    return PycHeader(magic, magic == MAGIC, flags, hash_based, check_source,
                     mtime, size, None)


def validate_against_source(header: PycHeader, source_path: str) -> HeaderValidation:
    """Reproduce CPython's cache-acceptance decision for this source file."""
    st = os.stat(source_path)
    if not header.magic_matches:
        return HeaderValidation("unknown", False,
                                "pyc magic does not match this interpreter; "
                                "this cache is not loadable here")
    if header.hash_based:
        if header.check_source:
            return HeaderValidation("hash", True,
                                    "hash-based cache with source check enabled")
        return HeaderValidation(
            "hash-unchecked", True,
            "hash-based cache with source checking DISABLED — never invalidated, "
            "even if the source file changes")
    if header.source_size == 0:
        return HeaderValidation("timestamp", False,
                                "cache records source size 0 (atomic-write mode); "
                                "loader recompiles")
    if (header.source_mtime == int(st.st_mtime)
            and header.source_size == st.st_size):
        return HeaderValidation(
            "timestamp", True,
            f"header matches source (mtime={header.source_mtime}, "
            f"size={header.source_size}) — the loader executes this bytecode "
            f"WITHOUT ever recompiling the source")
    return HeaderValidation(
        "timestamp", False,
        f"header stale (cache records mtime={header.source_mtime}, "
        f"size={header.source_size}; source is mtime={int(st.st_mtime)}, "
        f"size={st.st_size}) — loader would recompile")


def load_code_object(pyc_path: str):
    """Read the marshalled code object from a .pyc. Returns (code, header)."""
    import marshal
    with open(pyc_path, "rb") as f:
        data = f.read()
    header = parse_header(data)
    if not header.magic_matches:
        raise ValueError("pyc magic mismatch: compiled for a different Python version")
    return marshal.loads(data[HEADER_SIZE:]), header
