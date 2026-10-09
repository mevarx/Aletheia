"""Aletheia CLI.

  aletheia scan <bundle>            scan a skill folder, print verdict
  aletheia scan <bundle> --html r   write an HTML report
  aletheia scan <bundle> --json     machine-readable output
  aletheia scan <bundle> --semantic include local LLM verdicts
  aletheia forge <dest>             create a trap skill (demo/tests)
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .report import render
from .scanner import scan_bundle
from .semantic import explain_mismatch, model_pulled, ollama_available


def _print_console(report) -> None:
    color = {"CRITICAL": "\033[91m", "SUSPICIOUS": "\033[93m",
             "CLEAN": "\033[92m", "SOURCE-ONLY": "\033[90m",
             "SKIPPED": "\033[90m"}
    reset = "\033[0m"
    print(f"\nAletheia {__version__} — {report.root}")
    print(f"verdict: {color.get(report.worst, '')}{report.worst}{reset}  "
          f"(critical={report.critical} suspicious={report.suspicious} "
          f"clean={report.clean})\n")
    for fr in report.files:
        mark = color.get(fr.verdict, "")
        print(f"  {mark}[{fr.verdict}]{reset} {fr.source}")
        print(f"      {fr.reason}")
    if report.worst == "CLEAN":
        print("\nAll caches match their sources.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="aletheia",
                                 description="Read what runs, not what is shown.")
    ap.add_argument("--version", action="version",
                    version=f"aletheia {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="scan a skill bundle")
    sc.add_argument("bundle")
    sc.add_argument("--html", metavar="FILE", help="write HTML report")
    sc.add_argument("--json", action="store_true", help="JSON output")
    sc.add_argument("--semantic", action="store_true",
                    help="include local LLM semantic verdicts (needs Ollama)")

    fo = sub.add_parser("forge", help="create a trap skill for demos/tests")
    fo.add_argument("dest")
    fo.add_argument("--clean", action="store_true",
                    help="forge an HONEST skill (positive control)")

    ad = sub.add_parser("admit", help="verify a bundle and write its "
                                      "admission manifest")
    ad.add_argument("bundle")

    args = ap.parse_args(argv)

    if args.cmd == "forge":
        from .forge import forge_trap_skill, forge_clean_skill
        if args.clean:
            dest = forge_clean_skill(args.dest)
            print(f"clean skill written to {dest}")
        else:
            dest = forge_trap_skill(args.dest)
            print(f"trap skill written to {dest}")
        print("every documentation scanner passes this; run aletheia scan on it")
        return 0

    if args.cmd == "admit":
        from .guard import admit
        result = admit(args.bundle)
        if result.admitted:
            print(f"ADMITTED: {result.modules} module(s) verified — "
                  f"bytecode matches source")
            print(f"manifest: {result.manifest_path}")
            return 0
        print(f"REFUSED: {len(result.refused)} finding(s) — bundle not admitted")
        for rel, reason in result.refused:
            print(f"  - {rel}: {reason}")
        return 1

    report = scan_bundle(args.bundle)

    semantic = {}
    if args.semantic:
        if not (ollama_available() and model_pulled()):
            print("semantic layer unavailable (Ollama down or model not pulled) — "
                  "continuing with deterministic results only", file=sys.stderr)
        else:
            import os
            for fr in report.files:
                if fr.verdict == "CRITICAL":
                    src = os.path.join(report.root, fr.source)
                    with open(src, encoding="utf-8", errors="replace") as f:
                        code = f.read()
                    v = explain_mismatch(code, fr.executed_behavior, fr.diffs)
                    if v:
                        semantic[fr.source] = v

    if args.json:
        d = report.__dict__.copy()
        d["semantic"] = semantic
        print(json.dumps(d, indent=2, default=str))
    else:
        _print_console(report)
        for k, v in semantic.items():
            print(f"\n  semantic verdict — {k}:\n    "
                  + "\n    ".join(v.splitlines()))

    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(render(report, semantic))
        print(f"\nHTML report: {args.html}")

    return 1 if report.worst == "CRITICAL" else 0


if __name__ == "__main__":
    sys.exit(main())
