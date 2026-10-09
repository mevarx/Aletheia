"""HTML report — the deliverable judges read. Self-contained, no assets."""
from __future__ import annotations

import html
import json

_CSS = """
:root { --bg:#0b0d10; --card:#14171c; --border:#262b33; --fg:#e8eaed;
        --muted:#9aa3ad; --accent:#6ea8fe; --crit:#ff5c5c; --susp:#ffb020;
        --ok:#3ecf8e; --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
* { box-sizing:border-box; margin:0; padding:0; }
body { background:var(--bg); color:var(--fg);
       font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
       padding:32px 20px; }
.wrap { max-width:980px; margin:0 auto; }
h1 { font-size:26px; letter-spacing:-.02em; }
h1 .greek { color:var(--accent); font-style:italic; }
.sub { color:var(--muted); margin:6px 0 24px; }
.verdict-banner { border-radius:12px; padding:20px 24px; margin:20px 0;
  border:1px solid var(--border); background:var(--card); }
.verdict-banner.critical { border-color:var(--crit); }
.verdict-banner .tag { font:700 12px/1 var(--mono); letter-spacing:.12em;
  padding:4px 10px; border-radius:6px; display:inline-block; margin-bottom:10px; }
.critical .tag { background:var(--crit); color:#1a0505; }
.clean .tag { background:var(--ok); color:#04160c; }
.suspicious .tag { background:var(--susp); color:#1a1200; }
.stats { display:flex; gap:12px; flex-wrap:wrap; margin:18px 0 28px; }
.stat { background:var(--card); border:1px solid var(--border); border-radius:10px;
  padding:12px 18px; min-width:120px; }
.stat b { display:block; font-size:22px; }
.stat.crit b { color:var(--crit); } .stat.susp b { color:var(--susp); }
.stat.ok b { color:var(--ok); }
.stat span { color:var(--muted); font-size:12px; text-transform:uppercase;
  letter-spacing:.08em; }
.file { background:var(--card); border:1px solid var(--border); border-radius:12px;
  padding:20px 22px; margin:14px 0; }
.file.critical { border-color:var(--crit); }
.file.suspicious { border-color:var(--susp); }
.file h3 { font:600 15px/1.3 var(--mono); margin-bottom:4px; }
.file .meta { color:var(--muted); font:12px/1.6 var(--mono); margin-bottom:12px; }
.reason { margin:10px 0; padding:12px 14px; border-radius:8px;
  background:#1b1f26; border-left:3px solid var(--border); }
.critical .reason { border-left-color:var(--crit); }
.suspicious .reason { border-left-color:var(--susp); }
.clean .reason { border-left-color:var(--ok); }
.behavior { margin-top:12px; font:12.5px/1.7 var(--mono); }
.behavior .row { display:flex; gap:8px; margin:3px 0; }
.behavior .k { color:var(--muted); min-width:110px; flex-shrink:0; }
.behavior .v { word-break:break-all; }
.signal { display:inline-block; background:#2a1414; color:#ff9c9c; border-radius:5px;
  padding:1px 8px; margin:2px 4px 2px 0; font:11px/1.7 var(--mono); }
table.diff { width:100%; border-collapse:collapse; font:12px/1.5 var(--mono);
  margin-top:10px; }
table.diff th { text-align:left; color:var(--muted); font-weight:600;
  padding:6px 8px; border-bottom:1px solid var(--border); }
table.diff td { padding:6px 8px; border-bottom:1px solid #1c2027;
  vertical-align:top; word-break:break-all; }
.semantic { margin-top:14px; padding:14px 16px; border-radius:8px;
  background:#10161f; border:1px solid #1e2a3a; }
.semantic h4 { font:700 11px/1 var(--mono); letter-spacing:.12em;
  color:var(--accent); margin-bottom:8px; }
footer { color:var(--muted); font-size:12px; margin-top:36px; text-align:center; }
code { font:12.5px var(--mono); background:#1b1f26; padding:1px 6px; border-radius:4px; }
"""


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def render(report, semantic_verdicts: dict | None = None) -> str:
    semantic_verdicts = semantic_verdicts or {}
    cls = report.worst.lower()
    tag_text = {
        "CRITICAL": "CRITICAL — EXECUTED BYTECODE IS NOT THE SOURCE",
        "SUSPICIOUS": "SUSPICIOUS — REVIEW REQUIRED",
        "CLEAN": "CLEAN — ALL CACHES MATCH SOURCES",
    }.get(report.worst, report.worst)

    parts = [f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Aletheia — scan report</title><style>{_CSS}</style></head><body><div class="wrap">
<h1><span class="greek">Aletheia</span> — read what runs, not what is shown</h1>
<p class="sub">Bundle: <code>{_esc(report.root)}</code></p>
<div class="verdict-banner {cls}"><span class="tag">{_esc(tag_text)}</span>
<p>{_banner_line(report)}</p></div>
<div class="stats">
<div class="stat crit"><b>{report.critical}</b><span>critical</span></div>
<div class="stat susp"><b>{report.suspicious}</b><span>suspicious</span></div>
<div class="stat ok"><b>{report.clean}</b><span>clean</span></div>
<div class="stat"><b>{report.skipped}</b><span>skipped</span></div>
<div class="stat"><b>{report.source_only}</b><span>source-only</span></div>
</div>"""]

    for fr in report.files:
        parts.append(_render_file(fr, semantic_verdicts.get(fr.source)))
    parts.append("""<footer>Aletheia — deterministic code-object diff + optional local open-weight
semantic layer. The detection does not depend on the model.</footer>
</div></body></html>""")
    return "\n".join(parts)


def _banner_line(report) -> str:
    if report.worst == "CRITICAL":
        n = report.critical
        return (f"{n} source file{'s' if n != 1 else ''} ship a compiled cache the "
                f"loader will execute without recompiling, and that bytecode is not "
                f"the source. Every documentation-reading scanner passes this bundle.")
    if report.worst == "SUSPICIOUS":
        return (f"{report.suspicious} file(s) have untrustworthy bytecode artifacts. "
                f"No active trap confirmed, but the bundle is not clean.")
    return ("Every .pyc in this bundle corresponds to its source. Nothing here "
            "executes differently than it reads.")


def _render_file(fr, semantic: str | None) -> str:
    cls = fr.verdict.lower()
    out = [f'<div class="file {cls}"><h3>{_esc(fr.source)}</h3>']
    out.append(f'<div class="meta">verdict: <b>{_esc(fr.verdict)}</b> · '
               f'pyc: {_esc(fr.pyc or "—")} · header: {_esc(fr.header_mode or "—")}</div>')
    out.append(f'<div class="reason">{_esc(fr.reason)}</div>')

    beh = fr.executed_behavior
    if beh:
        sigs = "".join(f'<span class="signal">{_esc(s)}</span>'
                       for s in beh.get("signals", []))
        rows = []
        if beh.get("imports"):
            rows.append(("imports", ", ".join(beh["imports"])))
        if beh.get("urls"):
            rows.append(("urls", ", ".join(beh["urls"])))
        if beh.get("names_accessed"):
            rows.append(("names used", ", ".join(beh["names_accessed"][:14])))
        if beh.get("string_constants"):
            rows.append(("consts", " | ".join(beh["string_constants"][:5])))
        out.append('<div class="behavior">'
                   '<div class="row"><span class="k">executed</span>'
                   f'<span class="v">{sigs}</span></div>')
        for k, v in rows:
            out.append(f'<div class="row"><span class="k">{_esc(k)}</span>'
                       f'<span class="v">{_esc(v)}</span></div></div>')

    if fr.diffs:
        out.append('<table class="diff"><tr><th>attribute</th><th>where</th>'
                   '<th>source says</th><th>bytecode does</th></tr>')
        for d in fr.diffs[:10]:
            out.append(f'<tr><td>{_esc(d["attr"])}</td><td>{_esc(d["where"])}</td>'
                       f'<td>{_esc(d["source"])}</td><td>{_esc(d["executed"])}</td></tr>')
        out.append("</table>")
        if fr.diff_count > 10:
            out.append(f'<p class="meta" style="margin-top:6px">…and '
                       f'{fr.diff_count - 10} more structural diffs</p>')

    if semantic:
        out.append(f'<div class="semantic"><h4>LOCAL OPEN-WEIGHT MODEL — SEMANTIC '
                   f'VERDICT</h4><p>{_esc(semantic)}</p></div>')
    out.append("</div>")
    return "".join(out)
