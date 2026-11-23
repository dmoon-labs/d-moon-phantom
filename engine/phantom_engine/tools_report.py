"""J. Security Reporting (5 tools). Reports are stored as JSON under
$PHANTOM_HOME/reports (default ~/.d-moon/reports)."""
import html
import json
import os
import re
from datetime import datetime, timezone

from .common import PhantomError, home
from .registry import tool

ID_RE = re.compile(r"^RPT-\d{8}-\d{6}-[0-9a-f]{8}$")
SEVS = ["critical", "high", "medium", "low", "info"]
DISCLAIMER = ("Findings marked 'heuristic' are rules of thumb, not verified threat intelligence. "
              "'fact' means a deterministic check on the supplied data; 'intel' means a match in a feed you imported.")


def _dir():
    d = os.path.join(home(), "reports")
    os.makedirs(d, exist_ok=True)
    return d


@tool("RPT-001", "report.build", "Assemble tool results into one report (severity totals, tool list, disclaimer) and optionally save it locally.",
      "title:str, results:list, target:str=, save:bool=true", "id, title, created, summary, findings, tools, saved_to, disclaimer", "file-write")
def rpt_build(p):
    created = datetime.now(timezone.utc)
    rid = "RPT-%s-%s" % (created.strftime("%Y%m%d-%H%M%S"), os.urandom(4).hex())
    findings, tools_run, errors = [], [], []
    for env in p["results"][:500]:
        if not isinstance(env, dict):
            continue
        name = env.get("tool", "?")
        if not env.get("ok"):
            errors.append({"tool": name, "error": (env.get("error") or {}).get("message", "failed")})
            continue
        tools_run.append(name)
        for f in (env.get("result") or {}).get("findings", []) or []:
            if isinstance(f, dict) and f.get("severity") in SEVS:
                findings.append(dict(f, tool=name))
    findings.sort(key=lambda f: SEVS.index(f["severity"]))
    summary = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVS}
    summary["tools_run"] = len(tools_run)
    summary["tools_failed"] = len(errors)
    report = {"id": rid, "title": p["title"][:200], "target": p["target"][:300], "created": created.isoformat(),
              "summary": summary, "findings": findings[:5000], "tools": tools_run, "errors": errors,
              "disclaimer": DISCLAIMER, "saved_to": None}
    if p["save"]:
        path = os.path.join(_dir(), rid + ".json")
        report["saved_to"] = path
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=1)
    return report


def render_text(r):
    lines = ["D-MOON PHANTOM REPORT", "=" * 60, "ID:      %s" % r.get("id", "-"), "Title:   %s" % r.get("title", ""),
             "Target:  %s" % (r.get("target") or "-"), "Created: %s" % r.get("created", "-"), ""]
    s = r.get("summary", {})
    lines.append("Summary: " + ", ".join("%s=%s" % (k, s.get(k, 0)) for k in SEVS))
    lines.append("Tools run: %s   failed: %s" % (s.get("tools_run", 0), s.get("tools_failed", 0)))
    lines.append("")
    for f in r.get("findings", []):
        lines.append("[%s] (%s) %s" % (f["severity"].upper(), f.get("kind", "heuristic"), f["title"]))
        if f.get("detail"):
            lines.append("    " + str(f["detail"]))
        lines.append("    tool: %s" % f.get("tool", "-"))
    if not r.get("findings"):
        lines.append("No findings.")
    for e in r.get("errors", []):
        lines.append("ERROR %s: %s" % (e["tool"], e["error"]))
    lines += ["", r.get("disclaimer", DISCLAIMER)]
    return "\n".join(lines)


@tool("RPT-002", "report.render_txt", "Render a report object as plain text.",
      "report:dict", "text")
def rpt_txt(p):
    return {"text": render_text(p["report"])}


COLORS = {"critical": "#ff6b8a", "high": "#ff9f6b", "medium": "#e6c76b", "low": "#9db4ff", "info": "#9aa0b4"}


@tool("RPT-003", "report.render_html", "Render a report as a self-contained dark HTML page (all values escaped, no scripts, no external resources).",
      "report:dict", "html, bytes")
def rpt_html(p):
    r, e = p["report"], html.escape
    s = r.get("summary", {})
    rows = []
    for f in r.get("findings", []):
        c = COLORS.get(f["severity"], "#9aa0b4")
        rows.append('<tr><td style="color:%s"><b>%s</b></td><td>%s</td><td>%s<br><small>%s</small></td><td>%s</td></tr>' % (
            c, e(f["severity"].upper()), e(str(f.get("kind", ""))), e(str(f["title"])), e(str(f.get("detail", ""))), e(str(f.get("tool", "")))))
    chips = "".join('<span class="chip" style="border-color:%s">%s %s</span>' % (COLORS[k], k, int(s.get(k, 0))) for k in SEVS)
    doc = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
           '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
           '<meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title><style>'
           'body{margin:0;background:#0d0b14;color:#e8e6f0;font:15px/1.5 system-ui,sans-serif;padding:20px}'
           'h1{font-size:20px;letter-spacing:.12em;color:#c9b8ff;margin:0 0 4px}.meta{color:#9aa0b4;font-size:13px}'
           '.chip{display:inline-block;border:1px solid;border-radius:999px;padding:2px 10px;margin:10px 6px 10px 0;font-size:13px}'
           'table{width:100%%;border-collapse:collapse;margin-top:10px}td,th{padding:8px;border-bottom:1px solid #2a2540;text-align:left;vertical-align:top;font-size:14px}'
           'th{color:#9aa0b4;font-weight:500}small{color:#9aa0b4}.wrap{overflow-x:auto}.note{margin-top:18px;color:#9aa0b4;font-size:13px}'
           '</style></head><body><h1>D-MOON PHANTOM</h1><div class="meta">%s &middot; %s &middot; %s</div>%s'
           '<div class="wrap"><table><tr><th>Severity</th><th>Basis</th><th>Finding</th><th>Tool</th></tr>%s</table></div>'
           '<p class="note">%s</p></body></html>') % (
        e(str(r.get("title", "Report"))), e(str(r.get("id", ""))), e(str(r.get("target") or "no target")),
        e(str(r.get("created", ""))), chips, "".join(rows) or "<tr><td colspan=4>No findings.</td></tr>",
        e(str(r.get("disclaimer", DISCLAIMER))))
    return {"html": doc, "bytes": len(doc.encode("utf-8"))}


@tool("RPT-004", "report.list", "List saved reports (newest first) with severity totals.",
      "limit:int=20", "reports, total", "file-read")
def rpt_list(p):
    names = sorted((f for f in os.listdir(_dir()) if f.endswith(".json") and ID_RE.match(f[:-5])), reverse=True)
    out = []
    for n in names[:max(1, min(500, p["limit"]))]:
        try:
            with open(os.path.join(_dir(), n), encoding="utf-8") as fh:
                r = json.load(fh)
            out.append({"id": r["id"], "title": r.get("title", ""), "target": r.get("target", ""),
                        "created": r.get("created", ""), "summary": r.get("summary", {})})
        except (OSError, ValueError, KeyError):
            continue
    return {"reports": out, "total": len(names)}


@tool("RPT-005", "report.show", "Load a saved report by ID and return it as JSON, text or HTML.",
      "id:str, format:str=json", "report, rendered", "file-read")
def rpt_show(p):
    if not ID_RE.match(p["id"]):
        raise PhantomError("bad_params", "invalid report ID format")
    fp = os.path.join(_dir(), p["id"] + ".json")
    if not os.path.isfile(fp):
        raise PhantomError("not_found", "no such report: " + p["id"])
    with open(fp, encoding="utf-8") as fh:
        r = json.load(fh)
    fmt = p["format"]
    if fmt not in ("json", "txt", "html"):
        raise PhantomError("bad_params", "format must be json, txt or html")
    rendered = render_text(r) if fmt == "txt" else rpt_html({"report": r})["html"] if fmt == "html" else None
    return {"report": r, "rendered": rendered}
