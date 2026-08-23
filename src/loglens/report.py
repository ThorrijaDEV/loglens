from __future__ import annotations

import html
import time
from pathlib import Path

from loglens.detect import Finding
from loglens.parsers import Event

SEV_COLOR = {"info": "#86868b", "warn": "#b58a00", "high": "#d32f2f"}
SEV_BG = {"info": "#f5f5f7", "warn": "#fff8e1", "high": "#fdecec"}

_CSS = """
body{font:15px/1.6 -apple-system,'Segoe UI',sans-serif;color:#1d1d1f;background:#f5f5f7;margin:0;padding:40px 16px}
main{max-width:900px;margin:0 auto}
h1{font-size:26px;letter-spacing:-.02em}h1 span{color:#0a84ff}
.meta{color:#6e6e73;font-size:13px;margin-bottom:26px}
.kpis{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:26px}
.kpi{flex:1;min-width:130px;background:#fff;border-radius:14px;padding:14px 18px;
 box-shadow:0 1px 3px rgba(0,0,0,.06)}
.kpi b{display:block;font-size:24px}.kpi span{font-size:12px;color:#6e6e73;text-transform:uppercase;letter-spacing:.05em}
section{background:#fff;border-radius:14px;padding:20px 24px;margin-bottom:18px;box-shadow:0 1px 3px rgba(0,0,0,.06)}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.08em;color:#6e6e73;margin:0 0 12px}
.finding{border-left:4px solid #ccc;background:#fafafa;border-radius:8px;padding:10px 14px;margin-bottom:10px}
.finding .t{font-weight:600}
.finding .d{font-size:13.5px;color:#48484a;margin-top:2px}
.finding .m{font-size:12px;color:#86868b;margin-top:3px;font-variant-numeric:tabular-nums}
.badge{float:right;font-size:11px;text-transform:uppercase;letter-spacing:.06em;padding:2px 9px;border-radius:99px;color:#fff}
.timeline{list-style:none;margin:0;padding:0;font-size:13px;font-variant-numeric:tabular-nums}
.timeline li{padding:3px 0;border-bottom:1px solid #f0f0f2;display:flex;gap:10px}
.timeline time{color:#86868b;min-width:150px}
footer{color:#86868b;font-size:12px;margin-top:26px;text-align:center}
"""


def _fmt_ts(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts)) + " UTC"


def render_report(
    sources: list[str],
    events: list[Event],
    findings: list[Finding],
    out_path: Path,
    window_label: str = "",
) -> Path:
    auth_n = sum(1 for e in events if e.kind == "auth")
    web_n = len(events) - auth_n
    fails_auth = sum(1 for e in events if e.kind == "auth" and e.failed)
    errs_web = sum(1 for e in events if e.kind == "web" and e.status >= 400)

    sev_rank = {"high": 0, "warn": 1, "info": 2}
    ordered = sorted(findings, key=lambda f: (sev_rank[f.severity], -f.count))

    kpis = [
        ("Hallazgos", str(len(findings))),
        ("Eventos", str(len(events))),
        ("Auth procesados", str(auth_n)),
        ("Fallos de login", str(fails_auth)),
        ("Web procesados", str(web_n)),
        ("Respuestas ≥400", str(errs_web)),
    ]

    parts = [
        "<!DOCTYPE html><html lang='es'><head><meta charset='utf-8'>",
        "<title>loglens · informe</title>",
        f"<style>{_CSS}</style></head><body><main>",
        "<h1>log<span>lens</span> · informe</h1>",
        "<p class='meta'>"
        + html.escape(", ".join(Path(s).name for s in sources) or "stdin")
        + (f" · {html.escape(window_label)}" if window_label else "")
        + f" · generado {time.strftime('%Y-%m-%d %H:%M')}"
        + "</p>",
        "<div class='kpis'>"
        + "".join(f"<div class='kpi'><b>{html.escape(v)}</b><span>{html.escape(k)}</span></div>"
                  for k, v in kpis)
        + "</div>",
        "<section><h2>Hallazgos</h2>",
    ]
    if not ordered:
        parts.append("<p style='color:#1a7f37'>Sin actividad sospechosa detectada.</p>")
    for f in ordered:
        parts.append(
            f"<div class='finding' style=\"border-color:{SEV_COLOR[f.severity]};background:{SEV_BG[f.severity]}\">"
            f"<span class='badge' style=\"background:{SEV_COLOR[f.severity]}\">{f.severity}</span>"
            f"<div class='t'>{html.escape(f.title)}</div>"
            f"<div class='d'>{html.escape(f.detail)}</div>"
            f"<div class='m'>{_fmt_ts(f.first_ts)} → {_fmt_ts(f.last_ts)} · regla {html.escape(f.rule)}</div>"
            "</div>")
    parts.append("</section><section><h2>Línea temporal (primeros 60 eventos)</h2><ul class='timeline'>")
    for e in events[:60]:
        if e.kind == "auth":
            desc = f"{'FALLO' if e.failed else 'ok'} login {e.user or '?'} desde {e.ip or '?'}"
            color = SEV_COLOR["high"] if e.failed else "inherit"
        else:
            desc = f"{e.method} {e.path} → {e.status}"
            color = SEV_COLOR["warn"] if e.failed else "inherit"
        parts.append(
            f"<li><time>{time.strftime('%H:%M:%S', time.gmtime(e.ts))}</time>"
            f"<span style='color:{color}'>{html.escape(desc)}</span></li>")
    parts.append("</ul></section>")
    parts.append(
        "<footer>Generado por loglens — análisis local y offline; los logs no salen de tu máquina.</footer>"
    )
    parts.append("</main></body></html>")

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(parts), encoding="utf-8")
    return out_path
