"""Generación de reportes: texto (terminal), JSON y HTML autocontenido."""
from __future__ import annotations

import json
from html import escape

from .models import ScanResult, Severity

COLORS = {"CRITICAL": "#7f1d1d", "HIGH": "#b91c1c", "MEDIUM": "#c2410c", "LOW": "#a16207", "INFO": "#475569"}


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)


def to_text(result: ScanResult, color: bool = True) -> str:
    def c(sev: str, s: str) -> str:
        if not color:
            return s
        code = {"CRITICAL": "1;41", "HIGH": "1;31", "MEDIUM": "33", "LOW": "36", "INFO": "90"}[sev]
        return f"\033[{code}m{s}\033[0m"

    lines = [f"Objetivo : {result.target}", f"Puntaje  : {result.score()}/100",
             "Resumen  : " + ", ".join(f"{k}={v}" for k, v in result.summary().items() if v) or "sin hallazgos", ""]
    for f in result.sorted_findings():
        lines.append(f"[{c(f.severity.name, f.severity.label.upper())}] {f.title}  ({f.check})")
        lines.append(f"    {f.description}")
        if f.evidence:
            lines.append("    Evidencia: " + f.evidence.replace("\n", "\n               "))
        if f.recommendation:
            lines.append(f"    Solución : {f.recommendation}")
        lines.append("")
    for e in result.errors:
        lines.append(f"[!] {e}")
    return "\n".join(lines)


def to_html(result: ScanResult) -> str:
    summ = result.summary()
    chips = "".join(
        f'<span class="chip" style="background:{COLORS[k]}">{Severity[k].label}: {v}</span>'
        for k, v in summ.items() if v) or "<span>Sin hallazgos</span>"
    cards = []
    for f in result.sorted_findings():
        col = COLORS[f.severity.name]
        ref = f'<p class="ref"><a href="{escape(f.reference)}" rel="noopener noreferrer">Referencia</a></p>' if f.reference else ""
        ev = f"<pre>{escape(f.evidence)}</pre>" if f.evidence else ""
        rec = f"<p><strong>Solución:</strong> {escape(f.recommendation)}</p>" if f.recommendation else ""
        cards.append(
            f'<article style="border-left:6px solid {col}"><h3><span class="sev" style="background:{col}">'
            f'{f.severity.label}</span> {escape(f.title)}</h3><p>{escape(f.description)}</p>{ev}{rec}{ref}'
            f'<p class="id">{escape(f.check)}</p></article>')
    errs = "".join(f"<li>{escape(e)}</li>" for e in result.errors)
    errs = f"<h2>Advertencias</h2><ul>{errs}</ul>" if errs else ""
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Reporte WebScan - {escape(result.target)}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#0f172a;background:#f8fafc}}
h1{{margin-bottom:.2rem}} .meta{{color:#475569}} .score{{font-size:2.5rem;font-weight:700}}
.chip{{color:#fff;padding:.2rem .6rem;border-radius:999px;margin-right:.4rem;font-size:.85rem}}
article{{background:#fff;padding:1rem 1.2rem;margin:1rem 0;border-radius:8px;box-shadow:0 1px 3px #0001}}
.sev{{color:#fff;padding:.1rem .5rem;border-radius:4px;font-size:.8rem;vertical-align:middle}}
pre{{background:#f1f5f9;padding:.6rem;border-radius:6px;overflow:auto;white-space:pre-wrap}}
.id{{color:#94a3b8;font-size:.75rem;margin:0}}
</style></head><body>
<h1>Reporte de seguridad</h1>
<p class="meta">{escape(result.target)} · {escape(result.started_at)}</p>
<p><span class="score">{result.score()}</span>/100 &nbsp; {chips}</p>
{errs}
<h2>Hallazgos ({len(result.findings)})</h2>
{''.join(cards) or '<p>No se detectaron hallazgos.</p>'}
<p class="meta">Diagnóstico pasivo y no intrusivo. Un puntaje alto no garantiza ausencia de vulnerabilidades.</p>
</body></html>"""
