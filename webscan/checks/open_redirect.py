"""Prueba ACTIVA de redirección abierta (open redirect). Requiere --active (opt-in explícito).

Busca parámetros con nombres habituales para redirecciones (url, next, redirect, return...)
y comprueba si el servidor redirige directamente a un dominio externo arbitrario. El dominio
de prueba (webscan-probe.invalid) no existe: solo se usa como marca, nunca se llega a conectar
a él (la validación de redirecciones de HttpClient además lo bloquearía si lo intentara).
"""
from __future__ import annotations

import re

from ..discovery import build_url, discover_params
from ..models import Finding, Severity
from . import Context, register

MAX_PARAMS = 6
PROBE = "https://webscan-probe.invalid/open-redirect-check"
REDIRECT_PARAM = re.compile(
    r"^(url|next|redirect(_?uri|_?url)?|return(_?url)?|continue|dest(ination)?|target|out|r|u|to|goto)$",
    re.I)
OWASP = "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"


@register("open_redirect", active=True)
def check_open_redirect(ctx: Context) -> list[Finding]:
    if not ctx.main:
        return []
    params = discover_params(ctx.final_url, ctx.main.text, max_params=MAX_PARAMS)
    out: list[Finding] = []
    for p in params:
        if not REDIRECT_PARAM.match(p.name):
            continue
        url = build_url(p.base_url, {**p.other_params, p.name: PROBE})
        resp = ctx.client.get_quiet(url, follow_redirects=False)
        if resp is None:
            continue
        location = resp.headers.get("Location", "")
        if resp.response.is_redirect and location.startswith(PROBE):
            out.append(Finding(
                "active.open_redirect", f"Redirección abierta en el parámetro '{p.name}'", Severity.MEDIUM,
                "El servidor redirige directamente a la URL indicada en el parámetro, sin validar que "
                "pertenezca a una lista de destinos permitidos. Se abusa para phishing (el enlace inicial "
                "es del dominio legítimo) y puede filtrar tokens si ocurre durante un flujo OAuth.",
                "Valida el destino contra una lista blanca de rutas/dominios, o usa un identificador "
                "interno en vez de recibir una URL completa.",
                evidence=f"GET {p.base_url}  ?{p.name}={PROBE}  -> Location: {location}",
                reference=OWASP))
    return out
