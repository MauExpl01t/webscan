"""Prueba ACTIVA de XSS reflejado. Requiere --active (opt-in explícito).

No ejecuta JavaScript ni usa payloads "con efecto" (alert, fetch, etc.): envía una marca
aleatoria con los metacaracteres típicos de ruptura de HTML (`"'><`) en cada parámetro GET
descubierto y comprueba si la respuesta la devuelve tal cual, sin codificar. Esa falta de
escape es la condición necesaria para que un payload real se ejecute en el navegador de una
víctima; no se llega a comprobar la ejecución porque esta herramienta no tiene navegador y
porque hacerlo no aportaría nada que el escaneo no pueda ya inferir con seguridad.
"""
from __future__ import annotations

import secrets

from ..discovery import build_url, discover_params
from ..models import Finding, Severity
from . import Context, register

MAX_PARAMS = 6
OWASP = "https://owasp.org/www-community/attacks/xss/"


@register("xss_reflected", active=True)
def check_xss(ctx: Context) -> list[Finding]:
    if not ctx.main or "html" not in ctx.main.headers.get("Content-Type", "").lower():
        return []
    params = discover_params(ctx.final_url, ctx.main.text, max_params=MAX_PARAMS)
    out: list[Finding] = []
    for p in params:
        token = "wsxss" + secrets.token_hex(4)
        probe = f"\"'><{token}>"  # rompe atributo, comilla y etiqueta; no es ejecutable
        resp = ctx.client.get_quiet(build_url(p.base_url, {**p.other_params, p.name: probe}))
        if resp is None or "html" not in resp.headers.get("Content-Type", "").lower():
            continue
        if probe in resp.text:
            out.append(Finding(
                "active.xss_reflected",
                f"Posible XSS reflejado en el parámetro '{p.name}'",
                Severity.HIGH,
                "El valor enviado en el parámetro se refleja en el HTML de la respuesta sin "
                "codificar comillas ni los signos < >. Un payload real (p. ej. una etiqueta "
                "<script> o un manejador de evento) probablemente se ejecutaría en el navegador "
                "de quien visite esa URL manipulada.",
                "Codifica (HTML-encode) toda entrada reflejada en la respuesta; usa un motor de "
                "plantillas con auto-escape activado y añade una Content-Security-Policy restrictiva "
                "como defensa en profundidad.",
                evidence=f"GET {p.base_url}  ?{p.name}={probe}  -> se refleja igual en el cuerpo",
                reference=OWASP))
    return out
