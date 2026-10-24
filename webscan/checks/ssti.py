"""Prueba ACTIVA de Server-Side Template Injection (SSTI). Requiere --active.

Solo detección por reflexión, sin payloads de explotación (nada de acceso a `__class__`,
ejecución de comandos vía el motor de plantillas, lectura de archivos, etc.): se envía una
multiplicación de dos números aleatorios en la sintaxis de los motores de plantillas más
habituales; si el *resultado* (no la expresión literal) aparece en la respuesta, el motor la
evaluó en el servidor. No es ejecución de código: solo matemática, suficiente para confirmar
la inyección sin tocar nada más.
"""
from __future__ import annotations

import re
import secrets

from ..discovery import build_url, discover_params
from ..models import Finding, Severity
from . import Context, register

MAX_PARAMS = 6
OWASP = "https://owasp.org/www-community/attacks/Server_Side_Template_Injection"


def _engines(a: int, b: int) -> dict[str, str]:
    return {
        "Jinja2/Twig": f"{{{{{a}*{b}}}}}",
        "ERB (Ruby)": f"<%= {a}*{b} %>",
        "Freemarker/EL": f"${{{a}*{b}}}",
    }


@register("ssti", active=True)
def check_ssti(ctx: Context) -> list[Finding]:
    if not ctx.main or "html" not in ctx.main.headers.get("Content-Type", "").lower():
        return []
    params = discover_params(ctx.final_url, ctx.main.text, max_params=MAX_PARAMS)
    out: list[Finding] = []

    for p in params:
        a, b = secrets.randbelow(900) + 100, secrets.randbelow(900) + 100
        product = str(a * b)
        if product in ctx.main.text:
            continue  # coincidencia improbable con contenido ya existente: se descarta este par

        for engine, expr in _engines(a, b).items():
            resp = ctx.client.get_quiet(build_url(p.base_url, {**p.other_params, p.name: expr}))
            if resp is None or "html" not in resp.headers.get("Content-Type", "").lower():
                continue
            if expr in resp.text:
                continue  # se reflejó tal cual: no fue evaluada, es solo reflexión sin escapar
            if re.search(rf"\b{re.escape(product)}\b", resp.text):
                out.append(Finding(
                    "active.ssti", f"Posible SSTI ({engine}) en el parámetro '{p.name}'",
                    Severity.CRITICAL,
                    f"Al enviar la expresión {expr!r} en el parámetro, la respuesta contiene "
                    f"{product} -el resultado de la multiplicación-, lo que indica que el motor de "
                    "plantillas evaluó la expresión en el servidor en vez de tratarla como texto.",
                    "Nunca construyas plantillas concatenando entrada de usuario; pasa siempre los "
                    "datos del usuario como variables a una plantilla precompilada, nunca como código "
                    "de plantilla.",
                    evidence=f"GET {p.base_url}  ?{p.name}={expr}  -> contiene {product} en el cuerpo",
                    reference=OWASP))
                break  # confirmado con este motor; no hace falta probar los demás
    return out
