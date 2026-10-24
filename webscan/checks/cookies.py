"""Atributos de seguridad de las cookies."""
from __future__ import annotations

import re

from ..models import Finding, Severity
from . import Context, register

SESSION_HINT = re.compile(r"(sess|sid|token|auth|jwt|login|csrf|xsrf)", re.I)
MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security"


def _raw_set_cookies(ctx: Context) -> list[str]:
    raw = ctx.main.response.raw
    try:
        return raw.headers.getlist("Set-Cookie")  # urllib3 HTTPHeaderDict
    except AttributeError:
        v = ctx.main.headers.get("Set-Cookie")
        return [v] if v else []


@register("cookies")
def check_cookies(ctx: Context) -> list[Finding]:
    if not ctx.main:
        return []
    out: list[Finding] = []
    is_https = ctx.final_url.startswith("https://")
    for raw in _raw_set_cookies(ctx):
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0]
        attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1)[1] if "=" in p else True) for p in parts[1:]}
        sensitive = bool(SESSION_HINT.search(name))
        sev_hi = Severity.MEDIUM if sensitive else Severity.LOW

        if is_https and "secure" not in attrs:
            out.append(Finding(
                "cookies.secure", f"Cookie '{name}' sin atributo Secure", sev_hi,
                "La cookie puede enviarse por conexiones HTTP sin cifrar.",
                "Agrega el atributo Secure.", evidence=raw[:200], reference=MDN))
        if "httponly" not in attrs:
            out.append(Finding(
                "cookies.httponly", f"Cookie '{name}' sin atributo HttpOnly", sev_hi,
                "JavaScript puede leer la cookie; un XSS permitiría robar la sesión.",
                "Agrega el atributo HttpOnly (salvo que el frontend deba leerla).", evidence=raw[:200], reference=MDN))
        samesite = str(attrs.get("samesite", "")).lower()
        if not samesite:
            out.append(Finding(
                "cookies.samesite", f"Cookie '{name}' sin atributo SameSite", Severity.LOW,
                "Sin SameSite, la cookie se envía en peticiones entre sitios (riesgo de CSRF).",
                "Agrega SameSite=Lax (o Strict).", evidence=raw[:200], reference=MDN))
        elif samesite == "none" and "secure" not in attrs:
            out.append(Finding(
                "cookies.samesite_none", f"Cookie '{name}' con SameSite=None sin Secure", Severity.MEDIUM,
                "SameSite=None requiere Secure; los navegadores modernos rechazan la cookie.",
                "Agrega Secure o cambia a Lax.", evidence=raw[:200], reference=MDN))
        if name.startswith("__Host-") and ("domain" in attrs or attrs.get("path") != "/"):
            out.append(Finding(
                "cookies.prefix", f"Cookie '{name}' viola el prefijo __Host-", Severity.LOW,
                "El prefijo __Host- exige Secure, Path=/ y sin Domain.", "Ajusta los atributos.", evidence=raw[:200]))
    return out
