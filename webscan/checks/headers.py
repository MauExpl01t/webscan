"""Cabeceras de seguridad HTTP y divulgación de información del servidor."""
from __future__ import annotations

import re

from ..models import Finding, Severity
from . import Context, register

MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"


def _h(ctx: Context, name: str) -> str | None:
    return ctx.main.headers.get(name) if ctx.main else None


@register("headers")
def check_headers(ctx: Context) -> list[Finding]:
    if not ctx.main:
        return []
    out: list[Finding] = []
    is_https = ctx.final_url.startswith("https://")

    # --- HSTS ---
    hsts = _h(ctx, "Strict-Transport-Security")
    if is_https:
        if not hsts:
            out.append(Finding(
                "headers.hsts", "Falta Strict-Transport-Security (HSTS)", Severity.MEDIUM,
                "Sin HSTS, un atacante en la red puede forzar o interceptar conexiones HTTP (SSL stripping).",
                "Agrega: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                reference=MDN + "Strict-Transport-Security"))
        else:
            m = re.search(r"max-age=(\d+)", hsts, re.I)
            if not m or int(m.group(1)) < 15552000:
                out.append(Finding(
                    "headers.hsts_short", "HSTS con max-age bajo", Severity.LOW,
                    "El max-age de HSTS es menor a 6 meses o no está definido.",
                    "Usa al menos max-age=31536000 (1 año).", evidence=f"Strict-Transport-Security: {hsts}",
                    reference=MDN + "Strict-Transport-Security"))

    # --- CSP ---
    csp = _h(ctx, "Content-Security-Policy")
    if not csp:
        out.append(Finding(
            "headers.csp", "Falta Content-Security-Policy (CSP)", Severity.MEDIUM,
            "CSP reduce el impacto de XSS e inyecciones de contenido restringiendo los orígenes permitidos.",
            "Define una CSP restrictiva, p. ej. default-src 'self'; object-src 'none'; frame-ancestors 'self'.",
            reference=MDN + "Content-Security-Policy"))
    else:
        weak = []
        if re.search(r"script-src[^;]*'unsafe-inline'", csp) or (
                "script-src" not in csp and re.search(r"default-src[^;]*'unsafe-inline'", csp)):
            weak.append("'unsafe-inline' en scripts")
        if re.search(r"(script-src|default-src)[^;]*'unsafe-eval'", csp):
            weak.append("'unsafe-eval'")
        if re.search(r"(script-src|default-src)[^;]*(\s\*|https?:\s|\s\*\s)", csp):
            weak.append("comodines o esquemas amplios en script-src/default-src")
        if "object-src" not in csp and "default-src" not in csp:
            weak.append("sin object-src ni default-src")
        if weak:
            out.append(Finding(
                "headers.csp_weak", "Content-Security-Policy débil", Severity.LOW,
                "La CSP existe pero tiene directivas que anulan buena parte de su protección: " + "; ".join(weak) + ".",
                "Elimina 'unsafe-inline'/'unsafe-eval' usando nonces o hashes y restringe los orígenes.",
                evidence=csp[:300], reference=MDN + "Content-Security-Policy"))

    # --- Clickjacking ---
    xfo = _h(ctx, "X-Frame-Options")
    has_fa = bool(csp and "frame-ancestors" in csp)
    if not xfo and not has_fa:
        out.append(Finding(
            "headers.clickjacking", "Sin protección contra clickjacking", Severity.MEDIUM,
            "La página puede incrustarse en un iframe de otro sitio, habilitando ataques de clickjacking.",
            "Usa Content-Security-Policy: frame-ancestors 'self' (o X-Frame-Options: DENY/SAMEORIGIN).",
            reference=MDN + "X-Frame-Options"))

    # --- MIME sniffing ---
    if (_h(ctx, "X-Content-Type-Options") or "").lower() != "nosniff":
        out.append(Finding(
            "headers.nosniff", "Falta X-Content-Type-Options: nosniff", Severity.LOW,
            "El navegador puede interpretar archivos con un tipo MIME distinto al declarado.",
            "Agrega: X-Content-Type-Options: nosniff", reference=MDN + "X-Content-Type-Options"))

    # --- Referrer / Permissions ---
    if not _h(ctx, "Referrer-Policy"):
        out.append(Finding(
            "headers.referrer", "Falta Referrer-Policy", Severity.LOW,
            "URLs internas (con tokens o IDs) pueden filtrarse a terceros mediante la cabecera Referer.",
            "Agrega: Referrer-Policy: strict-origin-when-cross-origin", reference=MDN + "Referrer-Policy"))
    if not _h(ctx, "Permissions-Policy"):
        out.append(Finding(
            "headers.permissions", "Falta Permissions-Policy", Severity.INFO,
            "No se restringen APIs del navegador (cámara, micrófono, geolocalización) para este sitio.",
            "Agrega una Permissions-Policy mínima, p. ej. camera=(), microphone=(), geolocation=().",
            reference=MDN + "Permissions-Policy"))

    # --- Divulgación de tecnología ---
    for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
        val = _h(ctx, name)
        if val and (re.search(r"\d", val) or name != "Server"):
            out.append(Finding(
                f"headers.disclosure.{name.lower()}", f"Divulgación de tecnología en {name}", Severity.LOW,
                "Exponer producto y versión facilita a un atacante buscar vulnerabilidades conocidas (CVE).",
                f"Oculta o genérica la cabecera {name} en el servidor/proxy.", evidence=f"{name}: {val}",
                reference="https://owasp.org/www-project-web-security-testing-guide/"))

    # --- Caché de contenido potencialmente sensible ---
    cc = (_h(ctx, "Cache-Control") or "").lower()
    if ctx.main.headers.get("Set-Cookie") and not any(t in cc for t in ("no-store", "private", "no-cache")):
        out.append(Finding(
            "headers.cache", "Respuesta con cookies sin Cache-Control restrictivo", Severity.LOW,
            "Respuestas que establecen cookies de sesión podrían ser almacenadas por cachés compartidas.",
            "Usa Cache-Control: no-store (o private) en respuestas con datos de sesión.",
            reference=MDN + "Cache-Control"))
    return out


@register("transport")
def check_transport(ctx: Context) -> list[Finding]:
    """Redirección HTTP→HTTPS y degradaciones."""
    out: list[Finding] = []
    from urllib.parse import urlparse

    host = urlparse(ctx.url).netloc
    if ctx.url.startswith("https://"):
        http_resp = ctx.client.get_quiet(f"http://{host}/", follow_redirects=False)
        if http_resp is None:
            return out  # puerto 80 cerrado: aceptable
        loc = http_resp.headers.get("Location", "")
        if not (http_resp.response.is_redirect and loc.startswith("https://")):
            out.append(Finding(
                "transport.no_redirect", "HTTP no redirige a HTTPS", Severity.MEDIUM,
                "El sitio responde por HTTP en claro sin redirigir a HTTPS; el tráfico puede ser interceptado.",
                "Redirige todo el tráfico HTTP a HTTPS con un 301 y habilita HSTS.",
                evidence=f"GET http://{host}/ -> {http_resp.status}"))
    else:
        out.append(Finding(
            "transport.plain_http", "El sitio se analiza por HTTP sin cifrar", Severity.HIGH,
            "La URL usa HTTP: credenciales y datos de sesión viajan sin cifrar.",
            "Sirve el sitio exclusivamente por HTTPS."))
    return out
