"""Análisis del HTML: contenido mixto, SRI, formularios y fugas de información."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup, Comment

from ..models import Finding, Severity
from . import Context, register

SRI_MDN = "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"
SECRET_PATTERNS = {
    "Clave de AWS": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Clave privada": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Token de GitHub": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "Token de Slack": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "Clave de API de Google": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
}


@register("content")
def check_content(ctx: Context) -> list[Finding]:
    if not ctx.main:
        return []
    ctype = ctx.main.headers.get("Content-Type", "")
    if "html" not in ctype.lower():
        return []
    out: list[Finding] = []
    soup = BeautifulSoup(ctx.main.text, "html.parser")
    page = urlparse(ctx.final_url)
    https = page.scheme == "https"

    # --- Contenido mixto ---
    if https:
        mixed = []
        for tag, attr in (("script", "src"), ("link", "href"), ("img", "src"), ("iframe", "src"),
                          ("audio", "src"), ("video", "src"), ("source", "src")):
            for el in soup.find_all(tag):
                v = el.get(attr, "")
                if isinstance(v, str) and v.startswith("http://"):
                    mixed.append(f"<{tag}> {v}")
        if mixed:
            active = [m for m in mixed if m.startswith(("<script", "<iframe"))]
            out.append(Finding(
                "content.mixed", "Contenido mixto (recursos HTTP en página HTTPS)",
                Severity.MEDIUM if active else Severity.LOW,
                "La página carga recursos por HTTP sin cifrar; pueden ser alterados por un atacante en la red.",
                "Carga todos los recursos por HTTPS o con rutas relativas.", evidence="\n".join(mixed[:5])))

    # --- Subresource Integrity en recursos de terceros ---
    no_sri = []
    for el in soup.find_all(["script", "link"]):
        url = el.get("src") or el.get("href")
        if not isinstance(url, str) or not url.startswith(("http://", "https://", "//")):
            continue
        if el.name == "link" and "stylesheet" not in (el.get("rel") or []):
            continue
        host = urlparse(url if "//" in url[:8] and not url.startswith("//") else "https:" + url).netloc
        if host and host != page.netloc and not el.get("integrity"):
            no_sri.append(f"<{el.name}> {url}")
    if no_sri:
        out.append(Finding(
            "content.sri", "Recursos de terceros sin Subresource Integrity", Severity.LOW,
            "Scripts/estilos de CDNs externos sin 'integrity': si el CDN es comprometido, el código malicioso se ejecuta en tu sitio.",
            "Agrega integrity y crossorigin a cada recurso externo, o aloja los archivos localmente.",
            evidence="\n".join(no_sri[:5]), reference=SRI_MDN))

    # --- Formularios ---
    for form in soup.find_all("form"):
        action = form.get("action", "") or ""
        method = (form.get("method") or "get").lower()
        has_pw = form.find("input", {"type": "password"}) is not None
        if has_pw and (action.startswith("http://") or (not https and not action.startswith("https://"))):
            out.append(Finding(
                "content.form_http", "Formulario de contraseña enviado sin cifrar", Severity.HIGH,
                "Un formulario con campo de contraseña se envía por HTTP; las credenciales viajan en claro.",
                "Sirve la página y el endpoint de destino exclusivamente por HTTPS.", evidence=f"action={action or '(misma URL)'}"))
        if has_pw and method == "get":
            out.append(Finding(
                "content.form_get", "Contraseña enviada mediante GET", Severity.HIGH,
                "Los datos de la URL quedan en historial, logs y cabeceras Referer.",
                "Usa method=\"post\" para formularios con credenciales."))
        if has_pw:
            ac = (form.find("input", {"type": "password"}).get("autocomplete") or "").lower()
            tokens = [i for i in form.find_all("input", {"type": "hidden"})
                      if re.search(r"csrf|xsrf|token|nonce", (i.get("name") or ""), re.I)]
            if method == "post" and not tokens and "samesite" not in ctx.main.headers.get("Set-Cookie", "").lower():
                out.append(Finding(
                    "content.csrf", "Formulario de login sin token anti-CSRF aparente", Severity.LOW,
                    "No se detectó un campo oculto tipo csrf/token ni cookies SameSite. Verifica manualmente la protección CSRF.",
                    "Implementa tokens anti-CSRF y cookies SameSite=Lax/Strict.", evidence=f"action={action or '(misma URL)'}"))

    # --- Comentarios HTML con información sensible ---
    leaks = []
    for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
        if re.search(r"(todo|fixme|password|passwd|secret|api[_-]?key|token|debug|admin|credencial|clave)", c, re.I):
            leaks.append(c.strip()[:120])
    if leaks:
        out.append(Finding(
            "content.comments", "Comentarios HTML con posible información sensible", Severity.LOW,
            "Hay comentarios en el HTML público que mencionan términos sensibles.",
            "Elimina comentarios de desarrollo antes de publicar.", evidence="\n".join(leaks[:3])))

    # --- Secretos expuestos en el HTML ---
    for label, rx in SECRET_PATTERNS.items():
        m = rx.search(ctx.main.text)
        if m:
            out.append(Finding(
                "content.secret", f"Posible secreto expuesto en el HTML: {label}", Severity.CRITICAL,
                "Se encontró una cadena con el formato de una credencial en el código fuente público.",
                "Revoca y rota la credencial de inmediato; nunca incluyas secretos en el frontend.",
                evidence=m.group(0)[:6] + "…(truncado)"))

    # --- Meta generator ---
    gen = soup.find("meta", attrs={"name": "generator"})
    if gen and gen.get("content") and re.search(r"\d", gen["content"]):
        out.append(Finding(
            "content.generator", "Versión del CMS expuesta en meta generator", Severity.LOW,
            "Revelar el CMS y su versión facilita ataques dirigidos.",
            "Elimina la etiqueta meta generator.", evidence=gen["content"]))
    return out
