"""Archivos y rutas sensibles expuestos por error. Peticiones GET simples y acotadas (sin fuerza bruta)."""
from __future__ import annotations

import re

from ..http_client import origin_of
from ..models import Finding, Severity
from . import Context, register

# (ruta, regex que confirma el contenido, severidad, título, recomendación)
SENSITIVE = [
    ("/.env", r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=", Severity.CRITICAL, "Archivo .env expuesto",
     "Bloquea el acceso al archivo, rota todas las credenciales que contenía y mueve la configuración fuera del directorio público."),
    ("/.git/HEAD", r"^ref:\s*refs/", Severity.HIGH, "Repositorio .git expuesto",
     "Bloquea /.git en el servidor web; un atacante puede reconstruir el código fuente completo."),
    ("/.git/config", r"\[core\]", Severity.HIGH, "Configuración de .git expuesta",
     "Bloquea /.git en el servidor web."),
    ("/.svn/entries", r"^\d+\s*$|dir", Severity.MEDIUM, "Metadatos de Subversion expuestos", "Bloquea /.svn."),
    ("/.DS_Store", r"Bud1", Severity.LOW, "Archivo .DS_Store expuesto", "Elimina el archivo y bloquea su acceso."),
    ("/wp-config.php.bak", r"DB_PASSWORD|DB_NAME", Severity.CRITICAL, "Respaldo de wp-config expuesto",
     "Elimina respaldos del directorio público y rota las credenciales de base de datos."),
    ("/backup.sql", r"(?i)CREATE TABLE|INSERT INTO", Severity.CRITICAL, "Volcado SQL expuesto",
     "Elimina el archivo y rota credenciales; asume que los datos fueron comprometidos."),
    ("/phpinfo.php", r"(?i)PHP Version|phpinfo\(\)", Severity.MEDIUM, "phpinfo() expuesto",
     "Elimina el archivo: revela versiones, rutas y configuración."),
    ("/server-status", r"(?i)Apache Server Status", Severity.MEDIUM, "Apache server-status accesible",
     "Restringe /server-status a IPs internas."),
    ("/actuator/env", r"(?i)propertySources|activeProfiles", Severity.HIGH, "Spring Boot Actuator /env expuesto",
     "Restringe los endpoints de Actuator o exige autenticación."),
    ("/composer.json", r'"require"\s*:', Severity.INFO, "composer.json accesible",
     "Evita exponer manifiestos de dependencias (revelan versiones)."),
    ("/package.json", r'"(dependencies|scripts)"\s*:', Severity.INFO, "package.json accesible",
     "Evita exponer manifiestos de dependencias (revelan versiones)."),
]


def _looks_like_html_catchall(body: str, main_body: str) -> bool:
    """Descarta SPAs/páginas 404 'blandas' que devuelven 200 con el mismo HTML."""
    return body.strip()[:300] == main_body.strip()[:300]


@register("exposure")
def check_exposure(ctx: Context) -> list[Finding]:
    base = origin_of(ctx.final_url)
    main_text = ctx.main.text if ctx.main else ""
    out: list[Finding] = []

    # Línea base: ¿el sitio devuelve 200 para rutas inexistentes (soft-404)?
    probe = ctx.client.get_quiet(base + "/webscan-no-existe-7f3a9c", follow_redirects=False)
    soft404 = bool(probe and probe.status == 200)

    for path, pattern, sev, title, rec in SENSITIVE:
        resp = ctx.client.get_quiet(base + path, follow_redirects=False)
        if resp is None or resp.status != 200:
            continue
        body = resp.text[:4000]
        if soft404 and _looks_like_html_catchall(body, main_text):
            continue
        if not re.search(pattern, body):
            continue
        out.append(Finding(
            f"exposure.{path.strip('/').replace('/', '_').replace('.', '')}", title, sev,
            f"La ruta {path} responde 200 y su contenido coincide con el formato esperado del archivo.",
            rec, evidence=f"GET {base}{path} -> 200 (contenido no mostrado por seguridad)"))

    # robots.txt / security.txt (informativo)
    sec = ctx.client.get_quiet(base + "/.well-known/security.txt", follow_redirects=True)
    if not sec or sec.status != 200 or "contact" not in sec.text.lower():
        out.append(Finding(
            "exposure.security_txt", "Sin security.txt", Severity.INFO,
            "No hay un canal publicado para que investigadores reporten vulnerabilidades (RFC 9116).",
            "Publica /.well-known/security.txt con Contact y Expires.", reference="https://securitytxt.org/"))

    # Listado de directorios en la raíz
    if ctx.main and re.search(r"<title>\s*Index of /", ctx.main.text, re.I):
        out.append(Finding("exposure.dir_listing", "Listado de directorios habilitado", Severity.MEDIUM,
                           "El servidor muestra el contenido de directorios.", "Desactiva autoindex/Options -Indexes."))
    return out
