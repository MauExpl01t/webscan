"""Configuración CORS: comprueba reflexión de Origin y comodines con credenciales."""
from __future__ import annotations

from ..models import Finding, Severity
from . import Context, register

MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
PROBE_ORIGIN = "https://webscan-probe.invalid"


@register("cors")
def check_cors(ctx: Context) -> list[Finding]:
    if not ctx.main:
        return []
    resp = ctx.client.get_quiet(ctx.final_url, headers={"Origin": PROBE_ORIGIN}, follow_redirects=False)
    if resp is None:
        return []
    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = (resp.headers.get("Access-Control-Allow-Credentials") or "").lower() == "true"
    out: list[Finding] = []
    if acao == PROBE_ORIGIN:
        out.append(Finding(
            "cors.reflected_origin",
            "CORS refleja cualquier Origin" + (" con credenciales" if acac else ""),
            Severity.HIGH if acac else Severity.MEDIUM,
            "El servidor devuelve el Origin recibido en Access-Control-Allow-Origin sin validarlo. "
            + ("Combinado con Allow-Credentials permite que cualquier sitio lea respuestas autenticadas."
               if acac else "Cualquier sitio puede leer respuestas no autenticadas de este recurso."),
            "Valida el Origin contra una lista blanca explícita; nunca reflejes orígenes arbitrarios.",
            evidence=f"Origin: {PROBE_ORIGIN} -> Access-Control-Allow-Origin: {acao}", reference=MDN))
    elif acao == "*":
        out.append(Finding(
            "cors.wildcard", "CORS con comodín (*)", Severity.LOW if not acac else Severity.HIGH,
            "Access-Control-Allow-Origin: * permite que cualquier sitio lea este recurso (sin cookies).",
            "Restringe a orígenes concretos si el recurso no es público.",
            evidence="Access-Control-Allow-Origin: *", reference=MDN))
    elif acao == "null":
        out.append(Finding(
            "cors.null_origin", "CORS permite el origen 'null'", Severity.MEDIUM,
            "El origen 'null' puede ser forzado desde iframes sandbox o documentos locales.",
            "No incluyas 'null' en la lista blanca de orígenes.", evidence="Access-Control-Allow-Origin: null",
            reference=MDN))
    return out
