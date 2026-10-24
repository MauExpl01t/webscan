"""Certificado y protocolos TLS (solo handshakes, sin explotación)."""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..models import Finding, Severity
from . import Context, register

DOC = "https://wiki.mozilla.org/Security/Server_Side_TLS"


def _handshake(host: str, port: int, version: ssl.TLSVersion | None, verify: bool, timeout: float = 8.0):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = verify
    ctx.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
    if verify:
        ctx.load_default_certs()
    if version is not None:
        ctx.minimum_version = version
        ctx.maximum_version = version
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            return s.version(), s.cipher(), s.getpeercert() if verify else s.getpeercert(binary_form=False)


@register("tls")
def check_tls(ctx: Context) -> list[Finding]:
    parsed = urlparse(ctx.url)
    if parsed.scheme != "https":
        return []
    host, port = parsed.hostname, parsed.port or 443
    out: list[Finding] = []

    # 1) Validación del certificado
    try:
        version, cipher, cert = _handshake(host, port, None, verify=True)
    except ssl.SSLCertVerificationError as exc:
        out.append(Finding(
            "tls.cert_invalid", "Certificado TLS no válido", Severity.HIGH,
            f"El certificado no pasa la validación: {exc.verify_message}.",
            "Instala un certificado válido emitido por una CA de confianza que cubra el dominio.",
            evidence=str(exc.verify_message)))
        return out
    except (OSError, ssl.SSLError) as exc:
        ctx.extra["tls_error"] = str(exc)
        out.append(Finding("tls.unreachable", "No se pudo completar el handshake TLS", Severity.INFO,
                           f"Error al negociar TLS: {exc}", "Verifica que el puerto 443 sirva TLS correctamente."))
        return out

    # 2) Vencimiento
    if cert and "notAfter" in cert:
        exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
        days = (exp - datetime.now(timezone.utc)).days
        if days < 0:
            out.append(Finding("tls.expired", "Certificado TLS vencido", Severity.HIGH,
                               f"Venció el {exp:%Y-%m-%d}.", "Renueva el certificado."))
        elif days < 15:
            out.append(Finding("tls.expiring", "Certificado TLS próximo a vencer", Severity.MEDIUM,
                               f"Vence en {days} días ({exp:%Y-%m-%d}).", "Renueva o automatiza la renovación (ACME).",
                               reference=DOC))
        elif days < 30:
            out.append(Finding("tls.expiring_soon", "Certificado TLS vence en menos de 30 días", Severity.LOW,
                               f"Vence en {days} días ({exp:%Y-%m-%d}).", "Programa la renovación.", reference=DOC))

    # 3) Protocolos obsoletos aún aceptados (solo se intenta negociar)
    for label, ver in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            _handshake(host, port, ver, verify=False, timeout=5.0)
        except (OSError, ssl.SSLError, ValueError):
            continue  # rechazado (lo esperado) o no soportado por la librería local
        out.append(Finding(
            f"tls.legacy_{label[-3:].replace('.', '')}", f"El servidor acepta {label}", Severity.MEDIUM,
            f"{label} está obsoleto (RFC 8996) y tiene debilidades conocidas.",
            "Deshabilita TLS 1.0/1.1 y deja solo TLS 1.2 y 1.3.", reference=DOC))

    # 4) Soporte de TLS 1.3 (informativo) y cifrados débiles negociados
    if version and version != "TLSv1.3":
        out.append(Finding("tls.no_tls13", "TLS 1.3 no negociado", Severity.INFO,
                           f"La conexión usó {version}.", "Habilita TLS 1.3 si tu servidor lo permite.", reference=DOC))
    if cipher and any(w in cipher[0].upper() for w in ("RC4", "3DES", "NULL", "EXPORT", "CBC-SHA")):
        out.append(Finding("tls.weak_cipher", "Suite de cifrado débil negociada", Severity.MEDIUM,
                           f"Se negoció {cipher[0]}.", "Prioriza suites AEAD (AES-GCM, ChaCha20-Poly1305).",
                           evidence=cipher[0], reference=DOC))
    return out
