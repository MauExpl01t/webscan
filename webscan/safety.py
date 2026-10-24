"""Guardas de seguridad de la propia herramienta.

Una herramienta que hace peticiones a URLs arbitrarias es un vector de SSRF si se
expone como servicio web. Este módulo valida los destinos antes de conectar.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class UnsafeTargetError(ValueError):
    """El destino no está permitido por la política de la herramienta."""


def normalize_target(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise UnsafeTargetError("URL vacía.")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeTargetError("Solo se permiten esquemas http y https.")
    if not parsed.hostname:
        raise UnsafeTargetError("URL sin host válido.")
    if parsed.username or parsed.password:
        raise UnsafeTargetError("No se permiten credenciales dentro de la URL.")
    return raw


def resolve_host(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeTargetError(f"No se pudo resolver el host '{host}': {exc}") from exc
    return sorted({i[4][0] for i in infos})


def is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip.split("%")[0])
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or getattr(addr, "is_site_local", False)
    )


def validate_target(url: str, allow_private: bool = False) -> str:
    """Valida el destino. Con allow_private=False bloquea redes internas (anti-SSRF)."""
    url = normalize_target(url)
    host = urlparse(url).hostname
    ips = resolve_host(host)
    if not allow_private:
        bad = [ip for ip in ips if not is_public_ip(ip)]
        if bad:
            raise UnsafeTargetError(
                f"El host resuelve a direcciones no públicas ({', '.join(bad)}). "
                "Usa --allow-private (CLI) solo para sistemas propios en redes internas."
            )
    return url
