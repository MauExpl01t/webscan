"""Orquestador: valida el destino, hace la petición principal y ejecuta los chequeos."""
from __future__ import annotations

from datetime import datetime, timezone

import requests

from .checks import ACTIVE, Context, load_all
from .http_client import HttpClient
from .models import ScanResult
from .safety import UnsafeTargetError, validate_target


def scan(target: str, allow_private: bool = False, only: list[str] | None = None,
         skip: list[str] | None = None, timeout: float = 10.0, active: bool = False) -> ScanResult:
    """active=False (por defecto) solo ejecuta chequeos pasivos (GET simples, sin payloads).
    active=True habilita además los chequeos intrusivos (XSS, SQLi, open redirect): deben
    usarse solo contra sistemas propios o con autorización escrita explícita para pruebas
    activas, no solo para el diagnóstico pasivo."""
    registry = load_all()
    url = validate_target(target, allow_private=allow_private)  # lanza UnsafeTargetError
    result = ScanResult(target=url, started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))

    client = HttpClient(allow_private=allow_private, timeout=timeout)
    ctx = Context(url=url, client=client)
    try:
        ctx.main = client.get(url)
    except (requests.RequestException, UnsafeTargetError) as exc:
        result.errors.append(f"No se pudo obtener la página principal: {exc}")

    names = [n for n in registry if (not only or n in only) and not (skip and n in skip)
             and (active or n not in ACTIVE)]
    for name in names:
        try:
            result.findings.extend(registry[name](ctx))
            result.checks_run.append(name)
        except Exception as exc:  # un chequeo roto no debe tumbar el escaneo completo
            result.errors.append(f"Chequeo '{name}' falló: {type(exc).__name__}: {exc}")

    result.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return result
