"""Registro de chequeos. Cada chequeo es una función run(ctx) -> list[Finding]."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..http_client import Fetched, HttpClient
from ..models import Finding


@dataclass
class Context:
    """Estado compartido entre chequeos (evita repetir peticiones)."""

    url: str  # URL normalizada solicitada
    client: HttpClient
    main: Fetched | None = None  # respuesta principal (tras redirecciones)
    extra: dict = field(default_factory=dict)

    @property
    def final_url(self) -> str:
        return self.main.url if self.main else self.url


CheckFn = Callable[[Context], list[Finding]]
REGISTRY: dict[str, CheckFn] = {}
ACTIVE: set[str] = set()  # nombres de chequeos que envían payloads (requieren opt-in --active)


def register(name: str, active: bool = False):
    """Registra un chequeo. active=True marca un chequeo intrusivo (XSS, SQLi, etc.):
    solo se ejecuta si scan()/CLI recibe active=True explícitamente."""

    def deco(fn: CheckFn) -> CheckFn:
        REGISTRY[name] = fn
        if active:
            ACTIVE.add(name)
        return fn

    return deco


def load_all() -> dict[str, CheckFn]:
    # Importar los módulos registra los chequeos.
    from . import headers, cookies, cors, content, tls, dns_mail, exposure  # noqa: F401
    from . import xss, sqli, open_redirect, cmd_injection, ssti  # noqa: F401  (activos, opt-in)

    return REGISTRY
