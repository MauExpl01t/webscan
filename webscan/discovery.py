"""Descubrimiento de parámetros GET para las pruebas activas.

Solo mira lo que ya trajo la petición principal (query string propia, enlaces <a> y
formularios de la página de inicio): no rastrea otras páginas ni hace fuerza bruta de rutas.
Los formularios POST se descartan a propósito, porque enviarlos podría tener efectos reales
(login, compras, borrados, envío de correo) y esta herramienta nunca debe causar esos efectos.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

SKIP_INPUT_TYPES = {"submit", "button", "image", "file", "password", "hidden"}


@dataclass(frozen=True)
class Param:
    """Un parámetro GET candidato a probar, con el resto de parámetros de su URL intactos."""

    base_url: str          # URL sin query string
    name: str               # parámetro que se va a variar
    other_params: dict      # resto de parámetros de esa misma URL, con su valor original
    original_value: str = ""


def build_url(base_url: str, params: dict) -> str:
    return base_url + ("?" + urlencode(params) if params else "")


def _split(url: str) -> tuple[str, dict]:
    parts = urlsplit(url)
    base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    return base, dict(parse_qsl(parts.query, keep_blank_values=True))


def discover_params(main_url: str, html: str, max_params: int = 6) -> list[Param]:
    origin = urlsplit(main_url)
    same_origin = (origin.scheme, origin.netloc)
    found: dict[tuple, Param] = {}

    def add_query(base: str, q: dict) -> None:
        for name, value in q.items():
            key = (base, name)
            if key in found or len(found) >= max_params:
                continue
            others = {k: v for k, v in q.items() if k != name}
            found[key] = Param(base_url=base, name=name, other_params=others, original_value=value)

    base, q = _split(main_url)
    if q:
        add_query(base, q)

    soup = BeautifulSoup(html, "html.parser")

    for a in soup.find_all("a", href=True):
        if len(found) >= max_params:
            break
        abs_url = urljoin(main_url, a["href"])
        parts = urlsplit(abs_url)
        if (parts.scheme, parts.netloc) != same_origin or not parts.query:
            continue
        b, qq = _split(abs_url)
        add_query(b, qq)

    for form in soup.find_all("form"):
        if len(found) >= max_params:
            break
        method = (form.get("method") or "get").strip().lower()
        if method != "get":
            continue  # los POST se omiten: ver docstring del módulo
        action = urljoin(main_url, form.get("action") or main_url)
        parts = urlsplit(action)
        if (parts.scheme, parts.netloc) != same_origin:
            continue
        q = {}
        for inp in form.find_all(["input", "select", "textarea"]):
            name = inp.get("name")
            if not name or (inp.get("type") or "").lower() in SKIP_INPUT_TYPES:
                continue
            q[name] = inp.get("value") or "1"
        if q:
            b = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
            add_query(b, q)

    return list(found.values())[:max_params]
