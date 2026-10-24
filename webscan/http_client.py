"""Cliente HTTP con límites: redirecciones validadas manualmente, tamaño y tiempo acotados."""
from __future__ import annotations

from urllib.parse import urljoin, urlparse

import requests

from .safety import UnsafeTargetError, validate_target

USER_AGENT = "WebScan/0.1 (diagnostico-seguridad-autorizado)"
MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MB
MAX_REDIRECTS = 5


class Fetched:
    """Respuesta ya materializada (con cuerpo truncado) y cadena de redirecciones."""

    def __init__(self, response: requests.Response, body: bytes, chain: list[str]):
        self.response = response
        self.status = response.status_code
        self.headers = response.headers
        self.url = response.url
        self.body = body
        self.chain = chain

    @property
    def text(self) -> str:
        enc = self.response.encoding or "utf-8"
        return self.body.decode(enc, errors="replace")


class HttpClient:
    def __init__(self, allow_private: bool = False, timeout: float = 10.0, verify_tls: bool = True):
        self.allow_private = allow_private
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self.requests_made = 0

    def get(self, url: str, headers: dict | None = None, follow_redirects: bool = True,
            timeout: float | None = None) -> Fetched:
        chain: list[str] = []
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            validate_target(current, allow_private=self.allow_private)  # revalida en cada salto
            resp = self.session.get(
                current,
                headers=headers,
                timeout=timeout if timeout is not None else self.timeout,
                allow_redirects=False,
                stream=True,
                verify=self.verify_tls,
            )
            self.requests_made += 1
            body = b""
            try:
                for chunk in resp.iter_content(8192):
                    body += chunk
                    if len(body) >= MAX_BODY_BYTES:
                        break
            finally:
                resp.close()
            chain.append(current)
            if follow_redirects and resp.is_redirect and "location" in resp.headers:
                current = urljoin(current, resp.headers["location"])
                continue
            return Fetched(resp, body, chain)
        raise UnsafeTargetError(f"Demasiadas redirecciones (> {MAX_REDIRECTS}).")

    def get_quiet(self, url: str, **kw) -> Fetched | None:
        try:
            return self.get(url, **kw)
        except (requests.RequestException, UnsafeTargetError):
            return None


def origin_of(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"
