"""Servidor HTTP local deliberadamente mal configurado, para probar los chequeos."""
from __future__ import annotations

import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

INDEX = b"""<html><head><title>Demo</title>
<meta name="generator" content="DemoCMS 1.2.3">
<script src="https://cdn.example.com/lib.js"></script></head>
<body><!-- TODO: quitar password admin -->
<form method="get" action="/login"><input type="password" name="p"></form>
<a href="/search?q=hola">buscar</a>
<a href="/product?id=1">producto</a>
<a href="/go?next=/gracias">continuar</a>
<a href="/ping?host=127.0.0.1">ping</a>
<a href="/greet?name=mundo">saludo</a>
</body></html>"""

_SLEEP_RX = re.compile(r"sleep\s+(\d+(?:\.\d+)?)")
_PING_RX = re.compile(r"ping -n (\d+)")
_TEMPLATE_RXS = [
    re.compile(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}"),
    re.compile(r"<%=\s*(\d+)\s*\*\s*(\d+)\s*%>"),
    re.compile(r"\$\{\s*(\d+)\s*\*\s*(\d+)\s*\}"),
]


def _run_as_shell(value: str) -> None:
    """Simula que `value` se concatenó a un comando de shell: si trae sleep/ping, se demora."""
    m = _SLEEP_RX.search(value)
    if m:
        time.sleep(min(float(m.group(1)), 6.0))
        return
    m = _PING_RX.search(value)
    if m:
        time.sleep(min(max(int(m.group(1)) - 1, 0), 6.0))


def _render_template(value: str) -> str:
    """Simula un motor de plantillas vulnerable: evalúa {{a*b}}/<%=a*b%>/${a*b} si aparece."""
    for rx in _TEMPLATE_RXS:
        m = rx.search(value)
        if m:
            return rx.sub(str(int(m.group(1)) * int(m.group(2))), value)
    return value


class VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silencio
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path, params = parsed.path, parse_qs(parsed.query)

        if path == "/.env":
            body, ctype = b"DB_PASSWORD=supersecreto\nAPI_KEY=abc\n", "text/plain"
        elif path == "/.git/HEAD":
            body, ctype = b"ref: refs/heads/main\n", "text/plain"
        elif path == "/":
            body, ctype = INDEX, "text/html"
        elif path == "/search":
            # Reflejado sin escapar a propósito: vulnerable a XSS reflejado.
            q = params.get("q", [""])[0]
            body = f"<html><body>Resultados para: {q}</body></html>".encode()
            ctype = "text/html"
        elif path == "/product":
            # Simula una consulta SQL concatenada a propósito (sin BD real detrás).
            pid = params.get("id", ["1"])[0]
            if pid.endswith("OR '1'='1"):
                body = b"<html><body>Producto: Widget (id=1)</body></html>"  # = respuesta con id=1
            elif pid.endswith("AND '1'='2"):
                body = b"<html><body>Sin resultados.</body></html>"
            elif "'" in pid:
                body = b"<html><body>Error: You have an error in your SQL syntax near " \
                       b"'" + pid.split("'", 1)[1].encode(errors="replace")[:20] + b"'</body></html>"
            else:
                body = f"<html><body>Producto: Widget (id={pid})</body></html>".encode()
            ctype = "text/html"
        elif path == "/go":
            # Redirección abierta a propósito: no valida el destino.
            target = params.get("next", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        elif path == "/ping":
            # Simula pasar `host` directo a un shell (os.system/subprocess shell=True).
            host = params.get("host", ["127.0.0.1"])[0]
            _run_as_shell(host)
            body = f"<html><body>ping host={host}</body></html>".encode()
            ctype = "text/html"
        elif path == "/greet":
            # Simula un motor de plantillas que renderiza la entrada del usuario como código.
            name = params.get("name", [""])[0]
            body = f"<html><body>Hola, {_render_template(name)}</body></html>".encode()
            ctype = "text/html"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Server", "Apache/2.4.49")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.send_header("Set-Cookie", "sessionid=abc123; Path=/")
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="session")
def vuln_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), VulnHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
