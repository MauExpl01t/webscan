"""Interfaz web mínima. Bloquea siempre redes privadas (anti-SSRF) y limita la tasa por IP."""
from __future__ import annotations

import os
import secrets
import time
from collections import defaultdict, deque
from html import escape

from flask import Flask, Response, abort, request, session

from ..report import to_html, to_json
from ..safety import UnsafeTargetError
from ..scanner import scan

RATE_LIMIT = 5  # escaneos
RATE_WINDOW = 300  # segundos

PAGE = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>WebScan</title>
<style>body{{font-family:system-ui,sans-serif;max-width:640px;margin:3rem auto;padding:0 1rem}}
input[type=text]{{width:100%;padding:.6rem;font-size:1rem;box-sizing:border-box}}
button{{padding:.6rem 1.2rem;font-size:1rem;margin-top:.8rem;cursor:pointer}}
.err{{background:#fee2e2;color:#7f1d1d;padding:.6rem;border-radius:6px}}
.note{{color:#475569;font-size:.9rem}}</style></head><body>
<h1>WebScan</h1><p>Diagnóstico pasivo de seguridad web.</p>{error}
<form method="post" action="/scan">
<input type="hidden" name="csrf" value="{csrf}">
<label>URL a analizar<input type="text" name="url" placeholder="https://ejemplo.cl" required></label>
<p><label><input type="checkbox" name="auth" value="1" required>
Declaro que soy responsable de este sitio o tengo autorización escrita para analizarlo.</label></p>
<button type="submit">Analizar</button></form>
<p class="note">Esta interfaz solo hace diagnóstico pasivo (sin payloads). Se bloquean destinos en redes
internas. Las pruebas activas (XSS/SQLi/open redirect) solo están disponibles por línea de
comandos, con confirmación explícita adicional.</p>
</body></html>"""


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("WEBSCAN_SECRET_KEY") or secrets.token_hex(32)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    hits: dict[str, deque] = defaultdict(deque)

    @app.after_request
    def secure(resp: Response):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
        return resp

    def form(error: str = "") -> str:
        session.setdefault("csrf", secrets.token_hex(16))
        err = f'<p class="err">{escape(error)}</p>' if error else ""
        return PAGE.format(csrf=session["csrf"], error=err)

    @app.get("/")
    def index():
        return form()

    @app.post("/scan")
    def run_scan():
        if not secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")):
            abort(400, "Token CSRF inválido.")
        if request.form.get("auth") != "1":
            return form("Debes confirmar que tienes autorización."), 400
        ip = request.remote_addr or "?"
        now = time.time()
        q = hits[ip]
        while q and now - q[0] > RATE_WINDOW:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            return form("Demasiados análisis. Intenta de nuevo en unos minutos."), 429
        q.append(now)
        try:
            # active=False siempre: la web es pública y un checkbox no es autorización real
            # para lanzar payloads (XSS/SQLi/open redirect) contra un tercero. Las pruebas
            # activas solo están disponibles por CLI, con --active --i-accept-active-risk.
            result = scan(request.form.get("url", ""), allow_private=False, active=False)
        except UnsafeTargetError as exc:
            return form(str(exc)), 400
        if request.args.get("format") == "json":
            return Response(to_json(result), mimetype="application/json")
        return Response(to_html(result), mimetype="text/html")

    return app
