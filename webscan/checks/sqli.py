"""Prueba ACTIVA de inyección SQL. Requiere --active (opt-in explícito).

Solo detección, nunca explotación: no hay payloads destructivos (sin DROP/DELETE/UPDATE,
sin subconsultas apiladas). Dos técnicas, ambas de solo lectura desde el punto de vista de
la base de datos objetivo:

1. Basada en error: se envía una comilla suelta y se busca una firma de error de motor SQL
   en la respuesta que no estaba en la respuesta base.
2. Basada en booleano: se compara la respuesta a una condición verdadera (`' OR '1'='1`)
   frente a una falsa (`' AND '1'='2`); si la "verdadera" se parece a la original y la
   "falsa" cambia, el parámetro probablemente llega sin sanear a una cláusula SQL.

No se usan técnicas basadas en tiempo (SLEEP/pg_sleep): evitan ralentizar o cargar el
servidor objetivo, a costa de no detectar inyecciones ciegas puras. Ver README.
"""
from __future__ import annotations

import re

from ..discovery import build_url, discover_params
from ..models import Finding, Severity
from . import Context, register

MAX_PARAMS = 6
OWASP = "https://owasp.org/www-community/attacks/SQL_Injection"

ERROR_SIGNATURES = [
    ("MySQL/MariaDB", re.compile(r"you have an error in your sql syntax|warning:\s*mysqli?_", re.I)),
    ("PostgreSQL", re.compile(r"pg_query\(\)|PG::SyntaxError|syntax error at or near", re.I)),
    ("MSSQL", re.compile(r"unclosed quotation mark|microsoft ole db provider for sql server|80040e14", re.I)),
    ("SQLite", re.compile(r"sqlite3\.OperationalError|unrecognized token|near \".*\": syntax error", re.I)),
    ("Oracle", re.compile(r"ORA-\d{5}")),
    ("Genérico", re.compile(r"sql syntax.*?error|sqlstate\[|unclosed quotation", re.I)),
]


def _error_engine(text: str) -> str | None:
    for label, pattern in ERROR_SIGNATURES:
        if pattern.search(text):
            return label
    return None


def _similar_length(a: str, b: str, tolerance: float = 0.05) -> bool:
    if a == b:
        return True
    if not a and not b:
        return True
    longest = max(len(a), len(b), 1)
    return abs(len(a) - len(b)) / longest <= tolerance


@register("sqli", active=True)
def check_sqli(ctx: Context) -> list[Finding]:
    if not ctx.main:
        return []
    params = discover_params(ctx.final_url, ctx.main.text, max_params=MAX_PARAMS)
    out: list[Finding] = []

    for p in params:
        # Línea base con el valor ORIGINAL del parámetro (no quitarlo): si no, cualquier
        # sitio que cambie de contenido al faltar el parámetro daría falsos positivos.
        base_url = build_url(p.base_url, {**p.other_params, p.name: p.original_value})
        baseline = ctx.client.get_quiet(base_url)
        if baseline is None:
            continue
        baseline_engine = _error_engine(baseline.text)

        # --- Basada en error ---
        err_resp = ctx.client.get_quiet(build_url(p.base_url, {**p.other_params, p.name: "wsqli'\""}))
        if err_resp is not None:
            engine = _error_engine(err_resp.text)
            if engine and engine != baseline_engine:
                out.append(Finding(
                    "active.sqli_error", f"Posible inyección SQL (basada en error) en '{p.name}'",
                    Severity.CRITICAL,
                    f"Al enviar una comilla en el parámetro, la respuesta muestra un mensaje de error "
                    f"característico de {engine} que no aparece en la respuesta normal. Es indicio de que "
                    "el valor llega sin sanear a una consulta SQL.",
                    "Usa siempre consultas parametrizadas o un ORM con bind parameters; nunca concatenes "
                    "entrada de usuario en SQL. No muestres errores de base de datos al usuario final.",
                    evidence=f"GET {p.base_url}  ?{p.name}=wsqli'\"  -> firma de error de {engine}",
                    reference=OWASP))
                continue  # ya confirmado por error; no hace falta el sondeo booleano

        # --- Basada en booleano ---
        orig = p.original_value or "1"
        true_resp = ctx.client.get_quiet(
            build_url(p.base_url, {**p.other_params, p.name: f"{orig}' OR '1'='1"}))
        false_resp = ctx.client.get_quiet(
            build_url(p.base_url, {**p.other_params, p.name: f"{orig}' AND '1'='2"}))
        if true_resp and false_resp:
            true_like_base = (true_resp.status == baseline.status
                               and _similar_length(baseline.text, true_resp.text))
            false_differs = (false_resp.status != baseline.status
                              or not _similar_length(baseline.text, false_resp.text))
            if true_like_base and false_differs:
                out.append(Finding(
                    "active.sqli_boolean", f"Posible inyección SQL (basada en booleano) en '{p.name}'",
                    Severity.CRITICAL,
                    "La condición verdadera (OR '1'='1') produce una respuesta equivalente a la original, "
                    "mientras que la condición falsa (AND '1'='2') cambia el contenido o el código de "
                    "estado: la consulta parece evaluar la entrada como código SQL, no como dato.",
                    "Usa consultas parametrizadas / prepared statements en lugar de concatenar entrada.",
                    evidence=(f"GET {p.base_url}  ?{p.name}=...OR '1'='1 (≈original, {true_resp.status}) "
                               f"vs ...AND '1'='2 ({false_resp.status}, distinto)"),
                    reference=OWASP))
    return out
