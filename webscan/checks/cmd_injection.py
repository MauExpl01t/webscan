"""Prueba ACTIVA de inyección de comandos del sistema operativo. Requiere --active.

Solo detección basada en tiempo, con confirmación diferencial para descartar falsos
positivos por ruido de red: se añade un separador de shell seguido de `sleep`/`ping` (nunca
comandos destructivos como borrar archivos, descargar algo o leer datos) y se mide si la
respuesta se demora lo esperado. Si hay indicio, se repite con un retardo distinto (+2s): solo
se confirma el hallazgo si la demora adicional también crece ~2s, lo que descarta que el
sitio sea simplemente lento.

Importante: estas peticiones SÍ tardan varios segundos cuando el objetivo es vulnerable (es
inherente a la técnica). Cuando no lo es, el comando nunca se ejecuta y la respuesta vuelve
rápido, así que el costo en tiempo solo se paga al confirmar un hallazgo real.
"""
from __future__ import annotations

import time

from ..discovery import build_url, discover_params
from ..models import Finding, Severity
from . import Context, register

MAX_PARAMS = 4
DELAY = 3.0                  # segundos de retardo pedido en el primer sondeo
CONFIRM_EXTRA_DELAY = 2.0    # segundos adicionales en el sondeo de confirmación
TIMEOUT_PAD = 5.0            # margen sobre el retardo para el timeout de la petición
OWASP = "https://owasp.org/www-community/attacks/Command_Injection"

# (etiqueta, función que construye el payload para un valor original y un retardo en segundos)
SEPARATORS = [
    ("Unix $(sleep N)", lambda orig, n: f"{orig}$(sleep {n})"),
    ("Unix ;sleep N;", lambda orig, n: f"{orig};sleep {n};"),
    ("Windows &ping&", lambda orig, n: f"{orig}&ping -n {int(n) + 1} 127.0.0.1&"),
]


def _timed(ctx: Context, url: str, timeout: float):
    start = time.monotonic()
    resp = ctx.client.get_quiet(url, timeout=timeout)
    return time.monotonic() - start, resp


@register("cmd_injection", active=True)
def check_cmd_injection(ctx: Context) -> list[Finding]:
    if not ctx.main:
        return []
    params = discover_params(ctx.final_url, ctx.main.text, max_params=MAX_PARAMS)
    out: list[Finding] = []

    for p in params:
        orig = p.original_value or "1"
        base_time, baseline = _timed(ctx, build_url(p.base_url, {**p.other_params, p.name: orig}),
                                      ctx.client.timeout)
        if baseline is None or base_time >= DELAY:
            continue  # ya es lento de por sí: el timing no sería una señal fiable

        for label, build in SEPARATORS:
            url = build_url(p.base_url, {**p.other_params, p.name: build(orig, DELAY)})
            elapsed, resp = _timed(ctx, url, DELAY + TIMEOUT_PAD)
            if resp is None or elapsed < DELAY - 0.3:
                continue  # no hubo demora: este separador no aplica

            confirm_url = build_url(p.base_url, {**p.other_params, p.name: build(orig, DELAY + CONFIRM_EXTRA_DELAY)})
            confirm_elapsed, confirm_resp = _timed(ctx, confirm_url, DELAY + CONFIRM_EXTRA_DELAY + TIMEOUT_PAD)
            if confirm_resp is None or confirm_elapsed - elapsed < CONFIRM_EXTRA_DELAY - 0.5:
                continue  # el retardo no escaló: probablemente ruido de red, no injection

            out.append(Finding(
                "active.cmd_injection", f"Posible inyección de comandos en '{p.name}' ({label})",
                Severity.CRITICAL,
                f"Añadir '{label}' al valor del parámetro demoró la respuesta {elapsed:.1f}s "
                f"(línea base {base_time:.1f}s), y pedir {CONFIRM_EXTRA_DELAY:.0f}s más de retardo "
                f"demoró {confirm_elapsed - elapsed:.1f}s más: la demora escala con lo pedido, lo que "
                "descarta que sea ruido de red y confirma que el parámetro se ejecuta como parte de "
                "un comando del sistema operativo.",
                "Nunca pases entrada de usuario a system()/exec()/subprocess con shell=True. Usa "
                "APIs específicas del lenguaje que no invoquen un shell, y si es imprescindible, "
                "valida la entrada contra una lista blanca estricta.",
                evidence=f"GET {p.base_url}  ?{p.name}=...{label}...  -> {elapsed:.1f}s (base {base_time:.1f}s)",
                reference=OWASP))
            break  # confirmado: no hace falta probar los demás separadores en este parámetro
    return out
