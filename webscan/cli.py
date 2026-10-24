"""Interfaz de línea de comandos: webscan scan <url> | webscan serve"""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .checks import ACTIVE, load_all
from .models import Severity
from .report import to_html, to_json, to_text
from .safety import UnsafeTargetError
from .scanner import scan

LEGAL = ("AVISO: analiza únicamente sistemas propios o con autorización escrita del responsable. "
         "El uso sin autorización puede ser delito.")
ACTIVE_WARNING = (
    "AVISO: --active envía payloads reales (XSS, SQLi, open redirect, inyección de comandos, "
    "SSTI) al objetivo. Esto es intrusivo: puede activar WAF/IDS, aparecer en logs de seguridad "
    "o alertas del equipo responsable, y en sitios mal hechos alterar datos. El chequeo de "
    "comandos además demora varios segundos por parámetro cuando encuentra algo. Úsalo solo "
    "contra sistemas propios o con autorización escrita que cubra explícitamente pruebas activas.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="webscan", description="Diagnóstico pasivo de seguridad web. " + LEGAL)
    p.add_argument("--version", action="version", version=f"webscan {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Analiza una URL")
    s.add_argument("url")
    s.add_argument("--i-have-authorization", action="store_true", required=True,
                   help="Confirma que tienes autorización para analizar este objetivo (obligatorio)")
    s.add_argument("--format", choices=["text", "json", "html"], default="text")
    s.add_argument("-o", "--output", help="Archivo de salida (por defecto stdout)")
    s.add_argument("--only", help="Chequeos a ejecutar, separados por coma")
    s.add_argument("--skip", help="Chequeos a omitir, separados por coma")
    s.add_argument("--allow-private", action="store_true", help="Permite objetivos en redes privadas/localhost")
    s.add_argument("--timeout", type=float, default=10.0)
    s.add_argument("--fail-on", choices=[x.name.lower() for x in Severity], default=None,
                   help="Código de salida 2 si hay hallazgos >= severidad (útil en CI/CD)")
    s.add_argument("--no-color", action="store_true")
    s.add_argument("--active", action="store_true",
                   help="Habilita chequeos activos/intrusivos: xss_reflected, sqli, open_redirect, "
                        "cmd_injection, ssti")
    s.add_argument("--i-accept-active-risk", action="store_true",
                   help="Confirma que entiendes el riesgo de --active (obligatorio junto con --active)")

    sub.add_parser("list-checks", help="Lista los chequeos disponibles (marca [activo] los intrusivos)")

    w = sub.add_parser("serve", help="Inicia la interfaz web")
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=5000)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.cmd == "list-checks":
        for name in load_all():
            print(f"{name} [activo]" if name in ACTIVE else name)
        return 0

    if args.cmd == "serve":
        from .web.app import create_app
        create_app().run(host=args.host, port=args.port)
        return 0

    if args.active and not args.i_accept_active_risk:
        print("--active requiere también --i-accept-active-risk (confirmación obligatoria).",
              file=sys.stderr)
        print(ACTIVE_WARNING, file=sys.stderr)
        return 1
    if args.active:
        print(ACTIVE_WARNING, file=sys.stderr)

    split = lambda v: [x.strip() for x in v.split(",") if x.strip()] if v else None  # noqa: E731
    try:
        result = scan(args.url, allow_private=args.allow_private, only=split(args.only),
                      skip=split(args.skip), timeout=args.timeout, active=args.active)
    except UnsafeTargetError as exc:
        print(f"Objetivo rechazado: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        out = to_json(result)
    elif args.format == "html":
        out = to_html(result)
    else:
        out = to_text(result, color=not args.no_color and not args.output and sys.stdout.isatty())
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"Reporte guardado en {args.output}")
    else:
        print(out)

    if args.fail_on:
        threshold = Severity[args.fail_on.upper()]
        if any(f.severity >= threshold for f in result.findings):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
