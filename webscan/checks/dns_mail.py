"""Higiene de DNS y correo del dominio (SPF, DMARC, CAA). Solo consultas DNS públicas."""
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

import dns.exception
import dns.resolver

from ..models import Finding, Severity
from . import Context, register


def _txt(name: str) -> list[str]:
    try:
        ans = dns.resolver.resolve(name, "TXT", lifetime=5.0)
    except (dns.exception.DNSException, OSError):
        return []
    return ["".join(s.decode() for s in r.strings) for r in ans]


def _registrable(host: str) -> str:
    """Aproximación simple al dominio base (sin lista de sufijos públicos)."""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("com", "co", "org", "gov", "net", "edu") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


@register("dns")
def check_dns_mail(ctx: Context) -> list[Finding]:
    host = urlparse(ctx.url).hostname or ""
    try:
        ipaddress.ip_address(host)
        return []  # IP literal: no aplica
    except ValueError:
        pass
    if host == "localhost" or "." not in host:
        return []
    domain = _registrable(host)
    out: list[Finding] = []

    spf = [t for t in _txt(domain) if t.lower().startswith("v=spf1")]
    if not spf:
        out.append(Finding(
            "dns.spf_missing", f"Sin registro SPF en {domain}", Severity.LOW,
            "Sin SPF, es más fácil suplantar correos que aparentan venir de este dominio.",
            "Publica un TXT SPF, p. ej. \"v=spf1 include:<tu-proveedor> -all\"."))
    else:
        rec = spf[0].lower()
        if rec.rstrip().endswith("+all") or rec.rstrip().endswith(" all") and "-all" not in rec and "~all" not in rec:
            out.append(Finding("dns.spf_permissive", "SPF permisivo (+all)", Severity.MEDIUM,
                               "El registro SPF autoriza a cualquier servidor a enviar correo por el dominio.",
                               "Termina el registro con -all (o ~all en transición).", evidence=spf[0]))
        elif "?all" in rec:
            out.append(Finding("dns.spf_neutral", "SPF neutral (?all)", Severity.LOW,
                               "?all no define política efectiva.", "Usa -all o ~all.", evidence=spf[0]))

    dmarc = [t for t in _txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        out.append(Finding(
            "dns.dmarc_missing", f"Sin registro DMARC en {domain}", Severity.LOW,
            "Sin DMARC no hay política contra suplantación de correo ni reportes de abuso.",
            "Publica _dmarc con p=quarantine o p=reject y una dirección rua para reportes."))
    elif "p=none" in dmarc[0].lower().replace(" ", ""):
        out.append(Finding("dns.dmarc_none", "DMARC en modo monitoreo (p=none)", Severity.INFO,
                           "La política no bloquea correos falsificados.",
                           "Cuando los reportes estén limpios, pasa a p=quarantine o p=reject.", evidence=dmarc[0]))

    try:
        dns.resolver.resolve(domain, "CAA", lifetime=5.0)
    except dns.resolver.NoAnswer:
        out.append(Finding("dns.caa_missing", "Sin registros CAA", Severity.INFO,
                           "CAA limita qué autoridades pueden emitir certificados para el dominio.",
                           "Agrega registros CAA con tu CA preferida."))
    except (dns.exception.DNSException, OSError):
        pass
    return out
