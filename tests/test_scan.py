import pytest

from webscan.safety import UnsafeTargetError, is_public_ip, normalize_target, validate_target
from webscan.scanner import scan
from webscan.models import Severity
from webscan.report import to_html, to_json


# ---------- safety ----------
@pytest.mark.parametrize("ip,expected", [("8.8.8.8", True), ("127.0.0.1", False), ("10.1.2.3", False),
                                         ("169.254.169.254", False), ("192.168.0.1", False), ("::1", False)])
def test_is_public_ip(ip, expected):
    assert is_public_ip(ip) is expected


def test_blocks_private_by_default(vuln_server):
    with pytest.raises(UnsafeTargetError):
        validate_target(vuln_server)
    assert validate_target(vuln_server, allow_private=True)


@pytest.mark.parametrize("bad", ["", "ftp://x.com", "file:///etc/passwd", "https://user:pw@x.com"])
def test_rejects_bad_schemes(bad):
    with pytest.raises(UnsafeTargetError):
        normalize_target(bad)


def test_adds_https_scheme():
    assert normalize_target("example.com") == "https://example.com"


# ---------- escaneo contra servidor vulnerable ----------
@pytest.fixture(scope="module")
def result(vuln_server):
    return scan(vuln_server, allow_private=True, skip=["dns", "tls", "transport"])


def ids(result):
    return {f.check for f in result.findings}


def test_header_findings(result):
    got = ids(result)
    assert {"headers.csp", "headers.clickjacking", "headers.nosniff", "headers.referrer"} <= got
    assert "headers.disclosure.server" in got and "headers.disclosure.x-powered-by" in got


def test_cookie_findings(result):
    got = ids(result)
    assert {"cookies.httponly", "cookies.samesite"} <= got  # sin Secure no aplica: es http


def test_cors_reflection_is_high(result):
    f = next(f for f in result.findings if f.check == "cors.reflected_origin")
    assert f.severity == Severity.HIGH


def test_exposure_findings(result):
    got = ids(result)
    assert "exposure.env" in got and "exposure.git_HEAD" in got
    env = next(f for f in result.findings if f.check == "exposure.env")
    assert env.severity == Severity.CRITICAL
    assert "supersecreto" not in env.evidence  # nunca se vuelca el contenido


def test_content_findings(result):
    got = ids(result)
    assert {"content.form_get", "content.form_http", "content.comments", "content.generator", "content.sri"} <= got


def test_score_and_reports(result):
    assert 0 <= result.score() < 50
    assert "exposure.env" in to_json(result)
    html = to_html(result)
    assert "<script" not in html.lower()  # el reporte no ejecuta JS
    assert "Archivo .env expuesto" in html


def test_html_report_escapes_evidence():
    from webscan.models import Finding, ScanResult
    r = ScanResult(target="http://x", started_at="now")
    r.findings.append(Finding("t", "<img src=x onerror=alert(1)>", Severity.LOW, "d", evidence="<script>alert(1)</script>"))
    html = to_html(r)
    assert "<img src=x" not in html and "<script>alert" not in html


def test_unreachable_target_reports_error():
    r = scan("http://127.0.0.1:1", allow_private=True, only=["headers"])
    assert r.errors


# ---------- chequeos activos (opt-in) ----------
def test_active_checks_disabled_by_default(result):
    """El escaneo normal (sin active=True) nunca debe lanzar payloads."""
    got = ids(result)
    assert not any(c.startswith("active.") for c in got)
    for name in ("xss_reflected", "sqli", "open_redirect", "cmd_injection", "ssti"):
        assert name not in result.checks_run


@pytest.fixture(scope="module")
def active_result(vuln_server):
    return scan(vuln_server, allow_private=True, active=True, skip=["dns", "tls", "transport"])


def test_active_checks_run_when_opted_in(active_result):
    assert {"xss_reflected", "sqli", "open_redirect", "cmd_injection", "ssti"} <= set(active_result.checks_run)


def test_xss_reflected_detected(active_result):
    f = next(f for f in active_result.findings if f.check == "active.xss_reflected")
    assert f.severity == Severity.HIGH
    assert "q" in f.title


def test_sqli_error_based_detected(active_result):
    f = next(f for f in active_result.findings if f.check == "active.sqli_error")
    assert f.severity == Severity.CRITICAL
    assert "id" in f.title


def test_open_redirect_detected(active_result):
    f = next(f for f in active_result.findings if f.check == "active.open_redirect")
    assert f.severity == Severity.MEDIUM
    assert "next" in f.title


def test_ssti_detected(active_result):
    f = next(f for f in active_result.findings if f.check == "active.ssti")
    assert f.severity == Severity.CRITICAL
    assert "name" in f.title
    assert "Jinja2/Twig" in f.title


def test_cmd_injection_detected(active_result):
    # Tarda ~8s: el parámetro host sí es vulnerable, así que el chequeo confirma con timing real.
    f = next(f for f in active_result.findings if f.check == "active.cmd_injection")
    assert f.severity == Severity.CRITICAL
    assert "host" in f.title


def test_active_findings_absent_from_passive_scan(result):
    """Mismo servidor, mismo caché de fixture: el escaneo pasivo no debe reutilizar hallazgos activos."""
    assert ids(result).isdisjoint({
        "active.xss_reflected", "active.sqli_error", "active.open_redirect",
        "active.cmd_injection", "active.ssti"})


def test_cli_requires_explicit_ack_for_active(capsys):
    from webscan.cli import main
    assert main(["scan", "http://127.0.0.1:1", "--i-have-authorization", "--active"]) == 1
    assert "i-accept-active-risk" in capsys.readouterr().err
