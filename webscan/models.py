"""Modelos de datos compartidos por todos los chequeos."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return {0: "Informativo", 1: "Baja", 2: "Media", 3: "Alta", 4: "Crítica"}[int(self)]


@dataclass
class Finding:
    """Un hallazgo individual."""

    check: str  # id del chequeo, ej: "headers.csp"
    title: str
    severity: Severity
    description: str
    recommendation: str = ""
    evidence: str = ""
    reference: str = ""  # OWASP / CWE / MDN

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["severity_label"] = self.severity.label
        return d


@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str = ""
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-int(f.severity), f.check))

    def summary(self) -> dict[str, int]:
        counts = {s.name: 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            counts[f.severity.name] += 1
        return counts

    def score(self) -> int:
        """Puntaje 0-100 (100 = sin hallazgos relevantes). Heurístico, solo orientativo."""
        weights = {Severity.CRITICAL: 30, Severity.HIGH: 15, Severity.MEDIUM: 7, Severity.LOW: 2, Severity.INFO: 0}
        penalty = sum(weights[f.severity] for f in self.findings)
        return max(0, 100 - penalty)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "score": self.score(),
            "summary": self.summary(),
            "checks_run": self.checks_run,
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
