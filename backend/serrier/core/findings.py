"""Det centrala Finding-schemat — spinen allt flödar genom.

Kärnprincip (ARCHITECTURE.md): severity, confidence och status är TRE SKILDA fält.
Severity = hur illa OM det är verkligt. Confidence = ÄR det verkligt? Status = var i
åtgärdsflödet. De blandas aldrig ihop till en AI-gissad siffra. Risk-poängen härleds
deterministiskt ur en dokumenterad formel, inte ur en modell.

Hemligheter lagras ALDRIG i klartext: Evidence bär redaktad text + en hash.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field, computed_field


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Confidence(StrEnum):
    heuristic = "heuristic"      # ett mönster matchade — kan vara falskt positivt
    probable = "probable"        # starkt indicium
    confirmed = "confirmed"      # deterministiskt bekräftat


class Status(StrEnum):
    detected = "detected"
    investigating = "investigating"
    remediation_proposed = "remediation_proposed"
    remediation_approved = "remediation_approved"
    remediated = "remediated"
    verified = "verified"
    accepted_risk = "accepted_risk"


class Category(StrEnum):
    secret = "secret"  # noqa: S105 — enum-värde, inte ett lösenord
    dependency = "dependency"
    config = "config"
    authz = "authz"
    injection = "injection"
    info = "info"


def redact(text: str, synligt: int = 4) -> str:
    """Maska mitten; behåll en liten svans för igenkänning. En hemlighet får aldrig
    lagras i klartext. 'sk-ant-SECRET' -> 'sk-a…CRET' (eller '***' om för kort)."""
    t = text.strip()
    if len(t) <= synligt * 2:
        return "***"
    return f"{t[:synligt]}…{t[-synligt:]}"


def _hash(text: str) -> str:
    """Hash för dedup/match — aldrig reversibel till klartext."""
    return hashlib.sha256(text.encode()).hexdigest()[:16]


class Evidence(BaseModel):
    source: str                                  # detektor/fil som fann det
    location: str                                # path:line / commit / dependency
    detection_method: str                        # regel/skanner
    confidence: Confidence
    redacted_content: str                        # ALLTID redaktad, aldrig rå hemlighet
    content_hash: str                            # sha256-prefix för dedup/match
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def av(cls, *, source: str, location: str, detection_method: str,
           confidence: Confidence, ra_innehall: str) -> Evidence:
        """Bygg evidens ur RÅTT innehåll och redakta direkt — råtexten lämnar aldrig
        den här metoden."""
        return cls(source=source, location=location, detection_method=detection_method,
                   confidence=confidence, redacted_content=redact(ra_innehall),
                   content_hash=_hash(ra_innehall))


class Finding(BaseModel):
    project_id: str
    category: Category
    detector: str
    severity: Severity
    confidence: Confidence
    asset_ref: str                               # file:line / dep / endpoint
    title: str
    rule: str = ""                               # regel-id (ingår i stabilt id)
    status: Status = Status.detected
    evidence: list[Evidence] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def id(self) -> str:
        """Stabilt, deterministiskt — samma brist ur samma plats får samma id över
        skanningar (grunden för dedup och historik)."""
        return _hash(f"{self.detector}|{self.category.value}|{self.asset_ref}|{self.rule}")
