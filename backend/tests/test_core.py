"""Finding-schemat + risk-modellen. All data syntetisk."""

from serrier.core.findings import (
    Category,
    Confidence,
    Evidence,
    Finding,
    Severity,
    Status,
    redact,
)
from serrier.core.risk import risk_score

RA_HEMLIGHET = "sk-ant-api03-SUPERSECRETKEY1234567890"


def _finding(**kw) -> Finding:
    bas = {"project_id": "p1", "category": Category.secret, "detector": "builtin",
           "severity": Severity.critical, "confidence": Confidence.confirmed,
           "asset_ref": ".env:3", "title": "Anthropic API-nyckel", "rule": "anthropic-key"}
    return Finding(**{**bas, **kw})


# --- redaktion & evidens: hemligheten lagras aldrig i klartext ---

def test_redact_maskar_mitten() -> None:
    assert redact(RA_HEMLIGHET) == "sk-a…7890"
    assert redact("kort") == "***"


def test_evidens_lagrar_aldrig_ra_hemlighet() -> None:
    e = Evidence.av(source="builtin", location=".env:3", detection_method="anthropic-key",
                    confidence=Confidence.confirmed, ra_innehall=RA_HEMLIGHET)
    assert RA_HEMLIGHET not in e.redacted_content          # rå hemlighet aldrig lagrad
    assert RA_HEMLIGHET not in e.content_hash
    assert e.redacted_content == "sk-a…7890"
    assert len(e.content_hash) == 16


# --- stabilt id: dedup-grunden ---

def test_stabilt_id_ar_deterministiskt() -> None:
    assert _finding().id == _finding().id                  # samma brist → samma id
    assert _finding(asset_ref=".env:9").id != _finding().id   # annan plats → annat id


# --- tre skilda fält ---

def test_severity_confidence_status_ar_separata() -> None:
    f = _finding(severity=Severity.critical, confidence=Confidence.heuristic)
    assert f.severity == Severity.critical                 # illa OM verkligt
    assert f.confidence == Confidence.heuristic            # men osäkert om verkligt
    assert f.status == Status.detected                     # default-status, oberoende


# --- risk-modellen: transparent, deterministisk ---

def test_risk_severity_driver_confidence_rabatterar() -> None:
    hog = risk_score(_finding(severity=Severity.critical, confidence=Confidence.confirmed))
    osaker = risk_score(_finding(severity=Severity.critical, confidence=Confidence.heuristic))
    lag = risk_score(_finding(severity=Severity.low, confidence=Confidence.confirmed))
    assert hog == 100
    assert osaker < hog                                    # confidence rabatterar
    assert lag < hog                                       # severity driver
    assert 0 <= osaker <= 100


def test_atgardad_risk_ar_noll() -> None:
    assert risk_score(_finding(status=Status.remediated)) == 0
    assert risk_score(_finding(status=Status.verified)) == 0
    assert risk_score(_finding(status=Status.accepted_risk)) == 0
