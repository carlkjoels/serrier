"""Transparent, deterministisk risk-poäng (0–100).

severity × confidence är kärnan; exploitability/exposure/asset_importance/
data_sensitivity/existing_mitigations är multiplikatorer (default 1.0 = neutral tills
de har riktiga källor). Formeln är inspekterbar per finding och dokumenterad — den är
ALDRIG en AI-gissad siffra. AI:n får förklara poängen, aldrig sätta den.
"""

from __future__ import annotations

from serrier.core.findings import Confidence, Finding, Severity, Status

_SEV = {Severity.info: 1, Severity.low: 2, Severity.medium: 3,
        Severity.high: 4, Severity.critical: 5}
_CONF = {Confidence.heuristic: 0.4, Confidence.probable: 0.7, Confidence.confirmed: 1.0}
# Åtgärdade/verifierade/accepterade risker bidrar inte till AKTUELL risk.
_NOLLSTATUS = {Status.remediated, Status.verified, Status.accepted_risk}


def risk_score(f: Finding, *, exploitability: float = 1.0, exposure: float = 1.0,  # noqa: PLR0913
               asset_importance: float = 1.0, data_sensitivity: float = 1.0,
               existing_mitigations: float = 1.0) -> int:
    """0–100. Severity driver, confidence rabatterar; övriga faktorer är neutrala tills
    de har källor. Åtgärdad/verifierad/accepterad → 0 (bidrar inte till aktuell risk)."""
    if f.status in _NOLLSTATUS:
        return 0
    bas = _SEV[f.severity] * _CONF[f.confidence]                       # 0.4 .. 5.0
    justerad = (bas * exploitability * exposure * asset_importance * data_sensitivity
                / max(existing_mitigations, 0.1))
    return max(0, min(100, round(justerad * 20)))                     # → 0–100
