"""Guardian beslutskärna (Design 0001, steg 4). Kedjar detektion → policy → redaktion och
returnerar ett GuardDecision. Lokal, deterministisk, noll integration — adaptrar (proxy,
CLI, …) konsumerar detta senare (steg 6).

Två säkerhetsegenskaper:
- `safe_text` ersätter varje träff med en OPAK markör `[redacted:regel]` — aldrig delar av
  en hemlighet läcker ut (till skillnad från findings-evidensen, som visar first4…last4 så
  utvecklaren känner igen vad som fångades).
- Om detektionen felar blir analysis_status = unknown (policy-motorns fel-läge avgör vad
  som händer). Rå text persisteras/loggas aldrig — den lever bara under anropet.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from serrier.core.findings import redact
from serrier.core.textdetect import Traff
from serrier.guardian.classify import detektera_kanslig, sensitivitet
from serrier.guardian.policy import (
    STANDARD,
    AnalysisStatus,
    FailureMode,
    GuardAction,
    Policy,
    Reason,
    besluta,
)


@dataclass(frozen=True)
class GuardFinding:
    """En detektion för svaret — ENDAST redakterad. Rå träff ingår aldrig."""
    regel: str
    kategori: str
    sensitivity: str
    redacted: str          # redact(träff) = first4…last4, aldrig rå
    start: int
    slut: int


@dataclass(frozen=True)
class GuardDecision:
    action: GuardAction
    analysis_status: AnalysisStatus
    failure_mode: FailureMode | None
    safe_text: str
    reasons: list[Reason] = field(default_factory=list)
    findings: list[GuardFinding] = field(default_factory=list)

    def som_dict(self) -> dict:
        return {
            "action": self.action.value,
            "analysis_status": self.analysis_status.value,
            "failure_mode": self.failure_mode.value if self.failure_mode else None,
            "safe_text": self.safe_text,
            "reasons": [{"regel": r.regel, "kategori": r.kategori,
                         "sensitivity": r.sensitivity, "action": r.action.value,
                         "forklaring": r.forklaring} for r in self.reasons],
            "findings": [{"regel": f.regel, "kategori": f.kategori,
                          "sensitivity": f.sensitivity, "redacted": f.redacted,
                          "start": f.start, "slut": f.slut} for f in self.findings],
        }


def maska(text: str, traffar: list[Traff]) -> str:
    """Ersätt varje träff-spann med en opak markör. Inga delar av en hemlighet lämnar
    kvar. Spannen är icke-överlappande (kärnan anspråkar spann), men vi hoppar defensivt
    över ev. överlapp."""
    if not traffar:
        return text
    delar: list[str] = []
    i = 0
    for t in sorted(traffar, key=lambda x: x.start):
        if t.start < i:
            continue
        delar.append(text[i:t.start])
        delar.append(f"[redacted:{t.regel}]")
        i = t.slut
    delar.append(text[i:])
    return "".join(delar)


def inspect(text: str, *, failure_mode: FailureMode = FailureMode.balanced,
            policy: Policy = STANDARD) -> GuardDecision:
    """Inspektera utgående text lokalt. Detektion-fel → UNKNOWN (fel-läget avgör). Rå text
    lagras/loggas aldrig; bara redakterad data lämnar den här funktionen."""
    try:
        traffar = detektera_kanslig(text)
        status = AnalysisStatus.ok
    except Exception:
        traffar, status = [], AnalysisStatus.unknown

    verdict = besluta(traffar, analysis_status=status, failure_mode=failure_mode, policy=policy)
    # safe_text redakteras alltid när något hittades — oavsett aktion — så en REDACT/WARN
    # kan skickas vidare utan hemligheten. (Vid UNKNOWN finns inga träffar att maska.)
    safe = maska(text, traffar)
    findings = [GuardFinding(regel=t.regel, kategori=t.kategori.value,
                             sensitivity=sensitivitet(t).name, redacted=redact(t.text),
                             start=t.start, slut=t.slut) for t in traffar]
    return GuardDecision(action=verdict.action, analysis_status=verdict.analysis_status,
                         failure_mode=verdict.failure_mode, safe_text=safe,
                         reasons=verdict.reasons, findings=findings)
