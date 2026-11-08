"""Guardian policy-motor (Design 0001, steg 3). KOD fattar beslutet, aldrig en modell.
Deterministisk och förklarbar: givet detektioner + sensitivitet → exakt ett verdikt, och
varje verdikt namnger regeln som gav det.

Två låsta principer kodas här:

1. UNKNOWN är ett eget tillstånd. `analysis_status` (ok|unknown) är SKILT från `action`.
   Okänt kollapsar aldrig till ALLOW/"godkänt" — vad som händer med oanalyserad trafik
   avgörs av fel-läget, aldrig av en tyst default.

2. Fel-läge = tre-läges-policy (STRICT/BALANCED/PERMISSIVE), inte ett universellt beteende.
   BALANCED släpper ALDRIG tyst igenom oanalyserat känsligt — den kräver godkännande.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from serrier.core.textdetect import Traff
from serrier.guardian.classify import Sensitivity, sensitivitet


class GuardAction(StrEnum):
    allow = "allow"
    warn = "warn"
    redact = "redact"
    require_approval = "require_approval"
    block = "block"


class AnalysisStatus(StrEnum):
    ok = "ok"              # analysen kördes klart
    unknown = "unknown"    # analysen felade/timeout/oparsbar — ALDRIG samma sak som säkert


class FailureMode(StrEnum):
    strict = "strict"          # fail-closed: blockera om kontrollen inte fungerar
    balanced = "balanced"      # riskbaserat: oanalyserat känsligt → kräver godkännande
    permissive = "permissive"  # fail-open: tillåt vid analysfel, med varning + logg


# Restriktivitet — strängast vinner när flera detektioner ger olika aktioner.
_RANG: dict[GuardAction, int] = {
    GuardAction.allow: 0, GuardAction.warn: 1, GuardAction.redact: 2,
    GuardAction.require_approval: 3, GuardAction.block: 4,
}

# Vad UNKNOWN mappar till per fel-läge. BALANCED kräver godkännande — släpper aldrig tyst.
_UNKNOWN_AKTION: dict[FailureMode, GuardAction] = {
    FailureMode.strict: GuardAction.block,
    FailureMode.balanced: GuardAction.require_approval,
    FailureMode.permissive: GuardAction.allow,
}


def strangast(aktioner: list[GuardAction]) -> GuardAction:
    return max(aktioner, key=lambda a: _RANG[a]) if aktioner else GuardAction.allow


@dataclass(frozen=True)
class Reason:
    """Varför en detektion ledde till sin aktion — spårbart till regel + sensitivitet."""
    regel: str
    kategori: str
    sensitivity: str
    action: GuardAction
    forklaring: str


@dataclass(frozen=True)
class GuardVerdict:
    action: GuardAction
    analysis_status: AnalysisStatus
    reasons: list[Reason] = field(default_factory=list)
    failure_mode: FailureMode | None = None   # satt när analysis_status = unknown


@dataclass(frozen=True)
class Policy:
    """Sensitivitet → aktion. Överridbar per org (owner-grindad, senare). Standard nedan."""
    tabell: dict[Sensitivity, GuardAction]

    def aktion(self, s: Sensitivity) -> GuardAction:
        return self.tabell[s]


# Standardpolicy: hemligheter (critical) blockeras; kort/pnr/generiska (high) maskeras;
# entropi/mejl (medium) + intern IP (low) varnar. Prevention-vänligt och förklarbart.
STANDARD = Policy({
    Sensitivity.critical: GuardAction.block,
    Sensitivity.high: GuardAction.redact,
    Sensitivity.medium: GuardAction.warn,
    Sensitivity.low: GuardAction.warn,
})


def _reason(t: Traff, action: GuardAction) -> Reason:
    s = sensitivitet(t)
    txt = f"{t.regel} ({t.kategori.value}, sensitivitet {s.name}) → {action.value}"
    return Reason(regel=t.regel, kategori=t.kategori.value, sensitivity=s.name,
                  action=action, forklaring=txt)


def besluta(traffar: list[Traff], *, analysis_status: AnalysisStatus = AnalysisStatus.ok,
            failure_mode: FailureMode = FailureMode.balanced,
            policy: Policy = STANDARD) -> GuardVerdict:
    """Fatta ett verdikt. Vid UNKNOWN avgör fel-läget — aldrig en tyst default, och
    aldrig rapporterat som 'analyserat'. Vid OK: strängaste aktionen bland detektionerna
    (inga detektioner → ALLOW, men analysis_status=ok = 'kontrollerat och rent', vilket är
    en ANNAN sak än unknown)."""
    if analysis_status is AnalysisStatus.unknown:
        action = _UNKNOWN_AKTION[failure_mode]
        txt = (f"analysen kunde inte slutföras; fel-läge {failure_mode.value} → "
               f"{action.value}. Okänt är inte samma sak som säkert.")
        return GuardVerdict(
            action=action, analysis_status=AnalysisStatus.unknown, failure_mode=failure_mode,
            reasons=[Reason(regel="analysis-unknown", kategori="unknown",
                            sensitivity="unknown", action=action, forklaring=txt)])

    reasons = [_reason(t, policy.aktion(sensitivitet(t))) for t in traffar]
    action = strangast([r.action for r in reasons])
    return GuardVerdict(action=action, analysis_status=AnalysisStatus.ok, reasons=reasons)
