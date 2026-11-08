"""Adapter-agnostiskt enforcement-kontrakt (Design 0001 §4.3, 0002 §8). Beslutskärnan
(`inspect`) är oförändrad; adaptrar (proxy nu, CLI/browser-ext senare) konsumerar dess
GuardDecision och verkställer den vid sin kontrollpunkt.

Kärnprincip: `enforcement_level` är en egenskap hos ADAPTERN, inte hos produkten. En proxy
som äger kontrollpunkten är `guaranteed` för routad trafik; en browser-extension är
`best_effort`. UI/rapport får ALDRIG uppgradera best_effort till garanterat block.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol, runtime_checkable

from serrier.guardian.policy import GuardAction


class EnforcementLevel(StrEnum):
    guaranteed = "guaranteed"      # block stoppar trafiken tekniskt (kontrollpunkt vi äger)
    best_effort = "best_effort"    # kan varna/redaktera men inte garantera stopp


class ProxyHandling(StrEnum):
    forward = "forward"            # skicka vidare (ev. efter varning/logg)
    redact = "redact"              # skriv om säkert, annars degradera till block
    block = "block"                # stoppa — når aldrig upstream


# Aktion → vad en enforcement-punkt gör. require_approval kan inte promptas interaktivt i en
# proxy → behandlas som block (håll tillbaka) med tydlig orsak. warn loggas men släpps.
_HANDLING: dict[GuardAction, ProxyHandling] = {
    GuardAction.allow: ProxyHandling.forward,
    GuardAction.warn: ProxyHandling.forward,
    GuardAction.redact: ProxyHandling.redact,
    GuardAction.require_approval: ProxyHandling.block,
    GuardAction.block: ProxyHandling.block,
}


def handling_for(action: GuardAction) -> ProxyHandling:
    return _HANDLING[action]


@runtime_checkable
class EnforcementAdapter(Protocol):
    namn: str
    enforcement_level: EnforcementLevel

    def covered_paths(self) -> list[str]:
        """Maskinläsbar täckningsgräns (0002 §2): exakt vilken trafik garantin gäller.
        Rapporteras alltid tillsammans med garantin — aldrig 'säkerhet', bara 'täckning'."""
        ...
