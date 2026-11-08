"""Remediation-motor: föreslå → (godkänn) → åtgärda → omskanna → verifiera. Inget
auto-applas; status ändras bara via människans explicita handling (store.satt_status) och
verifiering sker bara genom en faktisk omskanning (store auto-verifierar godkända fynd som
försvunnit).

KOD-framtvingad regel: en exponerad hemlighet är KOMPROMETTERAD → åtgärden är ROTATION/
ÅTERKALLELSE, inte 'ta bort raden' (den finns kvar i git-historik och kan redan vara läckt).
Det är inte modellens val.
"""

from __future__ import annotations

from collections.abc import Callable

from serrier import analyst

_ROTATIONSKRAV = ("Hemligheten är KOMPROMETTERAD — rotera/återkalla den omedelbart hos "
                  "utfärdaren. Att ta bort raden räcker INTE: den finns kvar i git-historik "
                  "och kan redan ha läckt.")


def foresla_atgard(f: dict, anropa: Callable[[str], str] | None = None) -> dict:
    """Ett åtgärdsförslag för ett fynd. Modellen föreslår text (via analyst); koden lägger
    till det icke förhandlingsbara rotationskravet för hemligheter."""
    analys = analyst.analysera(f, anropa)
    forslag = {"finding_id": f["id"], "prioritet": analys["prioritet"],
               "forklaring": analys["forklaring"], "impact": analys["impact"],
               "atgard": analys["atgard"], "kraver_godkannande": True}
    if f.get("category") == "secret":
        forslag["obligatorisk_atgard"] = _ROTATIONSKRAV      # kod-framtvingat, ej modellens val
    return forslag


def verifiera_utfall(risk_fore: int, finns_kvar_efter_omskanning: bool) -> dict:
    """Efter en omskanning: sjönk risken faktiskt? Ett försvunnet fynd = åtgärdat. Ett
    kvarvarande = inte löst (oavsett vad som sades)."""
    atgardat = not finns_kvar_efter_omskanning
    return {"atgardat": atgardat, "risk_fore": risk_fore,
            "risk_efter": 0 if atgardat else risk_fore,
            "slutsats": "risken borta efter omskanning" if atgardat
            else "fyndet finns kvar — inte åtgärdat"}
