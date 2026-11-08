"""Adversarial recall-svit (steg 5): försök att SMYGA FÖRBI Guardian-detektionen.
MÄRKT SYNTETISK fixtur — publicerade siffror, separat från verkliga data. Mäter recall över
evasions-vektorer OCH redovisar ärligt vilka vektorer vi INTE försvarar (ingen fullständig-
hetsclaim: detektion är < 100%).
"""

import base64

from serrier.guardian.inspect import inspect
from serrier.guardian.policy import GuardAction

RA = "sk-ant-api03-REALSECRET1234567890abcDEF"
_SLAPPT = GuardAction.allow      # enda aktionen som = "passerar ogranskat"


def _blockeras(text: str) -> bool:
    """Fångad = inte ALLOW (block/redact/warn/require_approval). ALLOW = förbisedd."""
    return inspect(text).action != _SLAPPT


def _homoglyf(s: str) -> str:
    return s.replace("a", "а").replace("e", "е").replace("o", "о")   # latin → kyrilliskt


# Vektorer vi FÖRSVARAR — ska alla fångas (recall 1.0).
FORSVARADE: dict[str, str] = {
    "rakt": f"min nyckel {RA}",
    "kodblock": f"```\n{RA}\n```",
    "homoglyf": f"nyckel {_homoglyf(RA)}",
    "zero-width": "sk-ant\u200b-api03-REALSECRET1234567890abcDEF",
    "mellanslag": " ".join(RA),
    "radbruten": "sk-ant-\napi03-REALSECRET1234567890abcDEF",
    "base64": f"payload={base64.b64encode(RA.encode()).decode()}",
    "base64-i-text": f"se datan {base64.b64encode(RA.encode()).decode()} tack",
    "crlf": f"rad1\r\nnyckel {RA}\r\n",
}

# Rena fall — ska ALDRIG blockeras (inga falska positiva på evasion-logiken).
RENA: list[str] = [
    "ett helt vanligt meddelande utan känsligt",
    "här är lite base64: aGVqIHbDpHJsZGVu men ofarligt",     # base64 av 'hej världen'
    "kolla https://example.com/path?q=test för mer info",
]


def test_recall_over_forsvarade_evasions() -> None:
    fångade = {namn for namn, text in FORSVARADE.items() if _blockeras(text)}
    missade = set(FORSVARADE) - fångade
    recall = len(fångade) / len(FORSVARADE)
    print(f"\n[syntetisk] evasion-recall={recall:.2f} "
          f"({len(fångade)}/{len(FORSVARADE)}) missade={sorted(missade)}")
    assert recall == 1.0, sorted(missade)


def test_inga_falska_positiva_pa_rena_fall() -> None:
    falska = [t for t in RENA if _blockeras(t)]
    assert falska == [], falska


def test_kanda_luckor_dokumenteras_ej_claimas() -> None:
    """ÄRLIGHET: vektorer vi INTE försvarar i v1. Testet hävdar inte att de fångas — det
    dokumenterar att vi vet om dem, så ingen fullständighetsclaim smyger sig in."""
    kanda_luckor = {
        "hex-kodad": RA.encode().hex(),                       # ingen hex-avkodning i v1
        "rot13-liknande": RA[::-1],                           # omkastad
        "krypterad/komprimerad nyttolast": "<chiffertext>",   # kan ej inspekteras
    }
    förbisedda = [namn for namn, text in kanda_luckor.items() if not _blockeras(text)]
    # Vi VÄNTAR oss att dessa slipper igenom — det är poängen med att redovisa dem.
    print(f"\n[syntetisk] kända oförsvaradevektorer som slipper igenom: {förbisedda}")
    assert "hex-kodad" in förbisedda                          # bekräftar: vi claimar inte hex
