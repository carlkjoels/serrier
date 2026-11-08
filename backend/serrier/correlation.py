"""Cross-detector-korrelation. När FLERA oberoende detektorer pekar på samma tillgång
(fil/lockfil) är det ett starkare signal än ett ensamt fynd — oberoende bekräftelse höjer
prioritet. Ren funktion över finding-dicts (store.lista_findings) → korrelationsgrupper.

Detta ÄNDRAR aldrig ett enskilt fynds confidence (det vore att blanda ihop fält). Det är
ett härlett prioriteringslager ovanpå: 'den här filen förtjänar uppmärksamhet först'.
"""

from __future__ import annotations

from serrier.core.findings import Severity

_SEV_RANG = {s.value: i for i, s in enumerate(Severity)}   # info=0 … critical=4


def fil_av(asset_ref: str) -> str:
    """Normalisera en asset_ref till dess tillgång (fil/lockfil). Alla detektorer kodar
    'fil:…': builtin/gitleaks/semgrep → 'path:line', osv → 'lockfil:pkg@ver'. Första
    kolon-segmentet är tillgången (posix-sökvägar har inga kolon)."""
    return asset_ref.split(":", 1)[0]


def _max_sev(fynd: list[dict]) -> str:
    return max((f["severity"] for f in fynd), key=lambda s: _SEV_RANG.get(s, 0))


def korrelera(findings: list[dict], *, min_detektorer: int = 2) -> list[dict]:
    """Gruppera fynd per tillgång; returnera de tillgångar som ≥min_detektorer SKILDA
    detektorer flaggat. Sorterat: flest detektorer först, sedan högst severity."""
    grupper: dict[str, list[dict]] = {}
    for f in findings:
        grupper.setdefault(fil_av(f["asset_ref"]), []).append(f)

    ut: list[dict] = []
    for tillgang, fynd in grupper.items():
        detektorer = sorted({f["detector"] for f in fynd})
        if len(detektorer) < min_detektorer:
            continue
        sev = _max_sev(fynd)
        ut.append({
            "tillgang": tillgang,
            "detektorer": detektorer,
            "antal_detektorer": len(detektorer),
            "antal_fynd": len(fynd),
            "hogsta_severity": sev,
            "finding_ids": sorted(f["id"] for f in fynd),
            "kategorier": sorted({f["category"] for f in fynd}),
            "motivering": (f"{tillgang} flaggad av {len(detektorer)} oberoende detektorer "
                           f"({', '.join(detektorer)}) — oberoende bekräftelse höjer "
                           f"prioritet; åtgärda denna tillgång först."),
        })
    ut.sort(key=lambda k: (k["antal_detektorer"], _SEV_RANG.get(k["hogsta_severity"], 0)),
            reverse=True)
    return ut
