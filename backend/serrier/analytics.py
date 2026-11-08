"""Analytics-lagret: aggregera findings till säkerhetsposture, risk-fördelning och
timeline. Rena funktioner på data (findings-dictar från store) — deterministiskt och
testbart. Posture-etiketten säger ALDRIG 'säker': ett rent läge är 'inga öppna fynd i
den körda täckningen', inte en garanti."""

from __future__ import annotations

from collections import Counter

# Status som inte räknas som öppen risk.
_STANGDA = {"remediated", "verified", "accepted_risk"}


def _oppna(findings: list[dict]) -> list[dict]:
    return [f for f in findings if f["status"] not in _STANGDA]


def _etikett(oppna: list[dict]) -> str:
    sev = {f["severity"] for f in oppna}
    if "critical" in sev:
        return "kritisk"
    if "high" in sev:
        return "förhöjd"
    if oppna:
        return "låg"
    return "inga öppna fynd"        # ALDRIG 'säker' — bara: täckningen fann inget öppet


def posture(findings: list[dict]) -> dict:
    oppna = _oppna(findings)
    risk_tot = sum(f["risk"] for f in oppna)
    return {
        "etikett": _etikett(oppna),
        "antal_findings": len(findings),
        "antal_oppna": len(oppna),
        "antal_atgardade": len(findings) - len(oppna),
        "risk_total": risk_tot,
        "risk_snitt": round(risk_tot / len(oppna), 1) if oppna else 0,
        "per_severity": dict(Counter(f["severity"] for f in oppna)),
        "per_kategori": dict(Counter(f["category"] for f in oppna)),
        "per_detektor": dict(Counter(f["detector"] for f in oppna)),
        "topp": [{"id": f["id"], "severity": f["severity"], "confidence": f["confidence"],
                  "detector": f["detector"], "asset_ref": f["asset_ref"],
                  "title": f["title"], "risk": f["risk"]}
                 for f in sorted(oppna, key=lambda d: d["risk"], reverse=True)[:10]],
    }


def timeline(scans: list[dict]) -> list[dict]:
    """Fynd per skanning över tid — enklaste trenden (riskutveckling kräver
    historik-snapshots, en senare skiva)."""
    return [{"tid": s["tid"], "antal": s["antal"]} for s in scans]


def reappearances(findings: list[dict]) -> list[dict]:
    """Fynd som återkommit efter att ha verifierats/åtgärdats (regression). En fix som
    inte höll är viktigare att veta om än ett nytt fynd — den signalerar en trasig
    åtgärdsprocess. Sorterat på flest återkomster först."""
    regr = [f for f in findings if f.get("aterkomster", 0) > 0]
    regr.sort(key=lambda f: f["aterkomster"], reverse=True)
    return [{"id": f["id"], "asset_ref": f["asset_ref"], "title": f["title"],
             "detector": f["detector"], "severity": f["severity"],
             "status": f["status"], "aterkomster": f["aterkomster"]} for f in regr]
