"""Analytics: posture, fördelningar, etikett (aldrig 'säker'), status exkluderar
åtgärdade. Rena funktioner → syntetisk data."""

from serrier import analytics


def _f(sev: str, kat: str = "secret", det: str = "builtin", status: str = "detected",
       risk: int = 50) -> dict:
    return {"id": f"{sev}-{kat}-{risk}", "severity": sev, "confidence": "probable",
            "category": kat, "detector": det, "status": status, "risk": risk,
            "asset_ref": "x:1", "title": "t"}


def test_posture_fordelningar_och_risk() -> None:
    f = [_f("critical", risk=100), _f("high", "injection", "semgrep", risk=80),
         _f("low", risk=20)]
    p = analytics.posture(f)
    assert p["etikett"] == "kritisk"
    assert p["antal_oppna"] == 3
    assert p["risk_total"] == 200
    assert p["per_severity"] == {"critical": 1, "high": 1, "low": 1}
    assert p["per_detektor"] == {"builtin": 2, "semgrep": 1}
    assert p["topp"][0]["risk"] == 100              # topp sorterad på risk


def test_atgardade_exkluderas_ur_oppen_risk() -> None:
    f = [_f("critical", status="remediated", risk=100), _f("low", risk=20)]
    p = analytics.posture(f)
    assert p["antal_oppna"] == 1                     # bara den låga är öppen
    assert p["antal_atgardade"] == 1
    assert p["etikett"] == "låg"                     # critical är åtgärdad → ej kritisk
    assert p["risk_total"] == 20


def test_etikett_sager_aldrig_saker() -> None:
    assert analytics.posture([])["etikett"] == "inga öppna fynd"
    assert "säker" not in analytics.posture([])["etikett"]


def test_timeline_fran_scans() -> None:
    t = analytics.timeline([{"tid": "2026-11-01T00:00:00", "antal": 3, "detektorer": "x"},
                            {"tid": "2026-11-02T00:00:00", "antal": 1, "detektorer": "x"}])
    assert [p["antal"] for p in t] == [3, 1]
