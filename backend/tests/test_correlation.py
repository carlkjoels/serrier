"""Cross-detector-korrelation: samma tillgång flaggad av flera detektorer grupperas och
prioriteras. Rena funktioner över finding-dicts. Syntetisk data."""

from serrier.correlation import fil_av, korrelera


def _f(detector: str, asset_ref: str, severity: str = "high", category: str = "secret",
       fid: str = "") -> dict:
    return {"id": fid or f"{detector}:{asset_ref}", "detector": detector,
            "asset_ref": asset_ref, "severity": severity, "category": category}


def test_fil_av_normaliserar_alla_detektorformat() -> None:
    assert fil_av(".env:1") == ".env"
    assert fil_av("src/app.py:42") == "src/app.py"
    assert fil_av("requirements.txt:flask@1.0") == "requirements.txt"


def test_ensam_detektor_ger_ingen_korrelation() -> None:
    fynd = [_f("builtin", ".env:1"), _f("builtin", ".env:2")]   # samma detektor
    assert korrelera(fynd) == []


def test_tva_detektorer_samma_fil_korrelerar() -> None:
    fynd = [_f("builtin", ".env:1"), _f("gitleaks", ".env:1")]
    k = korrelera(fynd)
    assert len(k) == 1
    assert k[0]["tillgang"] == ".env"
    assert k[0]["detektorer"] == ["builtin", "gitleaks"]
    assert k[0]["antal_detektorer"] == 2


def test_sorteras_flest_detektorer_och_hogsta_severity_forst() -> None:
    fynd = [
        _f("builtin", ".env:1", "low"), _f("gitleaks", ".env:1", "low"),   # 2 det, low
        _f("builtin", "app.py:5", "critical"), _f("semgrep", "app.py:5", "critical"),
        _f("osv-scanner", "app.py:5", "high"),                             # 3 det, critical
    ]
    k = korrelera(fynd)
    assert [g["tillgang"] for g in k] == ["app.py", ".env"]     # 3 det före 2 det
    assert k[0]["antal_detektorer"] == 3
    assert k[0]["hogsta_severity"] == "critical"
    assert len(k[0]["finding_ids"]) == 3
