"""Export: SARIF 2.1.0 + JSON. Verifierar strukturen CI/GitHub kräver, severity→nivå-
mappning, och att INGEN rå hemlighet läcker (bara redaktad evidens). Syntetisk data."""

from serrier.export import _uri_och_rad, till_json, till_sarif


def _f(**kw) -> dict:
    bas = {"id": "abc123", "category": "secret", "detector": "builtin",
           "severity": "high", "confidence": "probable", "status": "detected",
           "asset_ref": ".env:12", "title": "AWS-nyckel", "rule": "aws-key",
           "aterkomster": 0,
           "evidence": [{"redacted_content": "AKIA…MPLE"}]}
    return {**bas, **kw}


def test_uri_och_rad_delar_ratt() -> None:
    assert _uri_och_rad(".env:12") == (".env", 12)
    assert _uri_och_rad("requirements.txt:flask@1.0") == ("requirements.txt", None)
    assert _uri_och_rad("src/app.py:3") == ("src/app.py", 3)


def test_sarif_struktur() -> None:
    s = till_sarif([_f()])
    assert s["version"] == "2.1.0"
    run = s["runs"][0]
    assert run["tool"]["driver"]["name"] == "Serrier"
    assert run["tool"]["driver"]["rules"][0]["id"] == "aws-key"
    res = run["results"][0]
    assert res["ruleId"] == "aws-key"
    assert res["level"] == "error"                      # high → error
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == ".env"
    assert loc["region"]["startLine"] == 12
    # severity/confidence/status separata i properties, aldrig ihopblandade
    assert res["properties"]["severity"] == "high"
    assert res["properties"]["confidence"] == "probable"
    assert res["properties"]["serrierId"] == "abc123"


def test_sarif_severity_nivamappning() -> None:
    nivaer = {till_sarif([_f(severity=sev)])["runs"][0]["results"][0]["level"]
              for sev in ("critical", "high")}
    assert nivaer == {"error"}
    assert till_sarif([_f(severity="medium")])["runs"][0]["results"][0]["level"] == "warning"
    assert till_sarif([_f(severity="low")])["runs"][0]["results"][0]["level"] == "note"


def test_export_laker_aldrig_ra_hemlighet() -> None:
    hemlig = _f(evidence=[{"redacted_content": "AKIA…MPLE"}])
    for dump in (str(till_sarif([hemlig])), str(till_json([hemlig]))):
        assert "AKIAIOSFODNN7EXAMPLE" not in dump      # rå nyckel finns aldrig i exporten


def test_json_export_metadata() -> None:
    j = till_json([_f(), _f(id="x")])
    assert j["tool"] == "serrier"
    assert j["antal"] == 2
    assert len(j["findings"]) == 2
