"""AI-analysten: finding_id sätts av koden (aldrig modellen), ingen rå hemlighet i
kontexten, trasigt svar kraschar inte. Claude fejkas (inget API)."""

from serrier import analyst

FYND = {"id": "abc123", "category": "secret", "severity": "critical",
        "confidence": "confirmed", "asset_ref": ".env:1", "title": "Anthropic-nyckel",
        "rule": "anthropic-api-key",
        "evidence": [{"redacted_content": "sk-a…7890"}]}


def _fejk(svar: str):
    return lambda data: svar


def test_finding_id_satts_av_koden() -> None:
    a = analyst.analysera(FYND, _fejk('{"forklaring":"x","impact":"y",'
                                      '"prioritet":"hög","atgard":"rotera"}'))
    assert a["finding_id"] == "abc123"           # kod-satt, ej modellens val
    assert a["forklaring"] == "x"
    assert a["atgard"] == "rotera"


def test_kontext_bar_ingen_ra_hemlighet() -> None:
    # Fånga datan som skickas till modellen och kontrollera att den är redaktad.
    skickat = {}

    def fanga(data: str) -> str:
        skickat["data"] = data
        return "{}"

    analyst.analysera(FYND, fanga)
    assert "sk-ant-api03" not in skickat["data"]  # rått aldrig skickat
    assert "sk-a…7890" in skickat["data"]         # bara det redaktade


def test_trasigt_svar_kraschar_inte() -> None:
    a = analyst.analysera(FYND, _fejk("inte json alls"))
    assert a["finding_id"] == "abc123"
    assert a["forklaring"] == ""                  # tomt, ingen krasch
