"""Guardian beslutskärna (steg 4): inspect() + safe_text-redaktion + UNKNOWN vid fel,
samt API-endpointen. Bevisar att ingen rå hemlighet läcker i safe_text eller svaret.
Syntetisk data."""

from fastapi.testclient import TestClient

from serrier.api.app import app, get_store
from serrier.db.store import Store
from serrier.guardian import inspect as inspect_mod
from serrier.guardian.inspect import inspect, maska
from serrier.guardian.policy import AnalysisStatus, FailureMode, GuardAction

RA = "sk-ant-api03-REALSECRET1234567890abcDEF"


def test_hemlighet_blockeras_och_maskeras() -> None:
    d = inspect(f"min nyckel är {RA} ok")
    assert d.action == GuardAction.block
    assert d.analysis_status == AnalysisStatus.ok
    assert RA not in d.safe_text                     # rå hemlighet borta
    assert "[redacted:anthropic-api-key]" in d.safe_text


def test_safe_text_innehaller_aldrig_ra_traff() -> None:
    text = f"kort 4111 1111 1111 1111, pnr 810118-9879, nyckel {RA}"
    d = inspect(text)
    # ingen råträff kvar i safe_text
    assert RA not in d.safe_text
    assert "4111 1111 1111 1111" not in d.safe_text
    assert "810118-9879" not in d.safe_text


def test_ren_text_passerar_oforandrad() -> None:
    d = inspect("ett helt vanligt meddelande")
    assert d.action == GuardAction.allow
    assert d.analysis_status == AnalysisStatus.ok
    assert d.safe_text == "ett helt vanligt meddelande"
    assert d.findings == []


def test_findings_visar_redakterat_inte_ratt() -> None:
    d = inspect(f"nyckel {RA}")
    f = d.findings[0]
    assert f.redacted != RA
    assert "…" in f.redacted or f.redacted == "***"   # first4…last4


def test_detektionsfel_ger_unknown(monkeypatch) -> None:
    def spräng(_text: str):
        raise RuntimeError("detektorn kraschade")
    monkeypatch.setattr(inspect_mod, "detektera_kanslig", spräng)
    d = inspect("vad som helst", failure_mode=FailureMode.strict)
    assert d.analysis_status == AnalysisStatus.unknown    # aldrig tyst 'ok'
    assert d.action == GuardAction.block                  # strict → fail-closed


def test_maska_hoppar_overlapp_defensivt() -> None:
    assert maska("abc", []) == "abc"


# --- API ------------------------------------------------------------------
def _klient() -> TestClient:
    app.dependency_overrides[get_store] = lambda: Store("sqlite:///:memory:")
    return TestClient(app)


def test_endpoint_blockerar_och_laker_inte() -> None:
    c = _klient()
    try:
        r = c.post("/guard/inspect", json={"text": f"nyckel {RA}"})
        assert r.status_code == 200
        body = r.json()
        assert body["action"] == "block"
        assert body["analysis_status"] == "ok"
        assert RA not in str(body)                    # rå hemlighet aldrig i svaret
    finally:
        app.dependency_overrides.clear()


def test_endpoint_ogiltigt_failure_mode() -> None:
    c = _klient()
    try:
        r = c.post("/guard/inspect", json={"text": "x", "failure_mode": "nonsens"})
        assert r.status_code == 400
    finally:
        app.dependency_overrides.clear()


def test_endpoint_ren_text_allow() -> None:
    c = _klient()
    try:
        body = c.post("/guard/inspect", json={"text": "hej och god morgon"}).json()
        assert body["action"] == "allow"
        assert body["safe_text"] == "hej och god morgon"
    finally:
        app.dependency_overrides.clear()
