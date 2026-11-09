"""Prevention-flöde (#1): proxy/inspect → kontrollplan → dashboard. Ett test per del.
Allt som lagras/exponeras är REDAKTERAT — rå hemlighet får aldrig nå flödet. Syntetisk data."""

import httpx
from fastapi.testclient import TestClient
from upstream_harness import KontrolleradUpstream

from serrier.api.app import app, get_store
from serrier.db.store import Store
from serrier.guardian.proxy import GuardProxy, Upstream

RA = "sk-ant-api03-REALSECRET1234567890abcDEF"


def _api(store: Store) -> TestClient:
    app.dependency_overrides[get_store] = lambda: store
    return TestClient(app)


# --- del 1: Store ---------------------------------------------------------
def test_store_event_org_scopat_och_redakterat() -> None:
    st = Store("sqlite:///:memory:")
    a, b = st.skapa_org("a"), st.skapa_org("b")
    st.spara_guard_event(a, action="block", analysis_status="ok",
                         rules=[{"regel": "anthropic-api-key", "redacted": "sk-a…DEF"}])
    ev = st.lista_guard_events(a)
    assert len(ev) == 1
    assert ev[0]["action"] == "block"
    assert ev[0]["rules"][0]["regel"] == "anthropic-api-key"
    assert st.lista_guard_events(b) == []            # org-isolering


# --- del 2: API ingest + läs ----------------------------------------------
def test_api_ingest_och_las() -> None:
    c = _api(Store("sqlite:///:memory:"))
    try:
        r = c.post("/guard/events", json={
            "action": "redact", "analysis_status": "ok", "upstream": "api.anthropic.com",
            "rules": [{"regel": "credit-card", "redacted": "4111…1111"}]})
        assert r.status_code == 200
        ev = c.get("/guard/events").json()
        assert ev[0]["action"] == "redact"
        assert ev[0]["upstream"] == "api.anthropic.com"
    finally:
        app.dependency_overrides.clear()


# --- del 3: /guard/inspect skriver event (och redakterar) -----------------
def test_inspect_skriver_redakterat_event() -> None:
    c = _api(Store("sqlite:///:memory:"))
    try:
        c.post("/guard/inspect", json={"text": f"nyckel {RA}"})
        ev = c.get("/guard/events").json()
        assert any(e["action"] == "block" for e in ev)
        assert "REALSECRET" not in str(ev)           # rå hemlighet aldrig i flödet
    finally:
        app.dependency_overrides.clear()


# --- del 4: proxyn rapporterar event (serrier-guard-vägen) ----------------
def test_proxy_rapporterar_event() -> None:
    st = Store("sqlite:///:memory:")
    org = st.dev_org()
    up = KontrolleradUpstream()
    klient = httpx.AsyncClient(transport=httpx.ASGITransport(app=up.app()))
    px = GuardProxy(klient=klient, allowlist=[Upstream("test", "https://u.test")],
                    validera_ip=False, store=st, org_id=org)
    c = TestClient(px.app())
    c.post("/test/v1/x", content=f'{{"p":"{RA}"}}'.encode())
    ev = st.lista_guard_events(org)
    assert any(e["action"] == "block" for e in ev)
    assert "REALSECRET" not in str(ev)               # redakterat
