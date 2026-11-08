"""Per-org Guardian-policy via RBAC (steg 5b): owner sätter sensitivitet→aktion + fel-läge;
inspect använder orgens policy; viewer/member får inte ändra. Syntetisk data."""

from fastapi.testclient import TestClient

from serrier.api.app import app, get_store
from serrier.auth import Roll
from serrier.db.store import Store

KORT = "betalkort 4111 1111 1111 1111"      # high → default redact


def _klient(store: Store) -> TestClient:
    app.dependency_overrides[get_store] = lambda: store
    return TestClient(app)


def test_default_policy_ar_standard() -> None:
    c = _klient(Store("sqlite:///:memory:"))
    try:
        p = c.get("/guard/policy").json()
        assert p["tabell"]["critical"] == "block"
        assert p["tabell"]["high"] == "redact"
        assert p["failure_mode"] == "balanced"
    finally:
        app.dependency_overrides.clear()


def test_owner_kan_satta_och_inspect_foljer_org_policy() -> None:
    c = _klient(Store("sqlite:///:memory:"))      # dev-läge → owner
    try:
        # default: kort (high) → redact
        assert c.post("/guard/inspect", json={"text": KORT}).json()["action"] == "redact"
        # skärp: high → block
        r = c.put("/guard/policy", json={"tabell": {"high": "block"}, "failure_mode": "strict"})
        assert r.status_code == 200
        assert c.get("/guard/policy").json()["tabell"]["high"] == "block"
        # nu följer inspect orgens policy
        assert c.post("/guard/inspect", json={"text": KORT}).json()["action"] == "block"
    finally:
        app.dependency_overrides.clear()


def test_rbac_viewer_och_member_far_inte_satta() -> None:
    st = Store("sqlite:///:memory:")
    org = st.skapa_org("t")
    viewer = st.skapa_nyckel(org, Roll.viewer, "v")
    member = st.skapa_nyckel(org, Roll.member, "m")
    owner = st.skapa_nyckel(org, Roll.owner, "o")
    c = _klient(st)
    try:
        body = {"tabell": {"high": "block"}, "failure_mode": "balanced"}
        assert c.put("/guard/policy", json=body,
                     headers={"X-API-Key": viewer}).status_code == 403
        assert c.put("/guard/policy", json=body,
                     headers={"X-API-Key": member}).status_code == 403
        assert c.put("/guard/policy", json=body,
                     headers={"X-API-Key": owner}).status_code == 200
    finally:
        app.dependency_overrides.clear()


def test_ogiltig_policy_ger_400() -> None:
    c = _klient(Store("sqlite:///:memory:"))
    try:
        assert c.put("/guard/policy",
                     json={"tabell": {"high": "nonsens"}}).status_code == 400
        assert c.put("/guard/policy",
                     json={"tabell": {"felaktig": "block"}}).status_code == 400
    finally:
        app.dependency_overrides.clear()


def test_org_isolering_av_policy() -> None:
    st = Store("sqlite:///:memory:")
    a, b = st.skapa_org("a"), st.skapa_org("b")
    key_a = st.skapa_nyckel(a, Roll.owner, "a")
    key_b = st.skapa_nyckel(b, Roll.owner, "b")
    c = _klient(st)
    try:
        c.put("/guard/policy", json={"tabell": {"high": "block"}},
              headers={"X-API-Key": key_a})
        # org B påverkas inte av org A:s policy
        assert c.get("/guard/policy",
                     headers={"X-API-Key": key_b}).json()["tabell"]["high"] == "redact"
    finally:
        app.dependency_overrides.clear()
