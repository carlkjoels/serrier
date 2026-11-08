"""Auth: rollhierarki + nyckel-hashning (rena primitiver), samt API-beteendet —
dev-läge utan nycklar, 401 vid krav, RBAC per roll, cross-tenant-isolering, och att
en rå nyckel bara visas en gång. All data syntetisk."""

from pathlib import Path

from fastapi.testclient import TestClient

from serrier import auth
from serrier.api.app import app, get_store
from serrier.auth import Roll, far
from serrier.db.store import Store

HEMLIG_ENV = "ANTHROPIC_API_KEY=sk-ant-api03-REALSECRET1234567890abcDEF\n"


# --- rena primitiver ------------------------------------------------------
def test_rollhierarki() -> None:
    assert far(Roll.owner, Roll.viewer)
    assert far(Roll.member, Roll.member)
    assert not far(Roll.viewer, Roll.member)
    assert not far(Roll.member, Roll.owner)


def test_nyckel_hashas_och_matchar_i_konstant_tid() -> None:
    rå = auth.generera_nyckel()
    assert rå.startswith("srk_")
    h = auth.hasha(rå)
    assert h != rå                               # inte råtext
    assert len(h) == 64                          # sha256 hex
    assert auth.hash_matchar(rå, h)
    assert not auth.hash_matchar("srk_fel", h)


# --- API: dev-läge och auth-krav ------------------------------------------
def _klient(store: Store) -> TestClient:
    app.dependency_overrides[get_store] = lambda: store
    return TestClient(app)


def test_dev_lage_utan_nycklar_tillater_flode(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(HEMLIG_ENV)
    c = _klient(Store("sqlite:///:memory:"))
    try:
        pid = c.post("/projects", json={"namn": "demo"}).json()["project_id"]
        assert c.post(f"/projects/{pid}/scan", json={"sokvag": str(tmp_path)}).status_code == 200
    finally:
        app.dependency_overrides.clear()


def test_nar_nycklar_finns_kravs_auth() -> None:
    st = Store("sqlite:///:memory:")
    org = st.skapa_org("t")
    st.skapa_nyckel(org, Roll.member, "k")       # nu finns minst en nyckel
    c = _klient(st)
    try:
        assert c.post("/projects", json={"namn": "x"}).status_code == 401
        assert c.get("/natverk/posture",
                     headers={"Authorization": "Bearer srk_ogiltig"}).status_code == 401
    finally:
        app.dependency_overrides.clear()


def test_rbac_viewer_far_inte_skanna_men_member_far(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(HEMLIG_ENV)
    st = Store("sqlite:///:memory:")
    org = st.skapa_org("t")
    viewer = st.skapa_nyckel(org, Roll.viewer, "v")
    member = st.skapa_nyckel(org, Roll.member, "m")
    c = _klient(st)
    try:
        h_m = {"Authorization": f"Bearer {member}"}
        pid = c.post("/projects", json={"namn": "demo"}, headers=h_m).json()["project_id"]
        # viewer får läsa men inte skanna
        assert c.get(f"/projects/{pid}/findings",
                     headers={"X-API-Key": viewer}).status_code == 200
        assert c.post(f"/projects/{pid}/scan", json={"sokvag": str(tmp_path)},
                      headers={"X-API-Key": viewer}).status_code == 403
        assert c.post(f"/projects/{pid}/scan", json={"sokvag": str(tmp_path)},
                      headers=h_m).status_code == 200
    finally:
        app.dependency_overrides.clear()


def test_cross_tenant_ger_404(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(HEMLIG_ENV)
    st = Store("sqlite:///:memory:")
    org_a, org_b = st.skapa_org("a"), st.skapa_org("b")
    key_a = st.skapa_nyckel(org_a, Roll.member, "a")
    key_b = st.skapa_nyckel(org_b, Roll.member, "b")
    c = _klient(st)
    try:
        pid = c.post("/projects", json={"namn": "hemligt"},
                     headers={"X-API-Key": key_a}).json()["project_id"]
        # org B når aldrig org A:s projekt — 404, inte 403 (läcker inte existens)
        assert c.get(f"/projects/{pid}/findings",
                     headers={"X-API-Key": key_b}).status_code == 404
    finally:
        app.dependency_overrides.clear()


def test_bootstrap_org_ger_nyckel_en_gang_aldrig_hash() -> None:
    st = Store("sqlite:///:memory:")
    c = _klient(st)
    try:
        r = c.post("/orgs", json={"namn": "acme"}).json()
        oid, nyckel = r["org_id"], r["api_key"]
        assert nyckel.startswith("srk_")
        h = {"X-API-Key": nyckel}
        lista = c.get(f"/orgs/{oid}/keys", headers=h).json()
        assert len(lista) == 1
        assert all("hash" not in k and "api_key" not in k for k in lista)   # aldrig hemligt
        # när en nyckel finns är bootstrap stängd
        assert c.post("/orgs", json={"namn": "igen"}).status_code == 403
    finally:
        app.dependency_overrides.clear()
