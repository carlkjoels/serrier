"""API: MVP-flödet (skapa → scanna → lista), 404 på okänt projekt, cross-project-
isolering. In-memory-store injiceras. All data syntetisk."""

from pathlib import Path

from fastapi.testclient import TestClient

from serrier.api.app import app, get_store
from serrier.db.store import Store

HEMLIG_ENV = "ANTHROPIC_API_KEY=sk-ant-api03-REALSECRET1234567890abcDEF\n"


def _klient() -> TestClient:
    store = Store("sqlite:///:memory:")
    app.dependency_overrides[get_store] = lambda: store
    return TestClient(app)


def test_flode_skapa_scanna_lista(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(HEMLIG_ENV)
    c = _klient()
    try:
        pid = c.post("/projects", json={"namn": "demo"}).json()["project_id"]
        r = c.post(f"/projects/{pid}/scan", json={"sokvag": str(tmp_path)})
        assert r.status_code == 200
        assert r.json()["antal_findings"] >= 1
        fynd = c.get(f"/projects/{pid}/findings").json()
        assert any(f["category"] == "secret" for f in fynd)
        assert all("REALSECRET" not in str(f["evidence"]) for f in fynd)   # redaktat
    finally:
        app.dependency_overrides.clear()


def test_okant_projekt_ger_404() -> None:
    c = _klient()
    try:
        assert c.get("/projects/finnsinte/findings").status_code == 404
        r = c.post("/projects/finnsinte/scan", json={"sokvag": "/ingen/katalog/alls"})
        assert r.status_code == 404
    finally:
        app.dependency_overrides.clear()


def test_scan_av_icke_katalog_ger_400() -> None:
    c = _klient()
    try:
        pid = c.post("/projects", json={"namn": "x"}).json()["project_id"]
        r = c.post(f"/projects/{pid}/scan", json={"sokvag": "/finns/verkligen/inte"})
        assert r.status_code == 400
    finally:
        app.dependency_overrides.clear()


def test_posture_endpoint(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(HEMLIG_ENV)
    c = _klient()
    try:
        pid = c.post("/projects", json={"namn": "demo"}).json()["project_id"]
        c.post(f"/projects/{pid}/scan", json={"sokvag": str(tmp_path)})
        r = c.get(f"/projects/{pid}/posture")
        assert r.status_code == 200
        body = r.json()
        assert body["posture"]["etikett"] == "kritisk"      # anthropic-nyckel = critical
        assert body["posture"]["antal_oppna"] >= 1
        assert len(body["timeline"]) == 1                   # en skanning körd
    finally:
        app.dependency_overrides.clear()


def test_korrelationer_endpoint_och_posture_falt(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(HEMLIG_ENV)
    c = _klient()
    try:
        pid = c.post("/projects", json={"namn": "demo"}).json()["project_id"]
        c.post(f"/projects/{pid}/scan", json={"sokvag": str(tmp_path)})
        k = c.get(f"/projects/{pid}/correlations")
        assert k.status_code == 200
        assert isinstance(k.json(), list)                   # korrelationer (ev. tom)
        body = c.get(f"/projects/{pid}/posture").json()
        assert "antal_korrelationer" in body                # posture bär korrelations-antal
    finally:
        app.dependency_overrides.clear()


def test_remediation_loop_godkann_och_auto_verifiera(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(HEMLIG_ENV)
    c = _klient()
    try:
        pid = c.post("/projects", json={"namn": "demo"}).json()["project_id"]
        c.post(f"/projects/{pid}/scan", json={"sokvag": str(tmp_path)})
        fid = c.get(f"/projects/{pid}/findings").json()[0]["id"]
        g = c.post(f"/projects/{pid}/findings/{fid}/godkann").json()
        assert g["status"] == "remediation_approved"
        (tmp_path / ".env").unlink()                        # användaren åtgärdar
        c.post(f"/projects/{pid}/scan", json={"sokvag": str(tmp_path)})   # omskanning
        f = c.get(f"/projects/{pid}/findings").json()[0]
        assert f["status"] == "verified"                    # auto-verifierad (fyndet borta)
        assert f["risk"] == 0                               # verifierad → risk 0
    finally:
        app.dependency_overrides.clear()


def test_status_accepted_och_ogiltig(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(HEMLIG_ENV)
    c = _klient()
    try:
        pid = c.post("/projects", json={"namn": "x"}).json()["project_id"]
        c.post(f"/projects/{pid}/scan", json={"sokvag": str(tmp_path)})
        fid = c.get(f"/projects/{pid}/findings").json()[0]["id"]
        r = c.post(f"/projects/{pid}/findings/{fid}/status", json={"status": "accepted_risk"})
        assert r.json()["status"] == "accepted_risk"
        ogiltig = c.post(f"/projects/{pid}/findings/{fid}/status", json={"status": "nonsens"})
        assert ogiltig.status_code == 400
    finally:
        app.dependency_overrides.clear()


def test_cross_project_isolering(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(HEMLIG_ENV)
    c = _klient()
    try:
        a = c.post("/projects", json={"namn": "a"}).json()["project_id"]
        b = c.post("/projects", json={"namn": "b"}).json()["project_id"]
        c.post(f"/projects/{a}/scan", json={"sokvag": str(tmp_path)})
        assert c.get(f"/projects/{b}/findings").json() == []   # b ser aldrig a:s findings
    finally:
        app.dependency_overrides.clear()
