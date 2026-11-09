"""Säkerhets-remediation (extern statisk granskning 2026-11-09). Ett test per fynd (F1-F7).
Granskaren ska försöka ta sig RUNT dessa — testerna pinnar bara att fixarna gör vad de ska.
Syntetisk data."""

import pytest
from fastapi.testclient import TestClient

from serrier.api.app import app, get_store, krav_sakra_konfig
from serrier.db.store import Store


def _klient(store: Store) -> TestClient:
    app.dependency_overrides[get_store] = lambda: store
    return TestClient(app)


# --- F1: Docker auth-lucka ------------------------------------------------
def test_f1_krav_sakra_konfig_vagrar_osaker_start() -> None:
    # Auth krävs men ingen nyckel seedad → vägra starta
    with pytest.raises(RuntimeError):
        krav_sakra_konfig({"SERRIER_REQUIRE_AUTH": "1", "SERRIER_API_KEYS": ""})
    # Auth krävs + nyckel seedad → OK
    krav_sakra_konfig({"SERRIER_REQUIRE_AUTH": "1", "SERRIER_API_KEYS": "srk_x"})
    # Ingen auth krävs → OK (dev)
    krav_sakra_konfig({})


def test_f1_orgs_bootstrap_avstangd_i_auth_lage(monkeypatch) -> None:
    monkeypatch.setenv("SERRIER_REQUIRE_AUTH", "1")
    c = _klient(Store("sqlite:///:memory:"))
    try:
        r = c.post("/orgs", json={"namn": "acme"})
        assert r.status_code == 403                       # öppen bootstrap avstängd
    finally:
        app.dependency_overrides.clear()


def test_f1_orgs_bootstrap_oppen_i_dev(monkeypatch) -> None:
    monkeypatch.delenv("SERRIER_REQUIRE_AUTH", raising=False)
    c = _klient(Store("sqlite:///:memory:"))
    try:
        assert c.post("/orgs", json={"namn": "acme"}).status_code == 200
    finally:
        app.dependency_overrides.clear()


# --- F2: scanner-sökväg begränsad till workspace --------------------------
def test_f2_scan_utanfor_workspace_avvisas(monkeypatch, tmp_path) -> None:
    ws = tmp_path / "workspace"
    (ws / "proj").mkdir(parents=True)
    (tmp_path / "utanfor").mkdir()
    (ws / "lank").symlink_to(tmp_path / "utanfor")       # symlänk ut ur workspace
    monkeypatch.setenv("SERRIER_WORKSPACE_ROOT", str(ws))
    c = _klient(Store("sqlite:///:memory:"))
    try:
        pid = c.post("/projects", json={"namn": "p"}).json()["project_id"]
        # inom workspace → ok
        assert c.post(f"/projects/{pid}/scan",
                      json={"sokvag": str(ws / "proj")}).status_code == 200
        # utanför workspace → 403
        assert c.post(f"/projects/{pid}/scan",
                      json={"sokvag": str(tmp_path / "utanfor")}).status_code == 403
        # symlänk som pekar ut → 403 (inom_roten resolvar länken)
        assert c.post(f"/projects/{pid}/scan",
                      json={"sokvag": str(ws / "lank")}).status_code == 403
    finally:
        app.dependency_overrides.clear()
