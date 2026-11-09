"""Säkerhets-remediation (extern statisk granskning 2026-11-09). Ett test per fynd (F1-F7).
Granskaren ska försöka ta sig RUNT dessa — testerna pinnar bara att fixarna gör vad de ska.
Syntetisk data."""

import subprocess
import sys

import httpx
import pytest
from fastapi.testclient import TestClient
from upstream_harness import KontrolleradUpstream

from serrier import analyst
from serrier.api.app import app, get_store, krav_sakra_konfig
from serrier.db.store import Store
from serrier.guardian.policy import FailureMode, policy_fran_dict
from serrier.guardian.proxy import GuardProxy, Upstream, skriv_token
from serrier.scanners import base as scanners_base


def _proxy_rigg(**kw):
    up = KontrolleradUpstream()
    klient = httpx.AsyncClient(transport=httpx.ASGITransport(app=up.app()))
    px = GuardProxy(klient=klient, allowlist=[Upstream("test", "https://u.test")],
                    validera_ip=False, **kw)
    return up, TestClient(px.app()), px


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


# --- F3: strömmande body-gräns --------------------------------------------
def test_f3_stor_chunked_body_avvisas_utan_att_buffras() -> None:
    up = KontrolleradUpstream()
    klient = httpx.AsyncClient(transport=httpx.ASGITransport(app=up.app()))
    px = GuardProxy(klient=klient, allowlist=[Upstream("test", "https://u.test")],
                    validera_ip=False, max_body=1000)
    c = TestClient(px.app())

    def stor_chunked():                                   # ingen Content-Length
        for _ in range(50):
            yield b"x" * 100                              # 5000 B > gräns 1000

    r = c.post("/test/v1/x", content=stor_chunked())
    assert r.status_code == 413
    assert up.antal_bytes == 0                            # aldrig inspekterad/forwardad


# --- F5: kodad/ogenomskinlig body → UNKNOWN (aldrig tyst 'ok') -------------
def test_f5_gzip_body_blir_unknown_balanced_blockerar() -> None:
    up, c, px = _proxy_rigg(failure_mode=FailureMode.balanced)
    # Content-Encoding: gzip → kan ej inspekteras som text → unknown → balanced blockerar
    r = c.post("/test/v1/x", content=b"\x1f\x8b\x08rubbish",
               headers={"Content-Encoding": "gzip"})
    assert r.status_code == 403
    assert up.antal_bytes == 0
    assert px.audit[-1]["analysis_status"] == "unknown"   # aldrig 'ok'/'inspekterat'


def test_f5_gzip_body_permissive_forwardas_men_markt_unknown() -> None:
    _, c, px = _proxy_rigg(failure_mode=FailureMode.permissive)
    r = c.post("/test/v1/x", content=b"\x1f\x8b\x08rubbish",
               headers={"Content-Encoding": "gzip"})
    assert r.status_code == 200                            # fail-open i permissive
    assert px.audit[-1]["analysis_status"] == "unknown"   # men ALDRIG markerad inspekterad


# --- F4: query-strängen inspekteras (headers = medveten täckningsgräns) ----
def test_f4_hemlighet_i_query_blockeras() -> None:
    up, c, _ = _proxy_rigg()
    r = c.post("/test/v1/x?key=sk-ant-api03-REALSECRET1234567890abcDEF",
               content=b'{"msg":"ren"}')
    assert r.status_code == 403                            # känsligt i query → block
    assert up.antal_bytes == 0


def test_f4_ren_query_slapper_igenom() -> None:
    up, c, _ = _proxy_rigg()
    r = c.post("/test/v1/x?model=claude&max_tokens=10", content=b'{"msg":"ren"}')
    assert r.status_code == 200
    assert up.antal_bytes > 0


# --- F6: scanner-resursgränser (rlimit i subprocess-barnet) ---------------
def test_f6_resursgrans_dodar_subprocess_som_overskrider(tmp_path) -> None:
    if scanners_base.resource is None:
        pytest.skip("rlimit är POSIX-only")
    mal = tmp_path / "stor"
    # Skriv 10 MB med 1 MB filstorleksgräns → barnet dödas av RLIMIT_FSIZE (SIGXFSZ).
    r = subprocess.run(  # noqa: S603
        [sys.executable, "-c", f"open({str(mal)!r},'w').write('a'*10_000_000)"],
        capture_output=True,
        preexec_fn=lambda: scanners_base.resursgrans(minne=0, fstorlek=1_000_000), check=False)
    assert r.returncode != 0                              # gränsen slog till
    assert not mal.exists() or mal.stat().st_size <= 1_000_000


# --- F7: städning (token-fil, audit-tak, policy-audit, analyst-env) --------
def test_f7_token_skrivs_till_0600_fil_ej_stdout(tmp_path, capsys) -> None:
    fil = skriv_token("hemlig-token-xyz", tmp_path / "tok")
    assert fil.read_text() == "hemlig-token-xyz"
    assert oct(fil.stat().st_mode & 0o777) == "0o600"    # bara ägaren
    assert "hemlig-token-xyz" not in capsys.readouterr().out   # aldrig till stdout


def test_f7_audit_ar_bunden_ringbuffert() -> None:
    _, _, px = _proxy_rigg()
    assert px.audit.maxlen == 1000
    for i in range(1500):
        px.audit.append({"i": i})
    assert len(px.audit) == 1000                          # växer ej obegränsat
    assert px.audit[-1]["i"] == 1499                       # senaste behålls


def test_f7_policy_audit_innehaller_tabellen() -> None:
    st = Store("sqlite:///:memory:")
    org = st.skapa_org("t")
    st.satt_guard_policy(org, policy_fran_dict({"high": "block"}), FailureMode.strict)
    pol = [a for a in st.lista_audit(org) if a["handelse"] == "guard_policy"]
    assert pol
    assert "block" in pol[-1]["detalj"]                   # faktiska tabellen, ej bara fel-läge
    assert "strict" in pol[-1]["detalj"]


def test_f7_analyst_laser_inte_korsprojekt_env(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert analyst.ladda_nyckel() is False                # inget implicit beroende
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    assert analyst.ladda_nyckel() is True
