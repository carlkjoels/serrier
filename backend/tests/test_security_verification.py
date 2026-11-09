"""Oberoende VERIFIERINGSRUNDA av remediation-arbetet (2026-11-09). Till skillnad från
test_security_fixes.py (som pinnar att fixarna gör rätt sak) FÖRSÖKER dessa tester ta sig
RUNT varje fix — negativa/adversariella varianter — och DOKUMENTERAR kvarstående gap som
tester (ett gap som är medvetet oåtgärdat bevisas, det döljs inte). Syntetisk data."""

import gzip

import httpx
from fastapi.testclient import TestClient
from upstream_harness import KontrolleradUpstream

from serrier.api.app import app, get_store
from serrier.db.store import Store
from serrier.guardian.policy import FailureMode
from serrier.guardian.proxy import GuardProxy, Upstream

RA = "sk-ant-api03-REALSECRET1234567890abcDEF"


def _rigg(**kw):
    up = KontrolleradUpstream()
    klient = httpx.AsyncClient(transport=httpx.ASGITransport(app=up.app()))
    px = GuardProxy(klient=klient, allowlist=[Upstream("test", "https://u.test")],
                    validera_ip=False, **kw)
    return up, TestClient(px.app()), px


def _api(store: Store) -> TestClient:
    app.dependency_overrides[get_store] = lambda: store
    return TestClient(app)




# --- F1: försök kringgå auth-grinden --------------------------------------
def test_v_f1_require_auth_valfritt_varde_tvingar_auth(monkeypatch) -> None:
    # Även "0"/"false" är icke-tomt → auth PÅ (fail-safe riktning). Ingen oavsiktlig öppning.
    monkeypatch.setenv("SERRIER_REQUIRE_AUTH", "0")
    c = _api(Store("sqlite:///:memory:"))
    try:
        assert c.get("/natverk/posture").status_code == 401       # inget dev-owner trots "0"
        assert c.post("/orgs", json={"namn": "x"}).status_code == 403
    finally:
        app.dependency_overrides.clear()


# --- F2: försök ta sig ur workspace --------------------------------------
def test_v_f2_traversal_och_prefix_attack_avvisas(monkeypatch, tmp_path) -> None:
    ws = tmp_path / "ws"
    (ws / "proj").mkdir(parents=True)
    (tmp_path / "ws-evil").mkdir()                                 # syskon med delad prefix-sträng
    monkeypatch.setenv("SERRIER_WORKSPACE_ROOT", str(ws))
    c = _api(Store("sqlite:///:memory:"))
    try:
        pid = c.post("/projects", json={"namn": "p"}).json()["project_id"]
        # ../-traversal ut ur workspace
        assert c.post(f"/projects/{pid}/scan",
                      json={"sokvag": str(ws / ".." / "ws-evil")}).status_code == 403
        # prefix-sträng-attack: /…/ws-evil delar textprefix med /…/ws men ligger UTANFÖR
        assert c.post(f"/projects/{pid}/scan",
                      json={"sokvag": str(tmp_path / "ws-evil")}).status_code == 403
    finally:
        app.dependency_overrides.clear()


# --- F3: boundary + chunked-smuggling ------------------------------------
def test_v_f3_exakt_gräns_ok_en_over_blockeras() -> None:
    up, c, _ = _rigg(max_body=1000)

    def chunked(n):
        def gen():
            yield b"x" * n
        return gen()

    assert c.post("/test/v1/x", content=chunked(1000)).status_code == 200    # exakt = ok
    assert up.antal_bytes == 1000
    assert c.post("/test/v1/x", content=chunked(1001)).status_code == 413     # +1 → block


# --- F4: query-kringgång OCH det dokumenterade header-gapet ----------------
def test_v_f4_url_kodad_hemlighet_i_query_fangas() -> None:
    up, c, _ = _rigg()
    # procent-kodad hemlighet i query → unquote före inspektion → ska fångas
    kodad = RA.replace("-", "%2D")
    r = c.post(f"/test/v1/x?key={kodad}", content=b'{"m":"ren"}')
    assert r.status_code == 403
    assert up.antal_bytes == 0


def test_v_f4_header_ar_INTE_prevention_dokumenterat_gap() -> None:
    # ÄRLIGHET: headers innehålls-inspekteras INTE. En hemlighet i en custom header
    # VIDAREBEFORDRAS. Detta är en medveten täckningsgräns (F4) — bevisas, döljs ej.
    up, c, _ = _rigg()
    r = c.post("/test/v1/x", content=b'{"m":"ren"}', headers={"X-Secret": RA})
    assert r.status_code == 200
    assert up.mottaget[-1]["headers"].get("x-secret") == RA       # headern gick fram oinspekterad


# --- F5: kringgå encoded-body-grinden ------------------------------------
def test_v_f5_casing_och_identity() -> None:
    up, c, px = _rigg(failure_mode=FailureMode.balanced)
    # Versal-variant "GZIP" → fortfarande unknown (block i balanced)
    assert c.post("/test/v1/x", content=b"junk",
                  headers={"Content-Encoding": "GZIP"}).status_code == 403
    # identity → ska inspekteras normalt (en hemlighet blockeras, ej 'unknown')
    r = c.post("/test/v1/x", content=f'{{"p":"{RA}"}}'.encode(),
               headers={"Content-Encoding": "identity"})
    assert r.status_code == 403
    assert px.audit[-1]["analysis_status"] == "ok"                # identity = inspekterbar
    assert up.antal_bytes == 0


def test_v_f5_gzip_utan_header_ar_oloest_residual() -> None:
    # OLÖST RESIDUAL (redovisas, ej åtgärdat): en gzip-body UTAN Content-Encoding-header
    # inspekteras som 'text' och kan bli analysis_status=ok. (Funktionellt läcker den dock
    # inte en användbar hemlighet: utan headern av-gzippar inte heller upstream.)
    up, c, px = _rigg(failure_mode=FailureMode.balanced)
    kropp = gzip.compress(f'{{"p":"{RA}"}}'.encode())
    r = c.post("/test/v1/x", content=kropp)                       # ingen Content-Encoding
    # Dokumenterar nuläget: detektorn ser binärt brus, markerar ok, forwardar.
    assert r.status_code == 200
    assert px.audit[-1]["analysis_status"] == "ok"               # <-- känt gap, ej fix
    assert up.innehaller(RA.encode()) is False                    # men råa hemligheten läcker ej
