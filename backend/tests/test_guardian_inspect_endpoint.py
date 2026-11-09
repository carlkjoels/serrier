"""0005 steg 1 — loopback-inspektions-endpoint (POST /inspect) för browser-extensionen.

Endpointen BEDÖMER men verkställer inte: den returnerar alltid 200 med ett GuardDecision
(action/handling) så länge Host + token + storlek är OK. Extensionen (PEP:en i browsern)
agerar på verdiktet. Testerna bevisar: rätt verdikt per innehåll, ingen rå text i svaret,
samt att samma loopback-vakt (Host-allowlist + token) skyddar endpointen. Syntetisk data.
"""

import httpx
from starlette.testclient import TestClient

from serrier.guardian.policy import FailureMode
from serrier.guardian.proxy import GuardProxy, Upstream

RA = "sk-ant-api03-REALSECRET1234567890abcDEF"
ALLOW = [Upstream("test", "https://upstream.test")]


def _klient(**kw) -> TestClient:
    px = GuardProxy(klient=httpx.AsyncClient(), allowlist=ALLOW,
                    failure_mode=FailureMode.balanced, validera_ip=False, **kw)
    return TestClient(px.app())


def test_hemlighet_ger_block_verdikt() -> None:
    c = _klient()
    r = c.post("/inspect", content=f'{{"p":"{RA}"}}'.encode())
    assert r.status_code == 200
    data = r.json()
    assert data["handling"] == "block"
    assert data["action"] != "allow"


def test_ren_text_ger_allow() -> None:
    c = _klient()
    r = c.post("/inspect", content=b'{"p":"helt ofarlig text"}')
    assert r.status_code == 200
    assert r.json()["handling"] == "forward"          # forward = extensionen släpper igenom


def test_svaret_innehaller_aldrig_ra_hemlighet() -> None:
    """Rå text lämnar aldrig endpointen — bara redakterad data (first4…last4, safe_text)."""
    c = _klient()
    r = c.post("/inspect", content=f'{{"p":"{RA}"}}'.encode())
    assert "REALSECRET" not in r.text
    assert r.json()["analysis_status"] in ("ok", "unknown")


def test_token_kravs_nar_satt() -> None:
    c = _klient(token="hemlig")
    assert c.post("/inspect", content=b'{"p":"x"}').status_code == 401      # ingen token
    r = c.post("/inspect", content=b'{"p":"x"}', headers={"x-serrier-token": "hemlig"})
    assert r.status_code == 200


def test_path_token_variant_fungerar() -> None:
    c = _klient(token="hemlig")
    r = c.post("/t/hemlig/inspect", content=b'{"p":"x"}')
    assert r.status_code == 200
    assert c.post("/t/fel/inspect", content=b'{"p":"x"}').status_code == 401


def test_host_allowlist_mot_dns_rebinding() -> None:
    c = _klient(tillaten_host={"127.0.0.1:8788"})
    assert c.post("/inspect", content=b'{"p":"x"}',
                  headers={"host": "angripare.example"}).status_code == 403
    assert c.post("/inspect", content=b'{"p":"x"}',
                  headers={"host": "127.0.0.1:8788"}).status_code == 200


def test_for_stor_text_ger_413() -> None:
    c = _klient(max_body=100)
    assert c.post("/inspect", content=b"x" * 500).status_code == 413


def test_inspect_kolliderar_inte_med_proxy_rutter() -> None:
    """POST /inspect når inspektorn, inte /{nyckel}-catch-allen (annars 404 okänd upstream)."""
    c = _klient()
    r = c.post("/inspect", content=b'{"p":"ren"}')
    assert r.status_code == 200
    assert "handling" in r.json()                     # inspektor-svar, ej proxy-404
