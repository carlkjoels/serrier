"""Guardian loopback-proxy (steg 6). Prevention-verifiering mot den KONTROLLERADE
upstreamen (bytes-räknare): bevisar leak-through = 0 för blockerade fall, byte-identisk
genomfart för ren trafik, säker JSON-omskrivning vid redact, och SSRF/DNS-rebinding/
allowlist-skydd. Ingen osäkrad genväg: SSRF-guarden kör sin RIKTIGA logik, DNS matas
deterministiskt via monkeypatch. Syntetisk data."""

import base64
import socket

import httpx
from starlette.testclient import TestClient
from upstream_harness import KontrolleradUpstream

import serrier.guardian.inspect as im
from serrier.db.store import Store
from serrier.guardian.enforcement import EnforcementAdapter, EnforcementLevel
from serrier.guardian.policy import FailureMode, policy_fran_dict
from serrier.guardian.proxy import GuardProxy, Upstream, validerad_ip

RA = "sk-ant-api03-REALSECRET1234567890abcDEF"
KORT = "4111 1111 1111 1111"
ALLOW = [Upstream("test", "https://upstream.test")]


def _publik_dns(monkeypatch, ip: str = "93.184.216.34") -> None:
    """Mata SSRF-guarden en deterministisk PUBLIK adress (guardens logik kör på riktigt)."""
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))])


def _rigga(monkeypatch, *, failure_mode=FailureMode.balanced, validera_ip=True, **kw):
    up = KontrolleradUpstream()
    klient = httpx.AsyncClient(transport=httpx.ASGITransport(app=up.app()))
    px = GuardProxy(klient=klient, allowlist=ALLOW, failure_mode=failure_mode,
                    validera_ip=validera_ip, **kw)
    return up, TestClient(px.app()), px


# --- SSRF-guard som riktig enhet (pinnar validerad IP, TOCTOU-fix) --------
def test_ssrf_guard_avvisar_privat_och_loopback() -> None:
    assert validerad_ip("localhost") is None              # → 127.0.0.1 (privat)
    assert validerad_ip("nonexistent.invalid.") is None   # resolvfel → fail-closed


def test_ssrf_guard_slapper_global_och_pinnar_ip(monkeypatch) -> None:
    _publik_dns(monkeypatch)
    assert validerad_ip("upstream.test") == "93.184.216.34"   # returnerar IP att pinna


def test_ssrf_guard_avvisar_dns_rebinding_till_privat(monkeypatch) -> None:
    _publik_dns(monkeypatch, ip="10.0.0.5")               # allowlistad host → privat IP
    assert validerad_ip("upstream.test") is None


# --- prevention: leak-through = 0 -----------------------------------------
def test_block_stoppar_bytes_leakthrough_noll(monkeypatch) -> None:
    _publik_dns(monkeypatch)
    up, c, px = _rigga(monkeypatch)
    r = c.post("/test/v1/messages", content=f'{{"p":"{RA}"}}'.encode())
    assert r.status_code == 403
    assert r.json()["serrier"] == "blocked"
    assert up.antal_bytes == 0                             # LEAK-THROUGH = 0
    assert up.innehaller(RA.encode()) is False
    assert px.audit[-1]["handling"] == "block"


def test_ren_trafik_gar_igenom_byte_identisk(monkeypatch) -> None:
    _publik_dns(monkeypatch)
    up, c, _ = _rigga(monkeypatch)
    body = b'{"msg":"ett helt vanligt meddelande"}'
    r = c.post("/test/v1/messages", content=body)
    assert r.status_code == 200
    assert len(up.mottaget) == 1
    assert up.mottaget[0]["body"] == body                 # byte-identisk
    assert up.mottaget[0]["path"] == "/v1/messages"


def test_redact_skriver_om_json_och_skickar_sanerat(monkeypatch) -> None:
    _publik_dns(monkeypatch)
    up, c, _ = _rigga(monkeypatch)
    r = c.post("/test/v1/messages", content=f'{{"msg":"kort {KORT}"}}'.encode())
    assert r.status_code == 200
    assert up.innehaller(KORT.encode()) is False          # kortet nådde ALDRIG upstream
    assert b"[redacted:credit-card]" in up.mottaget[0]["body"]   # men requesten gick fram


def test_redact_degraderar_till_block_nar_ej_json(monkeypatch) -> None:
    _publik_dns(monkeypatch)
    up, c, _ = _rigga(monkeypatch)
    r = c.post("/test/v1/messages", content=f"kort {KORT}".encode())   # ej JSON
    assert r.status_code == 403
    assert up.antal_bytes == 0                             # sanerade ej → block, inget läckte


# --- allowlist & SSRF i proxy-flödet --------------------------------------
def test_okand_upstream_404_inget_lacker(monkeypatch) -> None:
    _publik_dns(monkeypatch)
    up, c, _ = _rigga(monkeypatch)
    r = c.post("/okand/v1/x", content=b'{"a":1}')
    assert r.status_code == 404
    assert up.antal_bytes == 0


def test_proxy_avvisar_privat_upstream_ssrf(monkeypatch) -> None:
    _publik_dns(monkeypatch, ip="127.0.0.1")              # upstream resolvar privat
    up, c, _ = _rigga(monkeypatch)
    r = c.post("/test/v1/messages", content=b'{"msg":"ren text"}')
    assert r.status_code == 502
    assert up.antal_bytes == 0                             # aldrig vidarebefordrat


# --- UNKNOWN-honesty -------------------------------------------------------
def test_unknown_blockeras_och_markt_aldrig_inspekterat(monkeypatch) -> None:
    _publik_dns(monkeypatch)
    def spräng(_text):
        raise RuntimeError("detektorn kraschade")
    monkeypatch.setattr(im, "detektera_kanslig", spräng)
    up, c, px = _rigga(monkeypatch, failure_mode=FailureMode.strict)
    r = c.post("/test/v1/messages", content=b'{"msg":"x"}')
    assert r.status_code == 403                            # strict → fail-closed
    assert up.antal_bytes == 0
    assert px.audit[-1]["analysis_status"] == "unknown"   # aldrig 'ok'/'inspekterat'


def test_leakthrough_noll_over_batteri(monkeypatch) -> None:
    """HEADLINE-BEVIS: ett batteri känsliga payloads (inkl. evasions) genom proxyn →
    upstream tar emot NOLL bytes totalt. Leak-through = 0 (Design 0002 DoD)."""
    _publik_dns(monkeypatch)
    payloads = [
        f'{{"p":"{RA}"}}'.encode(),                                  # rak hemlighet
        f'{{"p":"{base64.b64encode(RA.encode()).decode()}"}}'.encode(),  # base64
        ('{"p":"' + " ".join(RA) + '"}').encode(),                   # mellanslag
        f"kort {KORT}".encode(),                                     # redact-degraderad (ej JSON)
        '{"p":"sk-ant-\u200b-api03-REALSECRET1234567890abcDEF"}'.encode(),  # zero-width
    ]
    up, c, _ = _rigga(monkeypatch)
    svar = [c.post("/test/v1/messages", content=p).status_code for p in payloads]
    assert all(s in (403,) for s in svar), svar      # alla blockerade
    assert up.antal_bytes == 0                        # LEAK-THROUGH = 0 över hela batteriet
    assert len(up.mottaget) == 0


# --- härdning (P0/P1) ------------------------------------------------------
def test_loopback_auth_token_kravs(monkeypatch) -> None:
    _publik_dns(monkeypatch)
    up, c, _ = _rigga(monkeypatch, token="hemlig-token")
    # utan token → 401, inget vidarebefordrat
    r = c.post("/test/v1/messages", content=b'{"msg":"ren"}')
    assert r.status_code == 401
    assert up.antal_bytes == 0
    # fel token → 401
    assert c.post("/test/v1/messages", content=b'{"msg":"ren"}',
                  headers={"X-Serrier-Token": "fel"}).status_code == 401
    # rätt token → igenom
    r = c.post("/test/v1/messages", content=b'{"msg":"ren"}',
               headers={"X-Serrier-Token": "hemlig-token"})
    assert r.status_code == 200
    assert up.antal_bytes > 0


def test_policy_koppling_till_org(monkeypatch) -> None:
    _publik_dns(monkeypatch)
    store = Store("sqlite:///:memory:")
    org = store.skapa_org("t")
    up = KontrolleradUpstream()
    klient = httpx.AsyncClient(transport=httpx.ASGITransport(app=up.app()))
    px = GuardProxy(klient=klient, allowlist=ALLOW, store=store, org_id=org)
    c = TestClient(px.app())
    body = f'{{"msg":"kort {KORT}"}}'.encode()
    # default org-policy: kort (high) → redact → forward sanerat
    assert c.post("/test/v1/messages", content=body).status_code == 200
    assert up.innehaller(KORT.encode()) is False
    # skärp org-policyn: high → block
    store.satt_guard_policy(org, policy_fran_dict({"high": "block"}), FailureMode.balanced)
    assert c.post("/test/v1/messages", content=body).status_code == 403   # nu blockerat


def test_body_for_stor_avvisas(monkeypatch) -> None:
    _publik_dns(monkeypatch)
    up, c, _ = _rigga(monkeypatch, max_body=100)
    r = c.post("/test/v1/messages", content=b"x" * 500)
    assert r.status_code == 413
    assert up.antal_bytes == 0                             # inspekterades/forwardades aldrig


# --- kontrakt --------------------------------------------------------------
def test_proxy_uppfyller_enforcement_kontraktet() -> None:
    px = GuardProxy(klient=httpx.AsyncClient(), allowlist=ALLOW)
    assert isinstance(px, EnforcementAdapter)
    assert px.enforcement_level == EnforcementLevel.guaranteed
    assert px.covered_paths()                             # icke-tom täckningsgräns
