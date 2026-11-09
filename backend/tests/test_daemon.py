"""Always-on Guardian-daemon (Design 0004, steg 1). Testar de deterministiska delarna + Host-
allowlist-härdningen; up/down/status live-röktestas separat. Syntetisk data."""

import os

import httpx
from fastapi.testclient import TestClient
from upstream_harness import KontrolleradUpstream

from serrier.guardian import daemon
from serrier.guardian.proxy import DEFAULT_ALLOWLIST, GuardProxy, Upstream


def _flytta_hem(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(daemon, "_DIR", tmp_path)
    monkeypatch.setattr(daemon, "_PID", tmp_path / "daemon.pid")
    monkeypatch.setattr(daemon, "_ENV", tmp_path / "env.sh")
    monkeypatch.setattr(daemon, "_TOKEN_FIL", tmp_path / "proxy-token")


# --- env.sh-innehåll ------------------------------------------------------
def test_env_innehall_routar_och_skyddar() -> None:
    s = daemon.env_innehall(8788, "TOK", list(DEFAULT_ALLOWLIST))
    assert 'export ANTHROPIC_BASE_URL="http://127.0.0.1:8788/t/TOK/anthropic"' in s
    assert 'export OPENAI_BASE_URL="http://127.0.0.1:8788/t/TOK/openai"' in s
    assert 'export NO_PROXY="127.0.0.1,localhost"' in s


# --- stabil token (0600, överlever) ---------------------------------------
def test_stabil_token_0600_och_aterbruk(monkeypatch, tmp_path) -> None:
    _flytta_hem(monkeypatch, tmp_path)
    t1 = daemon.stabil_token()
    assert oct((tmp_path / "proxy-token").stat().st_mode & 0o777) == "0o600"
    assert daemon.stabil_token() == t1               # samma över omstart


# --- Host-allowlist (DNS-rebinding-skydd) ---------------------------------
def test_host_allowlist() -> None:
    assert daemon.tillaten_host(8788) == {"127.0.0.1:8788", "localhost:8788", "[::1]:8788"}


def test_proxy_avvisar_otillaten_host() -> None:
    up = KontrolleradUpstream()
    klient = httpx.AsyncClient(transport=httpx.ASGITransport(app=up.app()))
    px = GuardProxy(klient=klient, allowlist=[Upstream("test", "https://u.test")],
                    validera_ip=False, tillaten_host={"127.0.0.1:8788"})
    c = TestClient(px.app())
    # TestClients default-Host ('testserver') är inte i allowlisten → 403 (rebinding-skydd)
    assert c.post("/test/v1/x", content=b'{"m":"ren"}').status_code == 403
    assert up.antal_bytes == 0
    # rätt loopback-Host → släpps igenom
    r = c.post("/test/v1/x", content=b'{"m":"ren"}', headers={"host": "127.0.0.1:8788"})
    assert r.status_code == 200


# --- status/down utan daemon ----------------------------------------------
def test_ar_igang_och_down_utan_daemon(monkeypatch, tmp_path) -> None:
    _flytta_hem(monkeypatch, tmp_path)
    assert daemon.ar_igang() is None                 # ingen pid-fil
    (tmp_path / "daemon.pid").write_text("999999999")  # död pid
    assert daemon.ar_igang() is None
    assert daemon.down() == 0                         # idempotent
    # levande pid (vår egen process) → ar_igang hittar den
    (tmp_path / "daemon.pid").write_text(str(os.getpid()))
    assert daemon.ar_igang() == os.getpid()
