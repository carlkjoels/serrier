"""CLI-wrapper `serrier run` (model C). Enhet: argv-parsning, barn-env, fail-closed. Och
INTEGRATION med ett riktigt barn-process över verkligt TCP: clean/BLOCK/REDACT + att barnet
inte ärver en osäker ambient proxy. Syntetisk data."""

from __future__ import annotations

import sys
from pathlib import Path

from upstream_harness import KontrolleradUpstream, LiveServer, ledig_port

from serrier.guardian.policy import FailureMode
from serrier.guardian.proxy import Upstream
from serrier.guardian.run import barn_env, kor, main

RA = "sk-ant-api03-REALSECRET1234567890abcDEF"
KORT = "4111 1111 1111 1111"
SIM = str(Path(__file__).parent / "_ai_klient_sim.py")
ALLOW_LOKAL = None   # sätts per test mot upstream-porten


# --- enhet -----------------------------------------------------------------
def test_main_anvandning() -> None:
    assert main([]) == 2
    assert main(["run"]) == 2               # inget --
    assert main(["run", "--"]) == 2         # inget kommando


def test_barn_env_routar_och_skyddar(monkeypatch) -> None:
    monkeypatch.setenv("MIN_EGEN", "bevara-mig")
    allow = [Upstream("anthropic", "https://api.anthropic.com"),
             Upstream("openai", "https://api.openai.com")]
    env = barn_env(dict_env := {"MIN_EGEN": "bevara-mig"}, 8787, "TOK", allow)
    assert env["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:8787/t/TOK/anthropic"
    assert env["OPENAI_BASE_URL"] == "http://127.0.0.1:8787/t/TOK/openai"
    assert env["NO_PROXY"] == "127.0.0.1,localhost"      # loopback ej via ambient proxy (req 10)
    assert env["MIN_EGEN"] == "bevara-mig"               # övriga env bevaras
    assert "GOOGLE_GEMINI_BASE_URL" not in env           # ej i allowlist → ej satt
    assert dict_env  # (behåll referens)


class _FailServer:
    def __init__(self, *_a) -> None: ...
    def starta(self, timeout: float = 5.0) -> bool:
        return False
    def stoppa(self) -> None: ...


def test_fail_closed_strict_kor_inte_barnet(tmp_path: Path) -> None:
    markor = tmp_path / "RAN"
    cmd = [sys.executable, "-c", f"open({str(markor)!r},'w').write('x')"]
    rc = kor(cmd, failure_mode=FailureMode.strict, server_fabrik=_FailServer)
    assert rc == 1                                        # fail-closed
    assert not markor.exists()                            # barnet kördes ALDRIG


def test_fail_open_permissive_kor_barnet_oskyddat(tmp_path: Path) -> None:
    markor = tmp_path / "RAN"
    cmd = [sys.executable, "-c", f"open({str(markor)!r},'w').write('x')"]
    rc = kor(cmd, failure_mode=FailureMode.permissive, server_fabrik=_FailServer)
    assert rc == 0
    assert markor.exists()                               # kördes (oskyddat, med varning)


# --- integration: riktigt barn-process + TCP -------------------------------
def _kor_sim(monkeypatch, body: str, up_port: int, **env) -> int:
    monkeypatch.setenv("SIM_BODY", body)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    allow = [Upstream("anthropic", f"http://127.0.0.1:{up_port}")]
    return kor([sys.executable, SIM], allowlist=allow, validera_ip=False)


def test_integration_clean_block_redact(monkeypatch) -> None:
    up = KontrolleradUpstream()
    up_port = ledig_port()
    with LiveServer(up.app(), up_port):
        # CLEAN → barnet får 200 (exit 0), upstream fick trafiken
        rc = _kor_sim(monkeypatch, '{"msg":"helt vanligt"}', up_port)
        assert rc == 0
        assert up.antal_bytes > 0

        # BLOCK → barnet får 403 (exit 3), upstream fick INGET nytt
        bytes_innan = up.antal_bytes
        rc = _kor_sim(monkeypatch, f'{{"p":"{RA}"}}', up_port)
        assert rc == 3
        assert up.antal_bytes == bytes_innan             # inget läckte
        assert up.innehaller(RA.encode()) is False

        # REDACT → barnet får 200, men kortet nådde aldrig upstream
        rc = _kor_sim(monkeypatch, f'{{"msg":"kort {KORT}"}}', up_port)
        assert rc == 0
        assert up.innehaller(KORT.encode()) is False


def test_integration_ignorerar_ambient_proxy(monkeypatch) -> None:
    # Ambient HTTPS_PROXY (trasig) får inte hindra barnets loopback-anrop (NO_PROXY, req 10).
    up = KontrolleradUpstream()
    up_port = ledig_port()
    with LiveServer(up.app(), up_port):
        rc = _kor_sim(monkeypatch, '{"msg":"ren"}', up_port,
                      HTTPS_PROXY="http://127.0.0.1:1", HTTP_PROXY="http://127.0.0.1:1")
        assert rc == 0                                   # nådde ändå fram
        assert up.antal_bytes > 0
