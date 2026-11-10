"""`serrier run -- <kommando>`: kör ett underordnat kommando med dess AI-trafik routad genom
en lokal Guardian-proxy (Design 0002, model C). Mål: friktionsfri daglig användning.

    serrier run -- claude
    serrier run -- python my_ai_client.py

Ändrar INTE beslutskärnan och lägger ingen ny detektion. Ingen MITM. Säkerhet:
- Proxyn startas IN-PROCESS på en loopback-port; token genereras i minnet och injiceras via
  barnets base_url-path (/t/<token>/…) — syns aldrig i en process-lista (argv) och loggas ej.
- Barnet får ANTHROPIC_BASE_URL/OPENAI_BASE_URL/… mot proxyn + NO_PROXY=127.0.0.1 så dess
  loopback-trafik aldrig kapas av en ambient HTTPS_PROXY. Övriga env-variabler bevaras.
- Kan proxyn inte startas: fail-closed enligt fel-läget (strict/balanced → kör INTE barnet;
  permissive → kör oskyddat med högljudd varning).

Täckning (vad som omfattas / kan kringgå): se docs/design/0002 §2. Kort: bara barn som
respekterar base_url-env och faktiskt routar dit skyddas. En process som hårdkodar en direkt-
anslutning, struntar i env, eller använder en annan kanal kringgår proxyn. Inga falska löften
om processisolering eller fullständig nätverkstäckning.
"""

from __future__ import annotations

import os
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable

import uvicorn

from serrier.db.store import Store, standard_db_url
from serrier.guardian.policy import FailureMode
from serrier.guardian.proxy import DEFAULT_ALLOWLIST, GuardProxy, Upstream, skapa_klient


def _ledig_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _ProxyServer:
    """Kör en GuardProxy på en loopback-port i en daemon-tråd; startbar/stoppbar."""

    def __init__(self, proxy: GuardProxy, port: int) -> None:
        self._server = uvicorn.Server(uvicorn.Config(
            proxy.app(), host="127.0.0.1", port=port, log_level="warning"))
        self._tråd = threading.Thread(target=self._server.run, daemon=True)

    def starta(self, timeout: float = 5.0) -> bool:
        self._tråd.start()
        slut = time.monotonic() + timeout
        while time.monotonic() < slut:
            if self._server.started:
                return True
            time.sleep(0.02)
        return self._server.started

    def stoppa(self) -> None:
        self._server.should_exit = True
        self._tråd.join(timeout=5)


# Provider-nyckel → vilka env-variabler barnet läser sin base_url från.
_BASE_URL_ENV: dict[str, tuple[str, ...]] = {
    "anthropic": ("ANTHROPIC_BASE_URL",),
    "openai": ("OPENAI_BASE_URL", "OPENAI_API_BASE"),
    "gemini": ("GOOGLE_GEMINI_BASE_URL",),
}


def barn_env(bas_env: dict, port: int, token: str, allowlist: list[Upstream]) -> dict:
    """Barnets miljö: base_url mot proxyn (token i path), NO_PROXY för loopback, övrigt bevarat."""
    env = dict(bas_env)
    prefix = f"http://127.0.0.1:{port}/t/{token}"
    nycklar = {u.nyckel for u in allowlist}
    for nyckel, variabler in _BASE_URL_ENV.items():
        if nyckel in nycklar:
            for v in variabler:
                env[v] = f"{prefix}/{nyckel}"
    # Barnets loopback-anrop får ALDRIG gå via en ambient proxy (req 10).
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env["no_proxy"] = "127.0.0.1,localhost"
    return env


def kor(cmd: list[str], *, failure_mode: FailureMode = FailureMode.balanced,  # noqa: PLR0913
        allowlist: list[Upstream] | None = None, validera_ip: bool = True,
        timeout: float | None = None, store: object = None, org_id: str | None = None,
        klient_fabrik: Callable[[], object] = skapa_klient,
        server_fabrik: Callable[..., object] = _ProxyServer) -> int:
    """Starta proxyn, kör `cmd` med routad miljö, städa upp. Returnerar barnets exit-kod
    (eller 1 vid fail-closed proxy-start, 124 vid timeout). store+org_id → proxyn rapporterar
    REDAKTERADE prevention-events till kontrollplanet (dashboardens live-flöde, #1)."""
    allowlist = allowlist or list(DEFAULT_ALLOWLIST)
    token = secrets.token_urlsafe(24)
    port = _ledig_port()
    proxy = GuardProxy(klient=klient_fabrik(), allowlist=allowlist, failure_mode=failure_mode,
                       token=token, validera_ip=validera_ip, store=store, org_id=org_id)
    server = server_fabrik(proxy, port)

    if not server.starta():
        if failure_mode is FailureMode.permissive:
            print("serrier: VARNING — proxyn kunde inte startas; kör OSKYDDAT (permissive).",
                  file=sys.stderr)
            env = dict(os.environ)
        else:
            print("serrier: FEL — proxyn kunde inte startas; avbryter (fail-closed).",
                  file=sys.stderr)
            return 1
    else:
        env = barn_env(dict(os.environ), port, token, allowlist)

    proc = subprocess.Popen(cmd, env=env)  # noqa: S603 — argv, ingen shell
    _tidigare = {s: signal.signal(s, lambda sig, _f: proc.send_signal(sig))
                 for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return 124
    finally:
        for s, h in _tidigare.items():
            signal.signal(s, h)
        server.stoppa()


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] != "run" or "--" not in argv:
        print("användning: serrier run -- <kommando> [args...]", file=sys.stderr)
        return 2
    cmd = argv[argv.index("--") + 1:]
    if not cmd:
        print("serrier: inget kommando angivet efter --", file=sys.stderr)
        return 2
    mode = FailureMode(os.environ.get("SERRIER_PROXY_FAILURE_MODE", "balanced"))
    # Dela DB med backend → prevention-events hamnar i dashboardens live-flöde (#1).
    # Fel här får aldrig hindra att skyddet startar.
    store = org_id = None
    try:
        store = Store(standard_db_url())
        org_id = store.dev_org()
    except Exception as e:
        print(f"serrier: (events av — {type(e).__name__})", file=sys.stderr)
    return kor(cmd, failure_mode=mode, store=store, org_id=org_id)


if __name__ == "__main__":
    sys.exit(main())
