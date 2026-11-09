"""Always-on Guardian-daemon (Design 0004, steg 1).

    serrier up       # starta beständig proxy på fast loopback-port + stabil token
    serrier status   # igång? port?
    serrier down      # stoppa + städa

`up` skriver ~/.serrier/env.sh — `source` den, så pekar dina AI-verktygs base_url på proxyn
(skyddet AGERAR så länge daemonen kör). Besluten syns i dashboardens live-flöde (#1).

Härdat för alltid-på (0004 §4): loopback-only · stabil token i 0600-fil · Host-allowlist mot
DNS-rebinding. Ingen MITM: täcker BARA verktyg som routas genom proxyn (se 0004 §2) — MCP,
godtycklig HTTP och DNS-egress omfattas inte.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

import uvicorn

from serrier.db.store import Store
from serrier.guardian.policy import FailureMode
from serrier.guardian.proxy import DEFAULT_ALLOWLIST, GuardProxy, Upstream, skapa_klient
from serrier.guardian.run import _BASE_URL_ENV

_DIR = Path(os.environ.get("SERRIER_HOME", str(Path.home() / ".serrier")))
_PID = _DIR / "daemon.pid"
_ENV = _DIR / "env.sh"
_TOKEN_FIL = _DIR / "proxy-token"
_LOGG = _DIR / "daemon.log"


def _port() -> int:
    return int(os.environ.get("SERRIER_PROXY_PORT", "8788"))


def stabil_token() -> str:
    """Token som ÖVERLEVER omstarter (persisterad 0600-fil) så verktygs-configen förblir giltig.
    Skrivs med behörighet 0600 — bara ägaren kan läsa den."""
    _DIR.mkdir(parents=True, exist_ok=True)
    if _TOKEN_FIL.exists():
        return _TOKEN_FIL.read_text().strip()
    token = secrets.token_urlsafe(24)
    _TOKEN_FIL.touch(mode=stat.S_IRUSR | stat.S_IWUSR, exist_ok=True)   # 0600
    _TOKEN_FIL.chmod(stat.S_IRUSR | stat.S_IWUSR)
    _TOKEN_FIL.write_text(token)
    return token


def tillaten_host(port: int) -> set[str]:
    return {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}


def env_innehall(port: int, token: str, allowlist: list[Upstream]) -> str:
    """Innehållet i env.sh: base_url mot proxyn (token i path) + NO_PROXY. Källa: `source` den."""
    prefix = f"http://127.0.0.1:{port}/t/{token}"
    rader = ["# Serrier always-on — source: `source ~/.serrier/env.sh`"]
    for u in allowlist:
        for var in _BASE_URL_ENV.get(u.nyckel, ()):
            rader.append(f'export {var}="{prefix}/{u.nyckel}"')
    rader += ['export NO_PROXY="127.0.0.1,localhost"', 'export no_proxy="127.0.0.1,localhost"']
    return "\n".join(rader) + "\n"


def ar_igang() -> int | None:
    """Daemonens pid om den lever, annars None (och städar en stale pid-fil)."""
    if not _PID.exists():
        return None
    try:
        pid = int(_PID.read_text().strip())
        os.kill(pid, 0)                  # signal 0 = finns processen?
    except (ValueError, OSError):
        return None
    return pid


def _vanta_port(port: int, timeout: float = 5.0) -> bool:
    slut = time.monotonic() + timeout
    while time.monotonic() < slut:
        with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), 0.2):
            return True
        time.sleep(0.1)
    return False


def serve(port: int) -> None:
    """Körs i den DETACHADE processen: beständig GuardProxy på loopback (host-allowlist + token),
    delar DB med backend → events i dashboarden."""
    token = stabil_token()
    store = org_id = None
    with contextlib.suppress(Exception):
        store = Store(os.environ.get("SERRIER_DB_URL", "sqlite:///serrier.db"))
        org_id = store.dev_org()
    mode = FailureMode(os.environ.get("SERRIER_PROXY_FAILURE_MODE", "balanced"))
    proxy = GuardProxy(klient=skapa_klient(), failure_mode=mode, token=token,
                       tillaten_host=tillaten_host(port), store=store, org_id=org_id)
    uvicorn.run(proxy.app(), host="127.0.0.1", port=port, log_level="warning")


def up() -> int:
    if ar_igang():
        print(f"serrier: redan igång (port {_port()}). `source {_ENV}` och kör ditt verktyg.")
        return 0
    port = _port()
    token = stabil_token()
    _ENV.write_text(env_innehall(port, token, DEFAULT_ALLOWLIST))
    with _LOGG.open("a") as logg:
        proc = subprocess.Popen(  # noqa: S603 — argv, ingen shell; startar den egna serve-processen
            [sys.executable, "-m", "serrier.guardian.daemon", "serve", str(port)],
            stdout=logg, stderr=logg, start_new_session=True)
    _PID.write_text(str(proc.pid))
    if not _vanta_port(port):
        print(f"serrier: FEL — daemonen svarade inte på :{port} (se {_LOGG})", file=sys.stderr)
        return 1
    print(f"""serrier: AGERAR nu — Guardian lyssnar på 127.0.0.1:{port}
  Aktivera i ett skal:  source {_ENV}
  Sen kör som vanligt:  claude     (eller valfritt AI-verktyg)
  Live-vy:              http://localhost:3000/guard   (kräver `make dev`)
  Stoppa:               serrier down

  Täckning: BARA verktyg som pekar sin base_url hit (anthropic/openai/gemini). Ingen MITM —
  MCP, godtycklig HTTP och DNS-egress omfattas inte.""")
    return 0


def _stada() -> None:
    for f in (_PID, _ENV):
        with contextlib.suppress(OSError):
            f.unlink()


def down() -> int:
    pid = ar_igang()
    if not pid:
        print("serrier: inte igång.")
        _stada()
        return 0
    with contextlib.suppress(OSError):
        os.kill(pid, signal.SIGTERM)
    for _ in range(50):
        if ar_igang() is None:
            break
        time.sleep(0.1)
    _stada()
    print("serrier: stoppad.")
    return 0


def status() -> int:
    pid = ar_igang()
    if pid:
        print(f"serrier: igång (pid {pid}, port {_port()}). Aktivera: source {_ENV}")
    else:
        print("serrier: inte igång. Starta med `serrier up`.")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "serve":          # intern: den detachade processen
        serve(int(argv[1]))
        return 0
    return {"up": up, "down": down, "status": status}.get(argv[0] if argv else "", lambda: 2)()


if __name__ == "__main__":
    sys.exit(main())
