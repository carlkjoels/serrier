"""End-to-end över VERKLIGT TCP (inte injicerad ASGI-transport). Startar den kontrollerade
upstreamen OCH proxyn på riktiga loopback-portar via uvicorn, och kör en RIKTIG httpx-klient
genom proxyn. Bevisar att BLOCK och byte-identisk genomfart håller över faktiska HTTP-
anslutningar — samt stora bodies, chunked transfer, oväntade headers, redirect-icke-följning
och env-proxy-isolering.

OBS: upstreamen är localhost (privat IP). SSRF/privat-IP-guarden avvisar korrekt privata
adresser och testas som riktig enhet i test_guardian_proxy.py; här sätts validera_ip=False
för att isolera FORWARD-axeln (verklig TCP). BLOCK-vägen når ändå aldrig guarden. Detta är
ingen osäkrad genväg — det är ett annat testområde. Syntetisk data."""

from __future__ import annotations

import socket
import threading
import time

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from upstream_harness import KontrolleradUpstream

from serrier.guardian.proxy import GuardProxy, Upstream, skapa_klient

RA = "sk-ant-api03-REALSECRET1234567890abcDEF"


def _ledig_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _Live:
    """Kör en ASGI-app på en riktig loopback-port i en tråd (verklig TCP)."""

    def __init__(self, app, port: int) -> None:
        self._server = uvicorn.Server(uvicorn.Config(
            app, host="127.0.0.1", port=port, log_level="warning"))
        self._tråd = threading.Thread(target=self._server.run, daemon=True)

    def __enter__(self) -> _Live:
        self._tråd.start()
        for _ in range(500):
            if self._server.started:
                break
            time.sleep(0.01)
        return self

    def __exit__(self, *_a) -> None:
        self._server.should_exit = True
        self._tråd.join(timeout=5)


def _redir_upstream(rec: KontrolleradUpstream) -> Starlette:
    """Upstream som spelar in bytes OCH svarar 302 mot intern host på /redir."""
    async def handler(request: Request) -> Response:
        body = await request.body()
        rec.mottaget.append({"method": request.method, "path": request.url.path,
                             "body": body, "headers": dict(request.headers)})
        if request.url.path.endswith("/redir"):
            return Response(status_code=302, headers={"location": "http://10.0.0.9/intern"})
        return JSONResponse({"ok": True})
    return Starlette(routes=[Route("/{p:path}", handler, methods=["GET", "POST"])])


def _proxy(up_port: int, **kw) -> GuardProxy:
    allow = [Upstream("test", f"http://127.0.0.1:{up_port}")]
    # validera_ip=False: upstream är localhost (se modulens docstring); FORWARD-axeln testas.
    return GuardProxy(klient=skapa_klient(), allowlist=allow, validera_ip=False, **kw)


def test_e2e_block_clean_large_chunked_headers() -> None:
    up = KontrolleradUpstream()
    up_port, px_port = _ledig_port(), _ledig_port()
    with _Live(up.app(), up_port), _Live(_proxy(up_port).app(), px_port):
        base = f"http://127.0.0.1:{px_port}/test/v1/messages"
        c = httpx.Client(timeout=10)

        # 1. BLOCK över verklig TCP — upstream får inget
        r = c.post(base, content=f'{{"p":"{RA}"}}'.encode())
        assert r.status_code == 403
        assert up.antal_bytes == 0

        # 2. Ren trafik — byte-identisk över nätet
        body = b'{"msg":"verklig tcp foerst"}'
        r = c.post(base, content=body)
        assert r.status_code == 200
        assert up.mottaget[-1]["body"] == body

        # 3. Stor body (~1 MB) — byte-identisk
        stor = b'{"d":"' + b"a" * 1_000_000 + b'"}'
        r = c.post(base, content=stor)
        assert r.status_code == 200
        assert up.mottaget[-1]["body"] == stor

        # 4. Chunked transfer (ingen Content-Length) — generator → httpx chunkar
        def chunks():
            yield b'{"msg":"'
            yield b'chunkad-ren"}'
        r = c.post(base, content=chunks())
        assert r.status_code == 200
        assert up.mottaget[-1]["body"] == b'{"msg":"chunkad-ren"}'

        # 5. Oväntade headers — custom header vidarebefordras. (Hop-by-hop som Connection
        # stryps från KLIENTENS set; forward-klienten sätter sin egen per hopp — korrekt.)
        r = c.post(base, content=b'{"a":1}',
                   headers={"X-Konstig": "xyz", "Connection": "keep-alive"})
        assert r.status_code == 200
        assert up.mottaget[-1]["headers"].get("x-konstig") == "xyz"


def test_e2e_redirect_foljs_inte() -> None:
    up = KontrolleradUpstream()
    up_port, px_port = _ledig_port(), _ledig_port()
    with _Live(_redir_upstream(up), up_port), _Live(_proxy(up_port).app(), px_port):
        c = httpx.Client(timeout=10)
        r = c.post(f"http://127.0.0.1:{px_port}/test/redir", content=b'{"a":1}')
        # Proxyn följer ALDRIG redirect (→ intern host = SSRF); 302 returneras rått
        assert r.status_code == 302
        assert r.headers.get("location") == "http://10.0.0.9/intern"


def test_e2e_ignorerar_ambient_https_proxy(monkeypatch) -> None:
    # En fientlig/trasig HTTPS_PROXY i miljön får INTE kapa Serriers forward (trust_env=False).
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    up = KontrolleradUpstream()
    up_port, px_port = _ledig_port(), _ledig_port()
    with _Live(up.app(), up_port), _Live(_proxy(up_port).app(), px_port):
        c = httpx.Client(timeout=10, trust_env=False)
        r = c.post(f"http://127.0.0.1:{px_port}/test/v1/x", content=b'{"msg":"ren"}')
        assert r.status_code == 200                        # forward lyckades trots env-proxy
        assert up.antal_bytes > 0
