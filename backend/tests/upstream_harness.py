"""Kontrollerad upstream för prevention-verifiering (Design 0002 §7). Står in för
api.anthropic.com m.fl. och REGISTRERAR exakt vilka bytes varje request-body bar. Så kan
vi bevisa att BLOCK stoppar bytes FÖRE upstream (leak-through = 0) och att ren trafik når
fram byte-identisk. Ren testharness — ingen produktionskod."""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


def ledig_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class LiveServer:
    """Kör en ASGI-app på en riktig loopback-port i en tråd (verklig TCP) — för e2e-tester."""

    def __init__(self, app, port: int) -> None:
        self._server = uvicorn.Server(uvicorn.Config(
            app, host="127.0.0.1", port=port, log_level="warning"))
        self._tråd = threading.Thread(target=self._server.run, daemon=True)

    def __enter__(self) -> LiveServer:
        self._tråd.start()
        for _ in range(500):
            if self._server.started:
                break
            time.sleep(0.01)
        return self

    def __exit__(self, *_a) -> None:
        self._server.should_exit = True
        self._tråd.join(timeout=5)


@dataclass
class KontrolleradUpstream:
    """Räknar varje mottagen request-body. `mottaget` = fullständig logg; `antal_bytes` =
    summan. Om BLOCK fungerar ska inga känsliga bytes någonsin dyka upp här."""
    mottaget: list[dict] = field(default_factory=list)

    def app(self) -> Starlette:
        async def handler(request: Request) -> JSONResponse:
            body = await request.body()
            self.mottaget.append({
                "method": request.method,
                "path": request.url.path,
                "body": body,                          # exakta bytes
                "headers": dict(request.headers),
            })
            return JSONResponse({"ok": True, "mottog_bytes": len(body)})

        return Starlette(routes=[Route(
            "/{rest:path}", handler,
            methods=["GET", "POST", "PUT", "DELETE", "PATCH"])])

    @property
    def antal_bytes(self) -> int:
        return sum(len(m["body"]) for m in self.mottaget)

    def innehaller(self, fragment: bytes) -> bool:
        """Dök det här (känsliga) fragmentet någonsin upp hos upstream? Ska vara False
        för blockerade fall."""
        return any(fragment in m["body"] for m in self.mottaget)
