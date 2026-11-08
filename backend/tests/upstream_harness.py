"""Kontrollerad upstream för prevention-verifiering (Design 0002 §7). Står in för
api.anthropic.com m.fl. och REGISTRERAR exakt vilka bytes varje request-body bar. Så kan
vi bevisa att BLOCK stoppar bytes FÖRE upstream (leak-through = 0) och att ren trafik når
fram byte-identisk. Ren testharness — ingen produktionskod."""

from __future__ import annotations

from dataclasses import dataclass, field

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


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
