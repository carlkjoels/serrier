"""Guardian enforcement-adapter: explicit loopback-proxy (Design 0002, steg 6). Klienten
pekar sin base_url på http://127.0.0.1:PORT/<nyckel>; proxyn inspekterar body:n LOKALT,
verkställer verdiktet, och vidarebefordrar bara ren/sanerad trafik till en ALLOWLISTAD
upstream som en verifierande TLS-klient.

Låsta säkerhetsbeslut (0002): loopback-only · strikt allowlist · ingen MITM · ingen rå body
i logg · UNKNOWN aldrig 'inspekterat' · proxy-fel = fail-closed · REDACT = säker JSON-
omskrivning annars BLOCK · leak-through = 0. Extra skydd: SSRF/privata IP/DNS-rebinding
(upstream måste resolva till globala adresser), inga redirects, TLS-verifiering på.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from serrier.guardian.enforcement import EnforcementLevel, ProxyHandling, handling_for
from serrier.guardian.inspect import GuardDecision, inspect
from serrier.guardian.policy import STANDARD, FailureMode, Policy


@dataclass(frozen=True)
class Upstream:
    nyckel: str       # route-nyckel i klientens base_url, t.ex. "anthropic"
    bas: str          # "https://api.anthropic.com"


# Bekräftad initial allowlist (strikt). Ingen wildcard. Utbyggbar via konstruktorn.
DEFAULT_ALLOWLIST: list[Upstream] = [
    Upstream("anthropic", "https://api.anthropic.com"),
    Upstream("openai", "https://api.openai.com"),
    Upstream("gemini", "https://generativelanguage.googleapis.com"),
]

# Hop-by-hop + headers vi aldrig vidarebefordrar (httpx sätter Host/Content-Length själv).
_SLOPPA_HEADERS = {"host", "content-length", "connection", "proxy-connection",
                   "keep-alive", "transfer-encoding", "te", "trailer", "upgrade"}


def losa_och_validera(host: str) -> bool:
    """SSRF/DNS-rebinding-skydd: upstream måste resolva till ENBART globala (publika) IP.
    Privata/loopback/link-local/reserverade → avvisa. Resolvfel → avvisa (fail-closed)."""
    try:
        infon = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError):
        return False
    adresser = {info[4][0] for info in infon}
    if not adresser:
        return False
    for a in adresser:
        try:
            ip = ipaddress.ip_address(a.split("%")[0])     # strippa ev. zon-id
        except ValueError:
            return False
        if not ip.is_global:
            return False
    return True


def _sanera_json(body: bytes, decision: GuardDecision) -> bytes | None:
    """REDACT-and-forward: skriv om body till safe_text OM resultatet fortfarande är giltig
    JSON OCH inga oredakterbara (evasion, -1) träffar finns. Annars None → degradera till
    BLOCK (skicka aldrig en body vi inte kunde sanera rent)."""
    if any(f.start < 0 for f in decision.findings):
        return None                                        # evasion kvar i safe_text → block
    try:
        json.loads(decision.safe_text)                     # måste förbli giltig JSON
    except (json.JSONDecodeError, ValueError):
        return None
    return decision.safe_text.encode("utf-8")


@dataclass
class GuardProxy:
    """Explicit loopback-proxy. `klient` = httpx.AsyncClient (prod: verify=True,
    follow_redirects=False); injiceras i test mot den kontrollerade upstreamen."""
    klient: httpx.AsyncClient
    allowlist: list[Upstream] = field(default_factory=lambda: list(DEFAULT_ALLOWLIST))
    failure_mode: FailureMode = FailureMode.balanced
    policy: Policy = STANDARD
    validera_ip: bool = True
    audit: list[dict] = field(default_factory=list)

    namn: str = "local-proxy"
    enforcement_level: EnforcementLevel = EnforcementLevel.guaranteed

    def covered_paths(self) -> list[str]:
        return [f"explicit loopback-routad HTTP(S) till allowlistad upstream: {u.nyckel} "
                f"→ {u.bas}" for u in self.allowlist]

    def _upstream(self, nyckel: str) -> Upstream | None:
        return next((u for u in self.allowlist if u.nyckel == nyckel), None)

    def _logga(self, upstream: str, handling: str, d: GuardDecision, bytes_fram: int) -> None:
        # ALDRIG rå body — bara verdikt + redakterade findings (findings bär first4…last4).
        self.audit.append({
            "upstream": upstream, "handling": handling, "action": d.action.value,
            "analysis_status": d.analysis_status.value,
            "findings": [{"regel": f.regel, "redacted": f.redacted} for f in d.findings],
            "bytes_vidarebefordrade": bytes_fram,
        })

    def _block_svar(self, d: GuardDecision, detalj: str) -> JSONResponse:
        return JSONResponse(status_code=403, content={
            "serrier": "blocked", "detalj": detalj, "action": d.action.value,
            "analysis_status": d.analysis_status.value,
            "reasons": [r.forklaring for r in d.reasons]})

    async def _hantera(self, request: Request) -> Response:
        nyckel = request.path_params["nyckel"]
        upstream = self._upstream(nyckel)
        if upstream is None:
            return JSONResponse(status_code=404,
                                content={"serrier": "okänd upstream", "nyckel": nyckel})

        body = await request.body()
        text = body.decode("utf-8", "replace")
        decision = inspect(text, failure_mode=self.failure_mode, policy=self.policy)
        handling = handling_for(decision.action)

        # UNKNOWN får aldrig tyst bli forward i strict/balanced — handling_for ger redan
        # block/require_approval→block där; logg bär analysis_status så det aldrig ser
        # 'inspekterat' ut.
        if handling is ProxyHandling.block:
            self._logga(upstream.bas, "block", decision, 0)
            return self._block_svar(decision, "känsligt innehåll stoppat")

        skickad_body = body
        if handling is ProxyHandling.redact:
            sanerad = _sanera_json(body, decision)
            if sanerad is None:
                self._logga(upstream.bas, "block(redact-degraderad)", decision, 0)
                return self._block_svar(decision, "kunde ej sanera body säkert → block")
            skickad_body = sanerad

        host = urlsplit(upstream.bas).hostname or ""
        if self.validera_ip and not losa_och_validera(host):
            self._logga(upstream.bas, "block(ssrf)", decision, 0)
            return JSONResponse(status_code=502, content={
                "serrier": "upstream avvisad", "detalj": "resolvar till icke-global adress"})

        url = upstream.bas.rstrip("/") + "/" + request.path_params.get("rest", "")
        if request.url.query:
            url += "?" + request.url.query
        vidare_headers = {k: v for k, v in request.headers.items()
                          if k.lower() not in _SLOPPA_HEADERS}
        try:
            svar = await self.klient.request(request.method, url, headers=vidare_headers,
                                             content=skickad_body)
        except httpx.HTTPError as e:
            # Nätfel vid vidarebefordran → fail-closed (skicka aldrig vidare blint).
            self._logga(upstream.bas, "block(upstream-fel)", decision, 0)
            return JSONResponse(status_code=502,
                                content={"serrier": "upstream-fel", "detalj": type(e).__name__})

        self._logga(upstream.bas, handling.value, decision, len(skickad_body))
        ut_headers = {k: v for k, v in svar.headers.items()
                      if k.lower() not in _SLOPPA_HEADERS}
        return Response(content=svar.content, status_code=svar.status_code,
                        headers=ut_headers)

    def app(self) -> Starlette:
        metoder = ["GET", "POST", "PUT", "DELETE", "PATCH"]
        return Starlette(routes=[
            Route("/{nyckel}", self._hantera, methods=metoder),
            Route("/{nyckel}/{rest:path}", self._hantera, methods=metoder),
        ])


def skapa_klient() -> httpx.AsyncClient:
    """Prod-klient: full TLS-verifiering, INGA redirects (redirect till intern host = SSRF),
    rimlig timeout. Används när proxyn körs skarpt mot riktiga upstreams."""
    return httpx.AsyncClient(verify=True, follow_redirects=False, timeout=30.0)


def main() -> None:
    """Kör proxyn skarpt på LOOPBACK (127.0.0.1, aldrig 0.0.0.0) med default-allowlisten.
    Klient: base_url = http://127.0.0.1:<port>/<anthropic|openai|gemini>.
    Env: SERRIER_PROXY_PORT (8787), SERRIER_PROXY_FAILURE_MODE (balanced)."""
    port = int(os.environ.get("SERRIER_PROXY_PORT", "8787"))
    mode = FailureMode(os.environ.get("SERRIER_PROXY_FAILURE_MODE", "balanced"))
    proxy = GuardProxy(klient=skapa_klient(), failure_mode=mode)
    uvicorn.run(proxy.app(), host="127.0.0.1", port=port)   # loopback-only, låst beslut


if __name__ == "__main__":
    main()
