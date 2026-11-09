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

import hmac
import ipaddress
import json
import os
import secrets
import socket
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from serrier.guardian.enforcement import EnforcementLevel, ProxyHandling, handling_for
from serrier.guardian.inspect import GuardDecision, inspect
from serrier.guardian.policy import STANDARD, FailureMode, Policy

if TYPE_CHECKING:
    from serrier.db.store import Store

_TOKEN_HEADER = "x-serrier-token"  # noqa: S105 — header-namn, inte en hemlighet


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


def validerad_ip(host: str) -> str | None:
    """SSRF/DNS-rebinding-skydd + TOCTOU-fix: resolva EN gång, kräv att ALLA adresser är
    globala (publika), och returnera den validerade IP:n att PINNA anslutningen till. Någon
    icke-global adress (privat/loopback/link-local/reserverad) → None (avvisa hela). Resolv-
    fel → None (fail-closed). Anroparen ansluter sedan till denna IP med SNI/Host = host, så
    ingen andra-resolution kan rebind:a till en intern adress mellan kontroll och anslutning."""
    try:
        infon = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError):
        return None
    adresser = [info[4][0].split("%")[0] for info in infon]   # strippa ev. zon-id
    if not adresser:
        return None
    for a in adresser:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            return None
        if not ip.is_global:
            return None
    return adresser[0]                                     # pinna första validerade adressen


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
    token: str | None = None                   # krävs i X-Serrier-Token om satt (loopback-auth)
    store: Store | None = None                 # satt → policy hämtas per org
    org_id: str | None = None
    max_body: int = 10_000_000                 # 10 MB — resursgräns (avvisa innan inspektion)
    audit: list[dict] = field(default_factory=list)

    namn: str = "local-proxy"
    enforcement_level: EnforcementLevel = EnforcementLevel.guaranteed

    def covered_paths(self) -> list[str]:
        return [f"explicit loopback-routad HTTP(S) till allowlistad upstream: {u.nyckel} "
                f"→ {u.bas}" for u in self.allowlist]

    def _upstream(self, nyckel: str) -> Upstream | None:
        return next((u for u in self.allowlist if u.nyckel == nyckel), None)

    def _auktoriserad(self, request: Request) -> bool:
        """Loopback-auth: andra lokala processer får inte använda proxyn. Token saknas i
        konfig → öppet (dev). Token tas från path (/t/<token>/…, injiceras via barnets
        base_url — syns ej i process-listor) eller X-Serrier-Token. Jämförelse konstant tid."""
        if self.token is None:
            return True
        given = request.path_params.get("token") or request.headers.get(_TOKEN_HEADER, "")
        return hmac.compare_digest(given, self.token)

    def _policy_och_mode(self) -> tuple[Policy, FailureMode]:
        """Per-org-policy om en store+org kopplats, annars proxyns default."""
        if self.store is not None and self.org_id is not None:
            return self.store.hamta_guard_policy(self.org_id)
        return self.policy, self.failure_mode

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

    async def _hantera(self, request: Request) -> Response:  # noqa: PLR0911 — grind-klausuler
        if not self._auktoriserad(request):
            return JSONResponse(status_code=401,
                                content={"serrier": "ogiltig eller saknad proxy-token"})

        nyckel = request.path_params["nyckel"]
        upstream = self._upstream(nyckel)
        if upstream is None:
            return JSONResponse(status_code=404,
                                content={"serrier": "okänd upstream", "nyckel": nyckel})

        # Resursgräns: avvisa för stora bodies FÖRE vi läser/inspekterar (DoS-skydd).
        cl = request.headers.get("content-length", "")
        if cl.isdigit() and int(cl) > self.max_body:
            return JSONResponse(status_code=413, content={"serrier": "body för stor"})
        body = await request.body()
        if len(body) > self.max_body:
            return JSONResponse(status_code=413, content={"serrier": "body för stor"})
        text = body.decode("utf-8", "replace")
        policy, mode = self._policy_och_mode()
        decision = inspect(text, failure_mode=mode, policy=policy)
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

        delar = urlsplit(upstream.bas)
        host = delar.hostname or ""
        if self.validera_ip:
            ip = validerad_ip(host)
            if ip is None:
                self._logga(upstream.bas, "block(ssrf)", decision, 0)
                return JSONResponse(status_code=502, content={
                    "serrier": "upstream avvisad", "detalj": "resolvar till icke-global adress"})
            # Pinna anslutningen till den validerade IP:n (TOCTOU-fix); SNI/Host = host.
            netloc_ip = f"{ip}:{delar.port}" if delar.port else ip
            url = urlunsplit((delar.scheme, netloc_ip, "/" + request.path_params.get("rest", ""),
                              request.url.query, ""))
            extensions = {"sni_hostname": host}
        else:
            url = upstream.bas.rstrip("/") + "/" + request.path_params.get("rest", "")
            if request.url.query:
                url += "?" + request.url.query
            extensions = {}

        vidare_headers = {k: v for k, v in request.headers.items()
                          if k.lower() not in _SLOPPA_HEADERS}
        vidare_headers["host"] = delar.netloc                 # korrekt Host trots pinnad IP
        try:
            # stream=True → svaret buffras ALDRIG; vi relayar råa chunks (SSE/chunking/
            # backpressure bevaras). OBS: svarsINNEHÅLLET inspekteras inte — medvetet
            # avgränsat (request-sidan är redan inspekterad ovan).
            req = self.klient.build_request(request.method, url, headers=vidare_headers,
                                            content=skickad_body, extensions=extensions)
            svar = await self.klient.send(req, stream=True)
        except httpx.HTTPError as e:
            # Nätfel vid vidarebefordran → fail-closed (skicka aldrig vidare blint).
            self._logga(upstream.bas, "block(upstream-fel)", decision, 0)
            return JSONResponse(status_code=502,
                                content={"serrier": "upstream-fel", "detalj": type(e).__name__})

        self._logga(upstream.bas, handling.value, decision, len(skickad_body))
        ut_headers = {k: v for k, v in svar.headers.items()
                      if k.lower() not in _SLOPPA_HEADERS}

        async def _kropp() -> AsyncIterator[bytes]:
            # Relaya chunks allteftersom; stäng alltid upstream (städning + backpressure).
            # Avbruten klient/fel → generatorn stängs, aclose frigör anslutningen.
            try:
                async for chunk in svar.aiter_raw():
                    yield chunk
            finally:
                await svar.aclose()

        return StreamingResponse(_kropp(), status_code=svar.status_code, headers=ut_headers)

    def app(self) -> Starlette:
        metoder = ["GET", "POST", "PUT", "DELETE", "PATCH"]
        # Path-token-rutter FÖRST (för CLI-injektion via base_url); sedan header-token-rutter.
        return Starlette(routes=[
            Route("/t/{token}/{nyckel}", self._hantera, methods=metoder),
            Route("/t/{token}/{nyckel}/{rest:path}", self._hantera, methods=metoder),
            Route("/{nyckel}", self._hantera, methods=metoder),
            Route("/{nyckel}/{rest:path}", self._hantera, methods=metoder),
        ])


def skapa_klient() -> httpx.AsyncClient:
    """Prod-klient: full TLS-verifiering, INGA redirects (redirect till intern host = SSRF),
    rimlig timeout, och trust_env=False så en ambient HTTPS_PROXY/NO_PROXY i miljön INTE
    kapar Serriers egen vidarebefordran. Resursgräns på body-storlek görs i handlern."""
    return httpx.AsyncClient(verify=True, follow_redirects=False, timeout=30.0, trust_env=False)


def main() -> None:
    """Kör proxyn skarpt på LOOPBACK (127.0.0.1, aldrig 0.0.0.0) med default-allowlisten och
    en PÅTVINGAD token (loopback-auth) som skrivs ut en gång. Klienten måste skicka den som
    X-Serrier-Token. Klient: base_url = http://127.0.0.1:<port>/<anthropic|openai|gemini>.
    Env: SERRIER_PROXY_PORT (8787), SERRIER_PROXY_FAILURE_MODE (balanced), SERRIER_PROXY_TOKEN."""
    port = int(os.environ.get("SERRIER_PROXY_PORT", "8787"))
    mode = FailureMode(os.environ.get("SERRIER_PROXY_FAILURE_MODE", "balanced"))
    token = os.environ.get("SERRIER_PROXY_TOKEN") or secrets.token_urlsafe(24)
    proxy = GuardProxy(klient=skapa_klient(), failure_mode=mode, token=token)
    print(f"serrier proxy: loopback 127.0.0.1:{port} — X-Serrier-Token: {token}")
    uvicorn.run(proxy.app(), host="127.0.0.1", port=port)   # loopback-only, låst beslut


if __name__ == "__main__":
    main()
