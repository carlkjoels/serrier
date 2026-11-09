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
import stat
from collections import deque
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlsplit, urlunsplit

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from serrier.guardian.enforcement import EnforcementLevel, ProxyHandling, handling_for
from serrier.guardian.inspect import GuardDecision, inspect
from serrier.guardian.policy import (
    STANDARD,
    AnalysisStatus,
    FailureMode,
    Policy,
    besluta,
)

if TYPE_CHECKING:
    from serrier.db.store import Store

_TOKEN_HEADER = "x-serrier-token"  # noqa: S105 — header-namn, inte en hemlighet
_AUDIT_MAX = 1000                   # audit-loggen är BUNDEN (ringbuffert) → växer inte obegränsat


def skriv_token(token: str, path: Path) -> None:
    """Skriv en proxy-token till en 0600-fil (G) — bara ägaren kan läsa den, och den hamnar
    ALDRIG i stdout/loggar. Delas av daemonen (stabil token) och foreground-main (engångs)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(mode=stat.S_IRUSR | stat.S_IWUSR, exist_ok=True)   # 0600
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)                       # tvinga 0600 även om den fanns
    path.write_text(token)


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
    # Host-header-allowlist mot DNS-rebinding (0004 §4) — krävs i alltid-på/daemon-läge.
    # None = ingen kontroll (dev); satt = avvisa Host som inte är en förväntad loopback-adress.
    tillaten_host: set[str] | None = None
    audit: deque[dict] = field(default_factory=lambda: deque(maxlen=_AUDIT_MAX))

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
        # Rapportera REDAKTERAT till kontrollplanet (#1) → dashboardens live-flöde. Ett fel
        # här får ALDRIG krascha proxyn eller blockera trafiken.
        if self.store is not None and self.org_id is not None:
            try:
                self.store.spara_guard_event(
                    self.org_id, action=d.action.value,
                    analysis_status=d.analysis_status.value,
                    failure_mode=d.failure_mode.value if d.failure_mode else "",
                    upstream=upstream,
                    rules=[{"regel": f.regel, "redacted": f.redacted} for f in d.findings])
            except Exception:  # noqa: S110 — telemetri får aldrig störa enforcement
                pass

    def _block_svar(self, d: GuardDecision, detalj: str) -> JSONResponse:
        return JSONResponse(status_code=403, content={
            "serrier": "blocked", "detalj": detalj, "action": d.action.value,
            "analysis_status": d.analysis_status.value,
            "reasons": [r.forklaring for r in d.reasons]})

    @staticmethod
    async def _las_begransad(request: Request, grans: int) -> bytes | None:
        """Läs request-body:n strömmande och avbryt så fort ``grans`` passeras.

        Returnerar hela body:n (bytes) om den ryms, annars ``None`` (→ 413). Till skillnad
        från ``await request.body()`` buffrar vi aldrig en obegränsad body i minnet: vi räknar
        bytes allteftersom chunkarna kommer och släpper så snart summan överskrider gränsen.
        Detta gäller oavsett Content-Length (chunked/ingen CL/ljugande CL hanteras lika)."""
        total = 0
        delar: list[bytes] = []
        async for chunk in request.stream():
            total += len(chunk)
            if total > grans:
                return None
            delar.append(chunk)
        return b"".join(delar)

    def _vakt(self, request: Request) -> Response | None:
        """Delad loopback-vakt (0004 §4): Host-allowlist mot DNS-rebinding + token-auth.
        Returnerar ett felsvar om något brister, annars None (fortsätt). Delas av
        proxy-vägen (_hantera) och inspektions-endpointen (_inspektera)."""
        if self.tillaten_host is not None and \
                request.headers.get("host", "").lower() not in self.tillaten_host:
            return JSONResponse(status_code=403, content={"serrier": "otillåten Host"})
        if not self._auktoriserad(request):
            return JSONResponse(status_code=401,
                                content={"serrier": "ogiltig eller saknad proxy-token"})
        return None

    async def _inspektera(self, request: Request) -> Response:
        """0005 steg 1 — ren inspektions-endpoint för browser-extensionen (PEP:en i browsern).

        Tar godtycklig text i body:n, kör SAMMA beslutskärna som proxyn (`inspect`), och
        returnerar ett GuardDecision som JSON. Den FORWARDAR ingenting och verkställer inget —
        extensionen är PEP:en som agerar på verdiktet (block/redact/warn/allow). Svaret bär
        bara redakterad data (findings = first4…last4, safe_text = maskerad); rå text lämnar
        aldrig den här funktionen och loggas aldrig. Skyddad av samma Host-allowlist + token."""
        fel = self._vakt(request)
        if fel is not None:
            return fel
        body = await self._las_begransad(request, self.max_body)
        if body is None:
            return JSONResponse(status_code=413, content={"serrier": "text för stor"})
        text = body.decode("utf-8", "replace")
        policy, mode = self._policy_och_mode()
        decision = inspect(text, failure_mode=mode, policy=policy)
        self._logga("(extension)", f"inspect:{handling_for(decision.action).value}", decision, 0)
        svar = decision.som_dict()
        svar["handling"] = handling_for(decision.action).value   # block | redact | forward(=allow)
        return JSONResponse(svar)

    async def _hantera(self, request: Request) -> Response:  # noqa: PLR0911 — grind-klausuler
        # DNS-rebinding-skydd (0004 §4): avvisa Host som inte är en förväntad loopback-adress.
        # En rebindad angripar-hostname blir äkta same-origin → bara Host-allowlist stoppar den.
        fel = self._vakt(request)
        if fel is not None:
            return fel

        nyckel = request.path_params["nyckel"]
        upstream = self._upstream(nyckel)
        if upstream is None:
            return JSONResponse(status_code=404,
                                content={"serrier": "okänd upstream", "nyckel": nyckel})

        # Resursgräns (C): avvisa för stora bodies FÖRE vi buffrar hela i minnet (DoS-skydd).
        # Content-Length är en snabb precheck men får INTE lita på: chunked utan CL, eller en
        # ljugande CL, kringgår den. Därför läser vi strömmen med en löpande byte-räknare och
        # avbryter i samma stund gränsen passeras — vi buffrar aldrig mer än gränsen + en chunk.
        cl = request.headers.get("content-length", "")
        if cl.isdigit() and int(cl) > self.max_body:
            return JSONResponse(status_code=413, content={"serrier": "body för stor"})
        body = await self._las_begransad(request, self.max_body)
        if body is None:
            return JSONResponse(status_code=413, content={"serrier": "body för stor"})
        policy, mode = self._policy_och_mode()

        # D — query-string-inspektion. Hemligheter smugglas ibland i URL:en (?key=sk-…),
        # inte bara i body:n. unquote() avkodar %-escaping så vi ser den riktiga texten.
        # Känsligt i query → block (vi kan inte "redakta" en URL utan att bryta anropet).
        if request.url.query:
            q = inspect(unquote(request.url.query), failure_mode=mode, policy=policy)
            if handling_for(q.action) is ProxyHandling.block:
                self._logga(upstream.bas, "block(query)", q, 0)
                return self._block_svar(q, "känsligt innehåll i query-string stoppat")

        # E — kodad/komprimerad body (gzip/deflate/br/…). Vi kan INTE inspektera innehållet
        # utan att först dekomprimera; att skicka det som "inspekterat-säkert" vore en lögn.
        # → analysis_status = UNKNOWN och fel-läget avgör (strict/balanced → block,
        # permissive → vidarebefordra OFÖRÄNDRAT men loggat som unknown, aldrig redact).
        ce = request.headers.get("content-encoding", "").strip().lower()
        if ce and ce != "identity":
            verdict = besluta([], analysis_status=AnalysisStatus.unknown,
                              failure_mode=mode, policy=policy)
            decision = GuardDecision(action=verdict.action,
                                     analysis_status=AnalysisStatus.unknown,
                                     failure_mode=verdict.failure_mode, safe_text="",
                                     reasons=verdict.reasons)
            if handling_for(decision.action) is ProxyHandling.block:
                self._logga(upstream.bas, "block(kodad-body-unknown)", decision, 0)
                return self._block_svar(
                    decision, f"kodad body ({ce}) kunde ej inspekteras → block")
            # permissive: forwarda den ORÖRDA kodade body:n (redact vore omöjlig på bytes).
            return await self._forwarda(request, upstream, body, decision,
                                        "forward(kodad-body-unknown)")

        text = body.decode("utf-8", "replace")
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

        return await self._forwarda(request, upstream, skickad_body, decision, handling.value)

    async def _forwarda(self, request: Request, upstream: Upstream, skickad_body: bytes,
                        decision: GuardDecision, logg_etikett: str) -> Response:
        """Vidarebefordra en redan beslutad request till upstream med SSRF-pinning + strömmat
        svar. Delas av den vanliga vägen och E-vägen (kodad body, forwardad orörd i permissive)."""
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

        self._logga(upstream.bas, logg_etikett, decision, len(skickad_body))
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
        # Inspektions-endpointen (0005) FÖRST — annars skulle "/inspect" matcha /{nyckel}.
        # Path-token-variant för symmetri med proxyn; header-token (X-Serrier-Token) räcker.
        # Path-token-rutter sedan (CLI-injektion via base_url); sist header-token-rutter.
        return Starlette(routes=[
            Route("/inspect", self._inspektera, methods=["POST"]),
            Route("/t/{token}/inspect", self._inspektera, methods=["POST"]),
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
    fran_env = os.environ.get("SERRIER_PROXY_TOKEN")
    token = fran_env or secrets.token_urlsafe(24)
    proxy = GuardProxy(klient=skapa_klient(), failure_mode=mode, token=token)
    # G: token hamnar ALDRIG i stdout/loggar. Satte användaren den själv (env) vet hen den
    # redan; annars skriver vi den till en 0600-fil och skriver bara ut SÖKVÄGEN.
    if fran_env:
        print(f"serrier proxy: loopback 127.0.0.1:{port} — token läst ur SERRIER_PROXY_TOKEN")
    else:
        tokenfil = Path(os.environ.get("SERRIER_PROXY_TOKEN_FILE",
                                       str(Path.home() / ".serrier" / "proxy-token")))
        skriv_token(token, tokenfil)
        print(f"serrier proxy: loopback 127.0.0.1:{port} — token i {tokenfil} (0600, läs den "
              "och skicka som X-Serrier-Token)")
    uvicorn.run(proxy.app(), host="127.0.0.1", port=port)   # loopback-only, låst beslut


if __name__ == "__main__":
    main()
