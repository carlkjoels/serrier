"""FastAPI — den typade ytan mot backend. MVP-flödet: skapa projekt → kör scan → lista
findings. Allt tenant-isolerat per ORG (Fas 7); findings bär redaktad evidens.

Auth: Bearer-/X-API-Key-nyckel → Principal(org, roll). Finns inga nycklar alls och
SERRIER_REQUIRE_AUTH är osatt körs dev-läge (owner i en dev-org) så lokalt bruk är
friktionsfritt. RBAC: viewer läser, member skannar/sätter status, owner hanterar nycklar.
Fel org behandlas som 404 — tenant-existens läcker aldrig över gränsen.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel

from serrier import analyst, analytics, correlation, export, remediation
from serrier.auth import Principal, Roll, far
from serrier.core.findings import Status
from serrier.db.store import Store
from serrier.guardian.inspect import inspect as guard_inspect
from serrier.guardian.policy import (
    FailureMode,
    policy_fran_dict,
    policy_till_dict,
)
from serrier.scanners import natverk
from serrier.scanners.registry import kor_skanners, tillgangliga


@lru_cache(maxsize=1)
def get_store() -> Store:                      # lat singleton; överskrivs i test
    return Store(os.environ.get("SERRIER_DB_URL", "sqlite:///serrier.db"))


StoreDep = Annotated[Store, Depends(get_store)]


def krav_sakra_konfig(env: dict) -> None:
    """Vägra en osäker produktionsstart (F1). Anropas från entrypoint FÖRE uvicorn: om
    auth krävs måste minst en owner-nyckel seedas (ingen öppen /orgs-bootstrap i auth-läge),
    annars vore en nätverksexponerad instans administrativt öppen tills första anropet."""
    if env.get("SERRIER_REQUIRE_AUTH") and not (env.get("SERRIER_API_KEYS") or "").strip():
        raise RuntimeError(
            "SERRIER_REQUIRE_AUTH är satt men SERRIER_API_KEYS är tomt — vägrar starta. "
            "Seeda minst en owner-nyckel; öppen bootstrap är avstängd i auth-läge.")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    # Seed owner-nycklar från env vid start (prod/compose). Osatt → inget byggs (test).
    rå = os.environ.get("SERRIER_API_KEYS", "")
    if rå:
        get_store().seed_nycklar_fran_env(rå.split(","))
    yield


app = FastAPI(title="Serrier", version="0.0.1", lifespan=lifespan)


# --- auth -----------------------------------------------------------------
def _extrahera_nyckel(request: Request) -> str | None:
    h = request.headers.get("authorization")
    if h and h.lower().startswith("bearer "):
        return h[7:].strip()
    return request.headers.get("x-api-key")


def nuvarande_principal(request: Request, store: StoreDep) -> Principal:
    rå = _extrahera_nyckel(request)
    if rå:
        p = store.verifiera_nyckel(rå)
        if p is None:
            raise HTTPException(status_code=401, detail="ogiltig API-nyckel")
        return p
    if store.antal_nycklar() > 0 or os.environ.get("SERRIER_REQUIRE_AUTH"):
        raise HTTPException(status_code=401, detail="API-nyckel krävs")
    return Principal(org_id=store.dev_org(), roll=Roll.owner, dev=True)


PrincipalDep = Annotated[Principal, Depends(nuvarande_principal)]


def kravs_roll(min_roll: Roll) -> Callable[[Principal], Principal]:
    def _check(p: PrincipalDep) -> Principal:
        if not far(p.roll, min_roll):
            raise HTTPException(status_code=403, detail=f"kräver roll {min_roll.name}")
        return p
    return _check


ViewerDep = Annotated[Principal, Depends(kravs_roll(Roll.viewer))]
MemberDep = Annotated[Principal, Depends(kravs_roll(Roll.member))]
OwnerDep = Annotated[Principal, Depends(kravs_roll(Roll.owner))]


class SkapaProjekt(BaseModel):
    namn: str


class ScanBegaran(BaseModel):
    sokvag: str


def _kravs_projekt(store: Store, pid: str, org_id: str) -> None:
    if not store.projekt_finns(pid, org_id):
        raise HTTPException(status_code=404, detail="okänt projekt")


@app.post("/projects")
def skapa_projekt(b: SkapaProjekt, store: StoreDep, p: MemberDep) -> dict:
    return {"project_id": store.skapa_projekt(b.namn, p.org_id)}


@app.post("/projects/{pid}/scan")
def scan(pid: str, b: ScanBegaran, store: StoreDep, p: MemberDep) -> dict:
    _kravs_projekt(store, pid, p.org_id)
    rot = Path(b.sokvag)
    if not rot.is_dir():
        raise HTTPException(status_code=400, detail="sökvägen är ingen katalog")
    fynd = kor_skanners(rot, pid)
    scan_id = store.spara_scan(pid, fynd, [s.namn for s in tillgangliga()])
    return {"scan_id": scan_id, "antal_findings": len(fynd)}


@app.get("/projects/{pid}/findings")
def findings(pid: str, store: StoreDep, p: ViewerDep) -> list[dict]:
    _kravs_projekt(store, pid, p.org_id)
    return store.lista_findings(pid)


@app.get("/projects/{pid}/posture")
def posture(pid: str, store: StoreDep, p: ViewerDep) -> dict:
    _kravs_projekt(store, pid, p.org_id)
    fynd = store.lista_findings(pid)
    return {"posture": analytics.posture(fynd),
            "timeline": analytics.timeline(store.lista_scans(pid)),
            "antal_korrelationer": len(correlation.korrelera(fynd)),
            "regressioner": analytics.reappearances(fynd)}


@app.get("/projects/{pid}/correlations")
def correlations(pid: str, store: StoreDep, p: ViewerDep) -> list[dict]:
    """Tillgångar som flera oberoende detektorer flaggat — prioritera dessa först."""
    _kravs_projekt(store, pid, p.org_id)
    return correlation.korrelera(store.lista_findings(pid))


@app.get("/projects/{pid}/export")
def exportera(pid: str, store: StoreDep, p: ViewerDep, format: str = "json") -> dict:
    """Exportera findings som SARIF 2.1.0 (CI/GitHub) eller ren JSON. Bara redaktad
    evidens lämnar systemet — filen kan delas utan att läcka hemligheter."""
    _kravs_projekt(store, pid, p.org_id)
    fynd = store.lista_findings(pid)
    if format == "sarif":
        return export.till_sarif(fynd)
    if format == "json":
        return export.till_json(fynd)
    raise HTTPException(status_code=400, detail="format måste vara 'sarif' eller 'json'")


class StatusBegaran(BaseModel):
    status: str


def _kravs_fynd(store: Store, pid: str, fid: str, org_id: str) -> dict:
    _kravs_projekt(store, pid, org_id)
    f = store.hamta_finding(pid, fid)
    if not f:
        raise HTTPException(status_code=404, detail="okänt fynd")
    return f


@app.get("/natverk/posture")
def natverk_posture(_: ViewerDep) -> dict:
    """Modul C — nätverks-/VPN-posture för DENNA maskin (ingen fjärr-prob)."""
    ss, interfaces, resolv = natverk.samla()
    return natverk.posture(ss, interfaces, resolv)


class GuardBegaran(BaseModel):
    text: str
    failure_mode: str | None = None          # None → orgens inställda fel-läge


@app.post("/guard/inspect")
def guard_inspect_endpoint(b: GuardBegaran, store: StoreDep, p: ViewerDep) -> dict:
    """Pre-Send Guardian — inspektera utgående text lokalt innan den skickas till en AI-
    tjänst. Använder ORGENS policy + fel-läge (eller STANDARD). Deterministiskt beslut
    (detektion→policy→safe_text). Den RÅA texten persisteras eller loggas ALDRIG; bara
    redakterad data returneras. Detektion-fel → analysis_status=unknown, aldrig tyst 'godkänt'."""
    policy, org_mode = store.hamta_guard_policy(p.org_id)
    mode = org_mode
    if b.failure_mode is not None:
        try:
            mode = FailureMode(b.failure_mode)
        except ValueError as e:
            raise HTTPException(status_code=400, detail="ogiltigt failure_mode") from e
    return guard_inspect(b.text, failure_mode=mode, policy=policy).som_dict()


class GuardPolicyBegaran(BaseModel):
    tabell: dict[str, str] = {}              # sensitivitet → aktion (partiell OK)
    failure_mode: str = "balanced"


@app.get("/guard/policy")
def hamta_guard_policy(store: StoreDep, p: ViewerDep) -> dict:
    policy, mode = store.hamta_guard_policy(p.org_id)
    return {"tabell": policy_till_dict(policy), "failure_mode": mode.value}


@app.put("/guard/policy")
def satt_guard_policy(b: GuardPolicyBegaran, store: StoreDep, p: OwnerDep) -> dict:
    """Owner sätter orgens Guardian-policy (sensitivitet→aktion + fel-läge). Partiell
    tabell fylls ut med STANDARD."""
    try:
        policy = policy_fran_dict(b.tabell)
        mode = FailureMode(b.failure_mode)
    except ValueError as e:
        raise HTTPException(status_code=400, detail="ogiltig policy") from e
    store.satt_guard_policy(p.org_id, policy, mode)
    return {"tabell": policy_till_dict(policy), "failure_mode": mode.value}


@app.post("/projects/{pid}/findings/{fid}/atgardsforslag")
def atgardsforslag(pid: str, fid: str, store: StoreDep, p: MemberDep) -> dict:
    """AI-analysten + remediation föreslår (Claude). Sätter status remediation_proposed.
    Inget appliceras — förslaget kräver uttryckligt godkännande."""
    f = _kravs_fynd(store, pid, fid, p.org_id)
    analyst.ladda_nyckel()
    forslag = remediation.foresla_atgard(f)
    store.satt_status(pid, fid, Status.remediation_proposed)
    return forslag


@app.post("/projects/{pid}/findings/{fid}/godkann")
def godkann(pid: str, fid: str, store: StoreDep, p: MemberDep) -> dict:
    """Människans uttryckliga godkännande. Omskanning verifierar sen om risken sjönk."""
    _kravs_fynd(store, pid, fid, p.org_id)
    store.satt_status(pid, fid, Status.remediation_approved)
    return {"finding_id": fid, "status": Status.remediation_approved.value}


@app.post("/projects/{pid}/findings/{fid}/status")
def satt_status(pid: str, fid: str, b: StatusBegaran, store: StoreDep, p: MemberDep) -> dict:
    """Explicit statusövergång (t.ex. accepted_risk, investigating)."""
    _kravs_fynd(store, pid, fid, p.org_id)
    try:
        ny = Status(b.status)
    except ValueError as e:
        raise HTTPException(status_code=400, detail="ogiltig status") from e
    store.satt_status(pid, fid, ny)
    return {"finding_id": fid, "status": ny.value}


# --- org & nyckelhantering (owner) ----------------------------------------
class SkapaOrg(BaseModel):
    namn: str


class SkapaNyckel(BaseModel):
    roll: str = "member"
    etikett: str = "api-nyckel"


@app.post("/orgs")
def skapa_org(b: SkapaOrg, store: StoreDep) -> dict:
    """Bootstrappa en org + dess första owner-nyckel. Öppen BARA i dev-läge. I auth-läge
    (SERRIER_REQUIRE_AUTH) är den öppna bootstrappen avstängd — orgar seedas via
    SERRIER_API_KEYS eller skapas av en befintlig owner (F1)."""
    if os.environ.get("SERRIER_REQUIRE_AUTH"):
        raise HTTPException(
            status_code=403,
            detail="öppen bootstrap avstängd i auth-läge; seeda via SERRIER_API_KEYS")
    if store.antal_nycklar() > 0:
        raise HTTPException(status_code=403, detail="orgskapande kräver owner-nyckel i prod")
    org_id = store.skapa_org(b.namn)
    rå = store.skapa_nyckel(org_id, Roll.owner, "bootstrap owner")
    return {"org_id": org_id, "api_key": rå,
            "obs": "nyckeln visas EN gång — spara den nu, den kan inte återställas"}


@app.post("/orgs/{oid}/keys")
def skapa_nyckel(oid: str, b: SkapaNyckel, store: StoreDep, p: OwnerDep) -> dict:
    if oid != p.org_id:
        raise HTTPException(status_code=404, detail="okänd org")
    try:
        roll = Roll.fran_namn(b.roll)
    except ValueError as e:
        raise HTTPException(status_code=400, detail="ogiltig roll") from e
    rå = store.skapa_nyckel(oid, roll, b.etikett)
    return {"api_key": rå, "roll": roll.name,
            "obs": "nyckeln visas EN gång — spara den nu, den kan inte återställas"}


@app.get("/orgs/{oid}/keys")
def lista_nycklar(oid: str, store: StoreDep, p: OwnerDep) -> list[dict]:
    if oid != p.org_id:
        raise HTTPException(status_code=404, detail="okänd org")
    return store.lista_nycklar(oid)   # metadata, aldrig hash/rå nyckel
