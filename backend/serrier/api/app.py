"""FastAPI — den typade ytan mot backend. MVP-flödet: skapa projekt → kör scan → lista
findings. Allt tenant-isolerat via project_id; findings bär redaktad evidens.

Säkerhet: skanningssökvägen valideras som en katalog (MVP = lokal, enanvändar; i
fleranvändar-läge krävs sandboxing, se THREAT_MODEL). Okänt projekt → 404.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from serrier import analyst, analytics, remediation
from serrier.core.findings import Status
from serrier.db.store import Store
from serrier.scanners import natverk
from serrier.scanners.registry import kor_skanners, tillgangliga


@lru_cache(maxsize=1)
def get_store() -> Store:                      # lat singleton; överskrivs i test
    return Store(os.environ.get("SERRIER_DB_URL", "sqlite:///serrier.db"))


StoreDep = Annotated[Store, Depends(get_store)]
app = FastAPI(title="Serrier", version="0.0.1")


class SkapaProjekt(BaseModel):
    namn: str


class ScanBegaran(BaseModel):
    sokvag: str


def _kravs_projekt(store: Store, pid: str) -> None:
    if not store.projekt_finns(pid):
        raise HTTPException(status_code=404, detail="okänt projekt")


@app.post("/projects")
def skapa_projekt(b: SkapaProjekt, store: StoreDep) -> dict:
    return {"project_id": store.skapa_projekt(b.namn)}


@app.post("/projects/{pid}/scan")
def scan(pid: str, b: ScanBegaran, store: StoreDep) -> dict:
    _kravs_projekt(store, pid)
    rot = Path(b.sokvag)
    if not rot.is_dir():
        raise HTTPException(status_code=400, detail="sökvägen är ingen katalog")
    fynd = kor_skanners(rot, pid)
    scan_id = store.spara_scan(pid, fynd, [s.namn for s in tillgangliga()])
    return {"scan_id": scan_id, "antal_findings": len(fynd)}


@app.get("/projects/{pid}/findings")
def findings(pid: str, store: StoreDep) -> list[dict]:
    _kravs_projekt(store, pid)
    return store.lista_findings(pid)


@app.get("/projects/{pid}/posture")
def posture(pid: str, store: StoreDep) -> dict:
    _kravs_projekt(store, pid)
    return {"posture": analytics.posture(store.lista_findings(pid)),
            "timeline": analytics.timeline(store.lista_scans(pid))}


class StatusBegaran(BaseModel):
    status: str


def _kravs_fynd(store: Store, pid: str, fid: str) -> dict:
    _kravs_projekt(store, pid)
    f = store.hamta_finding(pid, fid)
    if not f:
        raise HTTPException(status_code=404, detail="okänt fynd")
    return f


@app.get("/natverk/posture")
def natverk_posture() -> dict:
    """Modul C — nätverks-/VPN-posture för DENNA maskin (ingen fjärr-prob)."""
    ss, interfaces, resolv = natverk.samla()
    return natverk.posture(ss, interfaces, resolv)


@app.post("/projects/{pid}/findings/{fid}/atgardsforslag")
def atgardsforslag(pid: str, fid: str, store: StoreDep) -> dict:
    """AI-analysten + remediation föreslår (Claude). Sätter status remediation_proposed.
    Inget appliceras — förslaget kräver uttryckligt godkännande."""
    f = _kravs_fynd(store, pid, fid)
    analyst.ladda_nyckel()
    forslag = remediation.foresla_atgard(f)
    store.satt_status(pid, fid, Status.remediation_proposed)
    return forslag


@app.post("/projects/{pid}/findings/{fid}/godkann")
def godkann(pid: str, fid: str, store: StoreDep) -> dict:
    """Människans uttryckliga godkännande. Omskanning verifierar sen om risken sjönk."""
    _kravs_fynd(store, pid, fid)
    store.satt_status(pid, fid, Status.remediation_approved)
    return {"finding_id": fid, "status": Status.remediation_approved.value}


@app.post("/projects/{pid}/findings/{fid}/status")
def satt_status(pid: str, fid: str, b: StatusBegaran, store: StoreDep) -> dict:
    """Explicit statusövergång (t.ex. accepted_risk, investigating)."""
    _kravs_fynd(store, pid, fid)
    try:
        ny = Status(b.status)
    except ValueError as e:
        raise HTTPException(status_code=400, detail="ogiltig status") from e
    store.satt_status(pid, fid, ny)
    return {"finding_id": fid, "status": ny.value}
