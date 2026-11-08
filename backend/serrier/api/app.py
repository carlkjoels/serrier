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

from serrier.db.store import Store
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
