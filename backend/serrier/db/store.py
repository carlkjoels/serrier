"""Store: det enda stället som rör databasen. Tenant-isolering (allt filtreras på
project_id), upsert av findings på stabilt id (omskanning dubblar inte), append-only
audit. Status skrivs ALDRIG över av en re-scan — en åtgärdad brist förblir åtgärdad
tills något uttryckligen ändrar den."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from serrier.core.findings import Finding, Status
from serrier.core.risk import risk_score
from serrier.db.models import AuditEvent, Base, FindingRow, Project, Scan


def _evidens_json(f: Finding) -> str:
    return json.dumps([e.model_dump(mode="json") for e in f.evidence])


def engine_kwargs(url: str) -> dict:
    """Engine-argument per backend. Ren funktion så valet kan testas utan en riktig DB.
    SQLite i FastAPI:s trådpool måste dela anslutning (StaticPool) + tillåta åtkomst över
    trådar; in-memory kräver det särskilt. Postgres sköter sin egen pool."""
    if url.startswith("sqlite"):
        kwargs: dict = {"connect_args": {"check_same_thread": False}}
        if ":memory:" in url or url == "sqlite://":
            kwargs["poolclass"] = StaticPool
        return kwargs
    # Postgres o.a.: förnya döda anslutningar innan bruk (långlivad container).
    return {"pool_pre_ping": True}


class Store:
    def __init__(self, url: str = "sqlite:///serrier.db") -> None:
        self._engine = create_engine(url, **engine_kwargs(url))
        # I prod äger Alembic schemat (SERRIER_SKIP_CREATE_ALL=1). Dev/test skapar på plats.
        if not os.environ.get("SERRIER_SKIP_CREATE_ALL"):
            Base.metadata.create_all(self._engine)
        self._Session: sessionmaker[Session] = sessionmaker(self._engine)

    def _audit(self, s: Session, project_id: str, handelse: str, detalj: str) -> None:
        s.add(AuditEvent(project_id=project_id, handelse=handelse, detalj=detalj))

    def skapa_projekt(self, namn: str) -> str:
        with self._Session() as s:
            p = Project(namn=namn)
            s.add(p)
            s.flush()
            self._audit(s, p.id, "projekt_skapat", namn)
            s.commit()
            return p.id

    def projekt_finns(self, project_id: str) -> bool:
        with self._Session() as s:
            return s.get(Project, project_id) is not None

    def spara_scan(self, project_id: str, findings: list[Finding], detektorer: list[str]) -> str:
        with self._Session() as s:
            scan = Scan(project_id=project_id, detektorer=",".join(detektorer),
                        antal=len(findings))
            s.add(scan)
            for f in findings:
                rad = s.scalar(select(FindingRow).where(
                    FindingRow.project_id == project_id, FindingRow.finding_id == f.id))
                if rad:
                    rad.sist_sedd = datetime.now(UTC)
                    rad.evidens_json = _evidens_json(f)     # status rörs INTE (re-scan)
                else:
                    s.add(self._ny_rad(project_id, f))
            self._auto_verifiera(s, project_id, {f.id for f in findings})
            self._audit(s, project_id, "scan", f"{len(findings)} findings")
            s.commit()
            return scan.id

    def _auto_verifiera(self, s: Session, project_id: str, nuvarande: set[str]) -> None:
        """Åtgärd→verifiering stängs av en omskanning: en GODKÄND åtgärd vars fynd inte
        längre finns → risken sjönk faktiskt → verified. (Detect→…→Verify-loopen.)"""
        godkanda = s.scalars(select(FindingRow).where(
            FindingRow.project_id == project_id,
            FindingRow.status == Status.remediation_approved.value)).all()
        for rad in godkanda:
            if rad.finding_id not in nuvarande:
                rad.status = Status.verified.value
                self._audit(s, project_id, "verifierad",
                            f"{rad.finding_id}: borta efter omskanning → verified")

    def satt_status(self, project_id: str, finding_id: str, ny_status: Status) -> bool:
        """Explicit, auditerad statusövergång (människans hand i loopen: utreda, godkänna,
        acceptera risk). Ingen LLM och ingen omskanning sätter detta tyst."""
        with self._Session() as s:
            rad = s.scalar(select(FindingRow).where(
                FindingRow.project_id == project_id, FindingRow.finding_id == finding_id))
            if not rad:
                return False
            self._audit(s, project_id, "status", f"{finding_id}: {rad.status} → {ny_status.value}")
            rad.status = ny_status.value
            s.commit()
            return True

    @staticmethod
    def _ny_rad(project_id: str, f: Finding) -> FindingRow:
        return FindingRow(
            finding_id=f.id, project_id=project_id, category=f.category, detector=f.detector,
            severity=f.severity, confidence=f.confidence, status=f.status,
            asset_ref=f.asset_ref, title=f.title, rule=f.rule, evidens_json=_evidens_json(f))

    def lista_findings(self, project_id: str) -> list[dict]:
        with self._Session() as s:
            rader = s.scalars(select(FindingRow).where(
                FindingRow.project_id == project_id)).all()
            return sorted((self._till_dict(r) for r in rader),
                          key=lambda d: d["risk"], reverse=True)

    def hamta_finding(self, project_id: str, finding_id: str) -> dict | None:
        with self._Session() as s:
            rad = s.scalar(select(FindingRow).where(
                FindingRow.project_id == project_id, FindingRow.finding_id == finding_id))
            return self._till_dict(rad) if rad else None

    def lista_scans(self, project_id: str) -> list[dict]:
        with self._Session() as s:
            rader = s.scalars(select(Scan).where(Scan.project_id == project_id)
                              .order_by(Scan.tid)).all()
            return [{"tid": r.tid.isoformat(), "antal": r.antal,
                     "detektorer": r.detektorer} for r in rader]

    @staticmethod
    def _till_dict(r: FindingRow) -> dict:
        f = Finding(project_id=r.project_id, category=r.category, detector=r.detector,
                    severity=r.severity, confidence=r.confidence, status=r.status,
                    asset_ref=r.asset_ref, title=r.title, rule=r.rule)
        return {"id": r.finding_id, "category": r.category, "detector": r.detector,
                "severity": r.severity, "confidence": r.confidence, "status": r.status,
                "asset_ref": r.asset_ref, "title": r.title, "rule": r.rule,
                "risk": risk_score(f), "evidence": json.loads(r.evidens_json),
                "forst_sedd": r.forst_sedd.isoformat(), "sist_sedd": r.sist_sedd.isoformat()}
