"""Store: det enda stället som rör databasen. Tenant-isolering (allt filtreras på
project_id), upsert av findings på stabilt id (omskanning dubblar inte), append-only
audit. Status skrivs ALDRIG över av en re-scan — en åtgärdad brist förblir åtgärdad
tills något uttryckligen ändrar den."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from serrier.core.findings import Finding
from serrier.core.risk import risk_score
from serrier.db.models import AuditEvent, Base, FindingRow, Project, Scan


def _evidens_json(f: Finding) -> str:
    return json.dumps([e.model_dump(mode="json") for e in f.evidence])


class Store:
    def __init__(self, url: str = "sqlite:///serrier.db") -> None:
        # SQLite + FastAPI (trådpool): dela en anslutning (StaticPool) så alla trådar ser
        # samma databas, och tillåt åtkomst över trådar. In-memory kräver det särskilt.
        kwargs: dict = {}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
            if ":memory:" in url or url == "sqlite://":
                kwargs["poolclass"] = StaticPool
        self._engine = create_engine(url, **kwargs)
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
            self._audit(s, project_id, "scan", f"{len(findings)} findings")
            s.commit()
            return scan.id

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
