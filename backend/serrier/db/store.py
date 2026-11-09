"""Store: det enda stället som rör databasen. Tenant-isolering (allt filtreras på
project_id), upsert av findings på stabilt id (omskanning dubblar inte), append-only
audit. Status skrivs ALDRIG över av en re-scan — en åtgärdad brist förblir åtgärdad
tills något uttryckligen ändrar den."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from serrier import auth
from serrier.auth import Principal, Roll
from serrier.core.findings import Finding, Status
from serrier.core.risk import risk_score
from serrier.db.models import (
    ApiKey,
    AuditEvent,
    Base,
    FindingRow,
    GuardEvent,
    GuardPolicy,
    Org,
    Project,
    Scan,
)
from serrier.guardian.policy import (
    STANDARD,
    FailureMode,
    Policy,
    policy_fran_dict,
    policy_till_dict,
)

_DEV_ORG_ID = "dev-org"   # stabil id för dev-läges-orgen (ingen auth konfigurerad)


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

    # --- org & auth (Fas 7) -------------------------------------------------
    def skapa_org(self, namn: str) -> str:
        with self._Session() as s:
            o = Org(namn=namn)
            s.add(o)
            s.flush()
            self._audit(s, o.id, "org_skapad", namn)
            s.commit()
            return o.id

    def dev_org(self) -> str:
        """Hämta-eller-skapa dev-läges-orgen (stabil id). Används bara när ingen auth
        är konfigurerad — alla dev-anrop delar denna tenant."""
        with self._Session() as s:
            if s.get(Org, _DEV_ORG_ID) is None:
                s.add(Org(id=_DEV_ORG_ID, namn="dev"))
                s.commit()
        return _DEV_ORG_ID

    def antal_nycklar(self) -> int:
        with self._Session() as s:
            return s.scalar(select(func.count()).select_from(ApiKey)) or 0

    def skapa_nyckel(self, org_id: str, roll: Roll, etikett: str) -> str:
        """Skapar en nyckel och returnerar den RÅA strängen EN gång. Bara hashen sparas."""
        rå = auth.generera_nyckel()
        with self._Session() as s:
            s.add(ApiKey(org_id=org_id, nyckel_hash=auth.hasha(rå),
                         roll=roll.name, etikett=etikett))
            self._audit(s, org_id, "nyckel_skapad", f"{etikett} ({roll.name})")
            s.commit()
        return rå

    def verifiera_nyckel(self, rå_nyckel: str) -> Principal | None:
        """Slå upp en rå nyckel via dess hash → Principal, annars None."""
        with self._Session() as s:
            rad = s.scalar(select(ApiKey).where(ApiKey.nyckel_hash == auth.hasha(rå_nyckel)))
            if rad is None:
                return None
            return Principal(org_id=rad.org_id, roll=Roll.fran_namn(rad.roll))

    def lista_nycklar(self, org_id: str) -> list[dict]:
        """Metadata om nycklar — aldrig hash eller rå nyckel."""
        with self._Session() as s:
            rader = s.scalars(select(ApiKey).where(ApiKey.org_id == org_id)).all()
            return [{"id": r.id, "etikett": r.etikett, "roll": r.roll,
                     "skapad": r.skapad.isoformat()} for r in rader]

    def seed_nycklar_fran_env(self, råa: list[str]) -> str | None:
        """Startup-seed: ger varje medskickad rå nyckel owner-roll i en gemensam
        'bootstrap'-org, om den inte redan finns. Idempotent (hoppar kända hashar)."""
        råa = [k.strip() for k in råa if k.strip()]
        if not råa:
            return None
        with self._Session() as s:
            org = s.scalar(select(Org).where(Org.namn == "bootstrap"))
            if org is None:
                org = Org(namn="bootstrap")
                s.add(org)
                s.flush()
            for rå in råa:
                h = auth.hasha(rå)
                if s.scalar(select(ApiKey).where(ApiKey.nyckel_hash == h)) is None:
                    s.add(ApiKey(org_id=org.id, nyckel_hash=h, roll=Roll.owner.name,
                                 etikett="bootstrap (env)"))
            s.commit()
            return org.id

    # --- Guardian-policy per org (Fas 11, steg 5) --------------------------
    def satt_guard_policy(self, org_id: str, policy: Policy, failure_mode: FailureMode) -> None:
        with self._Session() as s:
            js = json.dumps(policy_till_dict(policy))
            rad = s.get(GuardPolicy, org_id)
            if rad:
                rad.tabell_json, rad.failure_mode = js, failure_mode.value
            else:
                s.add(GuardPolicy(org_id=org_id, tabell_json=js,
                                  failure_mode=failure_mode.value))
            self._audit(s, org_id, "guard_policy", f"fel-läge {failure_mode.value}")
            s.commit()

    def spara_guard_event(self, org_id: str, *, action: str, analysis_status: str,  # noqa: PLR0913
                          failure_mode: str = "", upstream: str = "",
                          rules: list[dict] | None = None) -> None:
        """Spara ett REDAKTERAT prevention-event. `rules` = [{regel, redacted}] — aldrig rå."""
        with self._Session() as s:
            s.add(GuardEvent(org_id=org_id, action=action, analysis_status=analysis_status,
                             failure_mode=failure_mode or "", upstream=upstream or "",
                             rules_json=json.dumps(rules or [])))
            s.commit()

    def lista_guard_events(self, org_id: str, limit: int = 100) -> list[dict]:
        """Senaste prevention-events för en org (nyast först). Allt redakterat."""
        with self._Session() as s:
            rader = s.scalars(
                select(GuardEvent).where(GuardEvent.org_id == org_id)
                .order_by(GuardEvent.tid.desc(), GuardEvent.id.desc()).limit(limit)).all()
            return [{"action": r.action, "analysis_status": r.analysis_status,
                     "failure_mode": r.failure_mode or None, "upstream": r.upstream or None,
                     "rules": json.loads(r.rules_json), "tid": r.tid.isoformat()} for r in rader]

    def hamta_guard_policy(self, org_id: str) -> tuple[Policy, FailureMode]:
        """Orgens policy, eller STANDARD + balanced om ingen satts."""
        with self._Session() as s:
            rad = s.get(GuardPolicy, org_id)
            if rad is None:
                return STANDARD, FailureMode.balanced
            return policy_fran_dict(json.loads(rad.tabell_json)), FailureMode(rad.failure_mode)

    # --- projekt (nu org-scopade) ------------------------------------------
    def skapa_projekt(self, namn: str, org_id: str) -> str:
        with self._Session() as s:
            p = Project(namn=namn, org_id=org_id)
            s.add(p)
            s.flush()
            self._audit(s, p.id, "projekt_skapat", f"{namn} (org {org_id})")
            s.commit()
            return p.id

    def projekt_finns(self, project_id: str, org_id: str | None = None) -> bool:
        """Finns projektet — och, om org_id ges, tillhör det den orgen? Fel org
        behandlas som 'finns inte' (läcker inte existens över tenant-gränsen)."""
        with self._Session() as s:
            p = s.get(Project, project_id)
            if p is None:
                return False
            return org_id is None or p.org_id == org_id

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
                    rad.evidens_json = _evidens_json(f)
                    # Regression: ett verifierat/åtgärdat fynd som dyker upp igen. Detta
                    # ÄR en meningsfull händelse (fixen höll inte) → status tillbaka till
                    # detected, räknat och auditerat. Övriga statusar rörs INTE av re-scan.
                    if rad.status in {Status.verified.value, Status.remediated.value}:
                        rad.aterkomster += 1
                        self._audit(s, project_id, "aterkomst",
                                    f"{f.id}: {rad.status} → detected (fynd återkom)")
                        rad.status = Status.detected.value
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
                "aterkomster": r.aterkomster,
                "forst_sedd": r.forst_sedd.isoformat(), "sist_sedd": r.sist_sedd.isoformat()}
