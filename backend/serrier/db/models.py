"""SQLAlchemy-modeller (SQLite nu, Postgres senare utan modelländringar).

Tenant-isolering via `project_id` på allt. Findings är upsert-bara på (project_id,
finding_id) så en omskanning uppdaterar i stället för att dubbla. Audit är append-only.
Evidens lagras som redaktad JSON — aldrig rå hemlighet (redaktionen skedde vid detektion).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> datetime:
    return datetime.now(UTC)


class Org(Base):
    """Tenant-gränsen. Projekt, findings och nycklar isoleras per org."""
    __tablename__ = "org"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    namn: Mapped[str] = mapped_column(String)
    skapad: Mapped[datetime] = mapped_column(DateTime, default=_now)


class ApiKey(Base):
    """En API-nyckel. Vi lagrar BARA sha256-hashen — den råa nyckeln visas en gång vid
    skapandet och går aldrig att återställa (samma princip som exponerade hemligheter:
    bevis, inte kvitto). Rollen avgör behörighet."""
    __tablename__ = "api_key"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("org.id"), index=True)
    nyckel_hash: Mapped[str] = mapped_column(String, unique=True, index=True)
    roll: Mapped[str] = mapped_column(String)
    etikett: Mapped[str] = mapped_column(String)
    skapad: Mapped[datetime] = mapped_column(DateTime, default=_now)


class GuardPolicy(Base):
    """Pre-Send Guardian-policy per org: sensitivitet→aktion-tabell (JSON) + fel-läge.
    En rad per org; saknas den → STANDARD-policy + balanced."""
    __tablename__ = "guard_policy"
    org_id: Mapped[str] = mapped_column(ForeignKey("org.id"), primary_key=True)
    tabell_json: Mapped[str] = mapped_column(Text)
    failure_mode: Mapped[str] = mapped_column(String)


class Project(Base):
    __tablename__ = "project"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("org.id"), index=True)
    namn: Mapped[str] = mapped_column(String)
    skapad: Mapped[datetime] = mapped_column(DateTime, default=_now)


class Scan(Base):
    __tablename__ = "scan"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    detektorer: Mapped[str] = mapped_column(String)
    antal: Mapped[int] = mapped_column(Integer)
    tid: Mapped[datetime] = mapped_column(DateTime, default=_now)


class FindingRow(Base):
    __tablename__ = "finding"
    __table_args__ = (UniqueConstraint("project_id", "finding_id"),)
    rad_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(String, index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    category: Mapped[str] = mapped_column(String)
    detector: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String)       # separat från confidence/status
    confidence: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)
    asset_ref: Mapped[str] = mapped_column(String)
    title: Mapped[str] = mapped_column(String)
    rule: Mapped[str] = mapped_column(String)
    evidens_json: Mapped[str] = mapped_column(Text)     # redaktad evidens
    forst_sedd: Mapped[datetime] = mapped_column(DateTime, default=_now)
    sist_sedd: Mapped[datetime] = mapped_column(DateTime, default=_now)
    # Antal gånger fyndet återkommit efter att ha verifierats/åtgärdats (regression).
    aterkomster: Mapped[int] = mapped_column(Integer, default=0, server_default="0")


class AuditEvent(Base):
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[str] = mapped_column(String, index=True)
    tid: Mapped[datetime] = mapped_column(DateTime, default=_now)
    handelse: Mapped[str] = mapped_column(String)
    detalj: Mapped[str] = mapped_column(String)
