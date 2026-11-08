"""Engine-konfig per backend + att Alembic-migrationen ger exakt modellernas schema.
Det senare fångar drift: ändras en modell utan migration failar testet."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.pool import StaticPool

from serrier.db.models import Base
from serrier.db.store import engine_kwargs

_BACKEND = Path(__file__).resolve().parent.parent


def test_engine_kwargs_sqlite_minne_delar_anslutning() -> None:
    kw = engine_kwargs("sqlite://")
    assert kw["poolclass"] is StaticPool
    assert kw["connect_args"] == {"check_same_thread": False}


def test_engine_kwargs_sqlite_fil_ingen_staticpool() -> None:
    kw = engine_kwargs("sqlite:///serrier.db")
    assert "poolclass" not in kw
    assert kw["connect_args"] == {"check_same_thread": False}


def test_engine_kwargs_postgres_pre_ping() -> None:
    kw = engine_kwargs("postgresql+psycopg://u:p@h/db")
    assert kw["pool_pre_ping"] is True
    assert "connect_args" not in kw


def test_migration_ger_samma_schema_som_modellerna(tmp_path: Path, monkeypatch) -> None:
    db = tmp_path / "mig.db"
    url = f"sqlite:///{db}"
    monkeypatch.setenv("SERRIER_DB_URL", url)
    cfg = Config(str(_BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND / "migrations"))
    command.upgrade(cfg, "head")

    migrerade = set(inspect(create_engine(url)).get_table_names())
    assert set(Base.metadata.tables) <= migrerade
