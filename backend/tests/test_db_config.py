"""Engine-konfig per backend + att Alembic-migrationen ger exakt modellernas schema.
Det senare fångar drift: ändras en modell utan migration failar testet."""

from __future__ import annotations

import tomllib
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.pool import StaticPool

from serrier.db.models import Base
from serrier.db.store import engine_kwargs, standard_db_url
from serrier.scanners import semgrep_adapter

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


def test_standard_db_url_env_vinner(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SERRIER_HOME", str(tmp_path / "hem"))
    monkeypatch.setenv("SERRIER_DB_URL", "sqlite:///:memory:")
    assert standard_db_url() == "sqlite:///:memory:"
    assert not (tmp_path / "hem").exists()          # rör inte hemkatalogen när URL är satt


def test_standard_db_url_absolut_i_serrier_home(monkeypatch, tmp_path: Path) -> None:
    """Utan SERRIER_DB_URL: en ABSOLUT fil i SERRIER_HOME — oberoende av aktuell katalog."""
    hem = tmp_path / "hem"
    monkeypatch.delenv("SERRIER_DB_URL", raising=False)
    monkeypatch.setenv("SERRIER_HOME", str(hem))
    monkeypatch.chdir(tmp_path)
    url = standard_db_url()
    assert url == f"sqlite:///{(hem / 'serrier.db').resolve()}"
    assert hem.is_dir()


def test_semgrep_regler_ar_deklarerade_som_paketdata() -> None:
    """Reglerna är en icke-Python-fil: utan package-data hamnar de inte i wheeln."""
    assert semgrep_adapter._REGLER.is_file()
    data = tomllib.loads((_BACKEND / "pyproject.toml").read_text())
    monster = data["tool"]["setuptools"]["package-data"]["serrier.scanners"]
    assert any(semgrep_adapter._REGLER.match(m) for m in monster)
