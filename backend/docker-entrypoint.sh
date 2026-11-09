#!/bin/sh
# Alembic äger schemat i prod (SERRIER_SKIP_CREATE_ALL=1): migrera före start.
# Vänta in Postgres om vi pekar på en (compose startar dem parallellt).
set -e

# F1: vägra starta osäkert (t.ex. auth krävs men ingen nyckel seedad).
echo "serrier: validerar konfiguration…"
uv run python -c "import os; from serrier.api.app import krav_sakra_konfig; krav_sakra_konfig(os.environ)"

case "$SERRIER_DB_URL" in
  postgresql*|postgres*)
    echo "serrier: väntar på databasen…"
    until uv run python -c "import os,sqlalchemy as s; s.create_engine(os.environ['SERRIER_DB_URL']).connect().close()" 2>/dev/null; do
      sleep 1
    done
    ;;
esac

echo "serrier: kör migrationer (alembic upgrade head)…"
uv run alembic upgrade head

echo "serrier: startar API på :8000"
exec uv run uvicorn serrier.api.app:app --host 0.0.0.0 --port 8000
