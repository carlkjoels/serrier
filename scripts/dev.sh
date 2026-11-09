#!/usr/bin/env bash
# Serrier — lokal dev med ETT kommando: startar backend + frontend, väntar in dem, skriver
# länkarna, och stänger BÅDA rent vid Ctrl-C. (Prod = docker compose; se docker-compose.yml.)
set -euo pipefail

ROT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_PORT="${SERRIER_PORT:-8000}"
FRONTEND_PORT="${SERRIER_FRONTEND_PORT:-3000}"

cleanup() { echo; echo "serrier: stänger ner…"; kill 0 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# Frontend-deps vid behov (första gången).
if [ ! -d "$ROT/frontend/node_modules" ]; then
  echo "serrier: installerar frontend-deps (en gång)…"
  (cd "$ROT/frontend" && npm install)
fi

echo "serrier: startar backend på :$BACKEND_PORT …"
(cd "$ROT/backend" && uv run uvicorn serrier.api.app:app --host 127.0.0.1 --port "$BACKEND_PORT") &

echo "serrier: startar frontend på :$FRONTEND_PORT …"
(cd "$ROT/frontend" && NEXT_PUBLIC_API="http://localhost:$BACKEND_PORT" \
   npm run dev -- --port "$FRONTEND_PORT") &

# Vänta in backend, skriv sedan länkarna.
for _ in $(seq 1 60); do
  curl -sf "http://localhost:$BACKEND_PORT/docs" >/dev/null 2>&1 && break
  sleep 0.5
done

cat <<EOF

  ──────────────────────────────────────────────────────────────
  Serrier kör (dev-läge, auth av):
    Dashboard (scanner):   http://localhost:$FRONTEND_PORT
    Pre-Send Guardian:     http://localhost:$FRONTEND_PORT/guard
    API-docs:              http://localhost:$BACKEND_PORT/docs

  Skanna ett repo:    make scan REPO=/sökväg/till/repo
  Prevention live:    make guard CMD="claude"   (eller: serrier-guard run -- claude)
  Ctrl-C stänger allt.
  ──────────────────────────────────────────────────────────────
EOF

wait
