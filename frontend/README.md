# Serrier dashboard (Next.js)

Professionell säkerhets-dashboard över den RIKTIGA API:n — ingen fabricerad data.
Visar posture, risk-fördelning (Recharts) och findings, tenant-isolerat per projekt-id.

## Kör
1. Starta backend: `cd ../backend && uv run uvicorn serrier.api.app:app` (port 8000).
2. Starta dashboard: `npm install && npm run dev` → http://localhost:3000.
3. API-adress via `NEXT_PUBLIC_API` (default http://localhost:8000).

Skapa ett projekt + scan via API:t, ange projekt-id i dashboarden.

Design: Robustium-stil (outline, hård offset-skugga, linjer). "Inga öppna fynd" ≠ "säker".
