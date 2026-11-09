# Serrier.ai — Security intelligence for the AI-native era

AI lets anyone ship software faster than they can understand what they're exposing:
secrets, auth, env config, DB permissions, insecure AI-generated code, prompt
injection, scraping and network risk. **Serrier closes that gap** — it continuously
identifies, contextualizes, measures, prioritizes, and helps remediate those risks.

Serrier is not a scanner. It is a feedback loop:

> **Detect → Understand → Prioritize → Remediate → Verify → Learn**

Every finding carries **evidence · context · impact · remediation · verification**.
Serrier never claims a system is "secure" — it reports residual risk, confidence, and
coverage limits honestly.

## Status

**Phases 0–10 built.** Full MVP loop + all four modules + deployment hardening,
multi-tenant auth, cross-detector correlation, regression tracking and SARIF/JSON
export. Backend: 86 tests, ruff-clean. The product never claims "secure".

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — modules, central finding schema, stack, trust boundary.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — Serrier processes untrusted input; what can go wrong.
- [`ROADMAP.md`](ROADMAP.md) — phased plan; the smallest meaningful MVP.
- [`SECURITY.md`](SECURITY.md) — how Serrier secures *itself* (it follows its own advice).
- [`docs/security/framework-alignment.md`](docs/security/framework-alignment.md) — mapping to
  NIST CSF/Zero Trust, OWASP ASVS/LLM Top 10, CISA/ENISA Secure-by-Default, MITRE ATT&CK/ATLAS
  (**informed-by, not certified**; each row bounded to a tested control).
- [`docs/security/red-team-brief.md`](docs/security/red-team-brief.md) — external review brief.

### What exists now

| Capability | Where |
|---|---|
| Secret/dep/insecure-code scanning (builtin, gitleaks, semgrep, osv) | `backend/serrier/scanners/` |
| Central Finding schema (severity/confidence/status separate, stable id, redacted evidence) | `backend/serrier/core/` |
| SQLite→Postgres, Alembic migrations, Docker/Compose | `backend/`, `docker-compose.yml` |
| API-key auth, orgs, RBAC (viewer/member/owner), tenant isolation | `backend/serrier/auth.py`, `api/app.py` |
| Cross-detector correlation + regression (reappearance) tracking | `backend/serrier/correlation.py`, `db/store.py` |
| AI analyst (Claude) + approve→rescan→verify remediation | `backend/serrier/analyst.py`, `remediation.py` |
| Analytics, SARIF 2.1.0 / JSON export, Next.js dashboard | `backend/serrier/{analytics,export}.py`, `frontend/` |
| Scraping (Module B) + network/VPN posture (Module C) | `backend/serrier/scanners/{scraping,natverk}.py` |

## Run it

**Locally (dev, SQLite, auth off):**

```bash
# backend — http://localhost:8000
cd backend && uv run uvicorn serrier.api.app:app --reload

# frontend — http://localhost:3000
cd frontend && npm install && npm run dev
```

With no API keys configured the backend runs in dev mode (owner access, no auth) so the
flow is friction-free. Set `SERRIER_API_KEYS=key1,key2` (or bootstrap via `POST /orgs`)
to turn auth on; then pass the key as `Authorization: Bearer <key>` or `X-API-Key`.

**Full stack (Postgres + migrations + dashboard):**

```bash
cp .env.example .env          # fill in POSTGRES_PASSWORD, optionally ANTHROPIC_API_KEY
docker compose up --build     # db + backend (migrated) + frontend
```

**Migrations:** `cd backend && SERRIER_DB_URL=... uv run alembic upgrade head`.

## Pre-Send Guardian — prevention (stop exposure *before* it's sent)

Inspect outbound AI-API traffic locally and **block/redact secrets & PII before they reach
the provider**. Wrap any AI client so its traffic routes through a local loopback proxy:

```bash
serrier-guard run -- claude
serrier-guard run -- python my_ai_client.py
```

The wrapper starts the Guardian proxy on loopback, injects a one-time token via the child's
`ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL` (never in a process list), and enforces the policy:
secrets → **block**, cards/PII → **redact** (safe JSON rewrite, else block), clean → forward.
Detection is **local and deterministic** — the raw text never leaves your machine.

**Streaming works:** SSE / `stream=True` is relayed without buffering (verified with the real
Anthropic SDK's `messages.stream`), so Claude CLI streaming is preserved. Streaming the
response does **not** inspect response *content* — request-side prevention is the guarantee.

**Honest coverage:** only clients that respect `*_BASE_URL` and actually route through the
proxy are protected; a tool that hardcodes a direct connection bypasses it. **No transparent
MITM.** REDACT is JSON-only (else block). Design + threat model + residual risks:
[`docs/design/0002-guardian-proxy-adapter.md`](docs/design/0002-guardian-proxy-adapter.md).

## MVP scope (locked small, on purpose)

**Local AI Development Security + Security Analytics + evidence-backed Remediation.**
One flow, end to end, on a local repository: scan → central findings with evidence
and confidence → risk view → a *proposed* fix the user must approve → re-scan →
record whether risk actually dropped. Scraping (Module B) and Network (Module C) come
*after* the core is stable.

## Environment reality (verified 2026-11-08, drives the stack choices)

- Python 3.12 · uv · Node 22 — present.
- **gitleaks / semgrep / osv-scanner — NOT installed.** Needed for the MVP; installed
  in Phase 1, wrapped behind a scanner interface that degrades gracefully if absent.
- **Docker / Postgres server — NOT present.** So the MVP uses **SQLite via SQLAlchemy**
  (trivial Postgres migration later) and runs natively. Docker/Postgres are a *deployment*
  concern, deferred — not needed to build or measure the MVP.

## Principle

Serrier is a security product; its own architecture obeys the principles it recommends
(least privilege, secure-by-default, data minimization, explicit authorization, no
secrets in logs). Scanned files, repos, scraped sites and AI output are **untrusted
input** and are never executed or allowed to alter Serrier's own instructions.
