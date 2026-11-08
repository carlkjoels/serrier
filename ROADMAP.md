# Serrier — Roadmap

Principle (Section 10 of the brief): a smaller, functioning, **measurable** product beats
a pile of half-built modules. Each phase must end with something demonstrable and tested.

## Phase 0 — Discovery & architecture  ✅ (this commit)
Environment inspected, stack chosen against reality, the five planning docs written. No
application code yet.

## Phase 1 — Core foundation + ONE real scanner (the MVP spine)
The smallest end-to-end loop on a **local repo**:
- Central `Finding` schema + `Evidence` + risk model (deterministic) in code, typed.
- SQLite via SQLAlchemy + migrations. Project + Scan + Finding + Audit tables.
- `Scanner` interface + **gitleaks** adapter (install) + a **built-in secret/.env scanner**
  (works even if external tools are absent — graceful degradation).
- Ingest: normalize + **deduplicate** findings by stable ID.
- FastAPI: create project, run scan, list findings. Secret redaction on the path in.
- Minimal CLI/API demo (no dashboard yet). Tests incl. a **false-positive** case.
**Done = scan a repo, get deduplicated, redacted, confidence-separated findings.**

## Phase 2 — Broaden AI-dev scanning
Add **semgrep** (insecure AI-generated code patterns) + **osv-scanner** (vulnerable deps)
+ git-history secret scan. Reliable ingestion/dedup across detectors. Precision/recall and
false-positive-rate measured on a fixture repo.

## Phase 3 — Analytics + dashboard
Security posture, risk distribution, timeline (detected→changed→remediated→verified→
reappeared), trends. **Next.js** dashboard over *real* findings (synthetic data clearly
labeled). Nothing fabricated as real.

## Phase 4 — AI analyst + remediation engine
Claude (structured outputs, tool use) explains findings, references Finding IDs, proposes
prioritized fixes. Remediation workflow: propose diff → **explicit approval** → apply →
re-scan → compare → record risk reduction. Exposed-secret flow = **recommend rotation/
revocation**, not just deletion. Nothing auto-applied to prod/credentials/network.

## Phase 5 — Scraping (Module B) + Network/VPN (Module C)
Independent modules, only after the core is stable. Untrusted scraped content stays data;
SSRF/egress controls enforced; authorized-only.

## Phase 6 — Deployment hardening  ✅
Postgres compatibility (testable `engine_kwargs`), Alembic migrations (own the schema in
prod via `SERRIER_SKIP_CREATE_ALL`), Docker/Compose (backend with scanners built in,
Next.js standalone, Postgres). A migration test asserts the schema matches the models.

## Phase 7 — Auth + multi-tenant  ✅
API keys (sha256-hashed, never stored raw, shown once), orgs as the tenant boundary,
RBAC (viewer<member<owner), tenant isolation (wrong org → 404, never leaks existence).
Dev mode (no keys configured) keeps the MVP friction-free.

## Phase 8 — Scanner depth + correlation  ✅
Cross-detector correlation (same asset flagged by ≥2 independent detectors → higher
priority, never altering a single finding's confidence). semgrep registry mode and osv
offline mode, both opt-in (network/non-determinism stays off by default).

## Phase 9 — Verification depth + export  ✅
Regression tracking: a verified/remediated finding that reappears is re-opened, counted
(`aterkomster`) and audited — the verify loop can run backwards when a fix doesn't hold.
SARIF 2.1.0 + JSON export (redacted evidence only — shareable without leaking).

## Phase 10 — Dashboard live-verification  ✅
Backend + frontend run end to end; dashboard surfaces correlations, regressions and
export; API-key field for auth-on mode. Verified live: real scan, redaction holds,
SARIF 2.1.0 output, standalone frontend build.

## Milestone — `v0.1.0` (tag)
Phases 0–10 are a stable, verifiable baseline. Compare future work against it; do not make
it harder to verify.

## Phase 11 — Pre-Send Guardian (prevention)  ◻ designed, not built
Shift from detecting problems at rest to **preventing exposure in motion**. Design in
[`docs/design/0001-pre-send-guardian.md`](docs/design/0001-pre-send-guardian.md). The spine
is Detection ≠ Decision ≠ Enforcement; the MVP is a local, deterministic decision core
(`POST /guard/inspect`) reusing the builtin detection engine — enforcement adapters come
one at a time, each declaring whether its block is *guaranteed* or *best-effort*. Build in
small steps (refactor shared core → classify+PII → policy → inspect → adversarial recall →
one adapter).

## Target picture (NOT a backlog — a direction)
The strategic vision (Secure AI Adoption Infrastructure: policy/model gateway, agent
governance, enterprise control plane, Serrier Secure Environments / air-gap) is a *target*,
deliberately gated behind the Guardian earning a real user. Scope explosion is the primary
product risk (design doc R1). Nothing here is built until the prevention MVP is validated.

## Deferred on purpose (not forgotten)
- Cross-detector *finding* correlation beyond same-asset (semantic dedup across rules).
- Live browser E2E in CI; reporting exports beyond SARIF/JSON (PDF/CSV).
- Real OSV/semgrep registry runs in CI (network-gated); key rotation/expiry for API keys.

## What "done" never means
"Serrier says you're secure." It means: measured coverage, separated severity/confidence/
status, honest residual risk — and a loop that proves a fix actually reduced risk.
