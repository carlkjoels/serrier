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

## Deferred on purpose (not forgotten)
- Postgres + Docker/Compose — deployment hardening, after the MVP proves value.
- RBAC/orgs/multi-tenant hardening — beyond single-user MVP.
- Verification depth, repeated-vuln analytics, reporting exports.

## What "done" never means
"Serrier says you're secure." It means: measured coverage, separated severity/confidence/
status, honest residual risk — and a loop that proves a fix actually reduced risk.
