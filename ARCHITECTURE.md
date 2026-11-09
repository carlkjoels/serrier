# Serrier — Architecture

## Shape: modular monolith (not microservices)

One deployable Python backend with hard module boundaries and typed interfaces. No
microservices until a boundary demonstrably needs independent scaling. The frontend is
a separate app that talks to the backend over a typed API.

```
serrier/
  backend/
    core/            # central Finding schema, risk model, IDs, config, audit
    scanners/        # scanner interface + adapters (gitleaks, semgrep, osv, builtin)
    ingest/          # normalize + deduplicate findings into the central schema
    remediation/     # propose → approve → apply → re-scan → verify
    analyst/         # Claude integration (evidence in, interpretation out)
    api/             # FastAPI routes, auth, RBAC, rate limiting
    db/              # SQLAlchemy models + migrations (SQLite now, Postgres later)
  frontend/          # Next.js dashboard (added after backend value exists)
```

## The four modules (Section 2 of the brief)

- **A — AI Development Security** (MVP): secrets, .env, git history, deps, config, DB
  exposure, authz weaknesses, unsafe AI-generated code, prompt-injection in project files.
- **B — Web Scraping Security** (Phase 5): scraping infra, collection governance, content
  integrity. Scraped content = untrusted; never becomes agent instructions.
- **C — Network & VPN Security** (Phase 5): VPN/DNS-leak/egress analysis. Only
  user-owned/authorized systems. VPN ≠ anonymity.
- **D — Security Intelligence & Analytics** (MVP-lite): aggregate findings → posture,
  risk distribution, timeline, trends; the AI analyst.

## The spine: the central Finding schema

Everything flows through one normalized `Finding`. Scanners *produce* evidence; nothing
downstream invents it. **Severity, confidence, and remediation status are three separate
fields** — never collapsed into one number.

```
Finding
  id                stable, deterministic (hash of detector + location + rule)
  project_id        tenant isolation boundary
  category          secret | dependency | config | authz | injection | ...
  detector          gitleaks | semgrep | osv | builtin | ...
  severity          info | low | medium | high | critical     (impact if real)
  confidence        heuristic | probable | confirmed           (is it real?)
  status            detected | investigating | remediation_proposed |
                    remediation_approved | remediated | verified | accepted_risk
  asset_ref         file/line/commit/dependency/endpoint
  evidence[]        Evidence (see below) — redacted for secrets
  risk_score        derived, transparent (see risk model); never an AI-picked number
  first_seen / last_seen / history[]
```

`Evidence`: source · timestamp · location · detection_method · confidence · **redacted**
content or a secure reference. Raw secrets are never stored in plaintext (see SECURITY.md).

## Risk model (transparent, deterministic)

`risk_score = f(severity, exploitability, exposure, asset_importance, data_sensitivity,
existing_mitigations, confidence)` — a documented formula, inspectable per finding, with
each input shown. The AI analyst may *explain* the score; it never *is* the score.

## Trust boundary (the heart of a security product's own security)

Scanned repos, files, scraped sites, AI output, and external-tool stdout are **untrusted
data**. Rules:

1. Scanners run as argv subprocesses (no shell) with **resource limits** (CPU + output-size
   rlimits via preexec) and path confinement; scanned code is never executed. Honest limits:
   a subprocess is **not** a security sandbox, and a reliable *memory* cap plus true isolation
   (least privilege, network-egress block, namespaces) require a container/cgroups/OS sandbox —
   future work (F6).
2. Untrusted content can never modify Serrier's system instructions or security policy
   (defends against prompt injection hidden in files/scraped content).
3. Claude receives the **minimum necessary evidence, secrets redacted** — never whole
   repos or full histories by default. Every AI recommendation references Finding IDs.
4. Findings and evidence are isolated per project/tenant.

## Stack (chosen against verified environment)

- Backend: **Python · FastAPI · Pydantic · SQLAlchemy**.
- DB: **SQLite now** (SQLAlchemy → Postgres later with zero model changes). Postgres/Docker
  are deployment concerns, not MVP blockers.
- Scanners: **gitleaks · semgrep · osv-scanner** behind a `Scanner` interface + a built-in
  secret/env scanner; graceful degradation when a tool is absent.
- Frontend: **Next.js/React/TS/Tailwind**, charts via Recharts — added once the backend
  produces real findings (no dashboard over fabricated data).
- AI: Anthropic Claude, **structured outputs + tool use**, strict trusted/untrusted split.

## Reuse from existing work (disclosed)

The `selvra-analysis` project already has a verified **crypto-shredding** primitive
(`kryptoradering.py`: per-item AES-256 key in a separate vault, erasure = key destruction,
proof not receipt). Serrier should reuse that pattern for **sensitive evidence at rest**
(store redacted + crypto-shred-able evidence; honor deletion/retention). This is a genuine
asset, not a new build.
