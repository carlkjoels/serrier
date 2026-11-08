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

**Phase 0 (discovery & architecture).** No application code yet — see the planning
docs below. This README is a pointer, not a claim of a working product.

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — modules, central finding schema, stack, trust boundary.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — Serrier processes untrusted input; what can go wrong.
- [`ROADMAP.md`](ROADMAP.md) — phased plan; the smallest meaningful MVP.
- [`SECURITY.md`](SECURITY.md) — how Serrier secures *itself* (it follows its own advice).

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
