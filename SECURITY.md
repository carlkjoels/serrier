# Serrier — Security of Serrier itself

A security product that is itself insecure is worse than none — it holds a map of its
users' weaknesses and their secrets. Serrier therefore obeys the principles it recommends.

## Mandatory principles (applied, not aspirational)

1. **Least privilege** — scanners run with the minimum rights; no ambient DB/admin access.
2. **Defense in depth** — redaction + isolation + authz + audit, not one control.
3. **Secure by default** — egress deny-by-default; new projects isolated; nothing shared.
4. **Explicit authorization** — no file/credential/infra/network change without approval.
5. **Data minimization** — store the least evidence needed; prefer local processing.
6. **Separation of duties** — detection (deterministic) is separate from interpretation (AI).
7. **Input validation** — all untrusted input schema-validated; argv not shell strings.
8. **Immutable audit** — append-only audit events for scans, approvals, remediations.
9. **No secrets in logs** — structured logging with a secret-redaction filter on every sink.
10. **Fail-safe** — on uncertainty, fail closed (don't mark remediated/secure).

## Secret handling (the sharpest edge)

- Detected secrets are **redacted at the point of detection** (`sk-…abcd` → `sk-***`).
- Stored as a **redacted form + salted hash** for dedup/match — never full plaintext.
- If raw content must be held transiently, it is **crypto-shredded** using the
  `kryptoradering` pattern from selvra-analysis (per-item AES-256 key in a separate vault;
  deletion = key destruction; proof not receipt).
- A found secret is treated as **compromised**: remediation recommends **rotation/
  revocation**, never "just delete the line" (git history still holds it).

## Sending evidence to Claude

Never the whole repo or full conversation history. Only the **minimal redacted evidence**
for the specific finding, with secrets already masked. Every AI recommendation must cite
Finding IDs; the AI interprets evidence — it does not invent findings or declare security.

## Tenant / project isolation

Findings, evidence and source are isolated by `project_id`, enforced at the data layer and
re-checked by authz on every query. Cross-tenant access is a tested-against failure mode.

## Retention & deletion

Evidence is kept only as long as useful; sensitive evidence supports verifiable deletion
(crypto-shred). Users can request erasure of a project's data.

## Reporting a vulnerability (coordinated disclosure)

Serrier is pre-production and under active external review. Report privately — **do not open
a public issue** and **do not include live secrets** in a report.

- **Contact:** security@serrier.ai (until live, via a GitHub **private security advisory**:
  repo → Security → "Report a vulnerability").
- **Include:** affected component/commit, reproduction steps, observed vs. expected behavior,
  and severity per [`docs/security/red-team-brief.md`](docs/security/red-team-brief.md).
- **Our commitment:** acknowledge within 3 business days; a remediation plan or documented
  risk acceptance within 10 business days; credit on request after a fix ships.
- **Disclosure:** coordinated — no public details until a fix is released or a risk acceptance
  is documented. Safe-harbor for good-faith research that avoids privacy violations, data
  destruction, and service disruption.

A finding that merely confirms a *documented* coverage limit (see the red-team brief) is a
coverage report, not a vulnerability.
