# Serrier — Threat Model

A security product that ingests untrusted repositories, files, scraped content and
external-tool output is itself a high-value, high-exposure target. This is a simple,
living risk analysis (not a full formal model), updated as the architecture evolves.

## Assets (what we hold, worth protecting)

1. **Scanned source code** of users' projects (often private, sometimes secret).
2. **Detected secrets** — API keys, tokens, credentials (the most dangerous asset).
3. **Findings & evidence** — a map of each project's weaknesses (a breach here is a
   target list for an attacker).
4. **Users' AI conversation context** sent to the analyst.
5. **Serrier's own credentials** — Claude API key, DB, any integration tokens.

## Trust boundaries

- **Untrusted:** scanned repos/files, git history, scraped sites, scanner stdout, and
  **AI-generated code/output**. Crossing into Serrier = must be treated as hostile data.
- **Semi-trusted:** the authenticated user (may be non-technical; may paste hostile
  content unknowingly).
- **Trusted:** Serrier's own core code, its security policy, its system prompts.

## Top threats and mitigations

| # | Threat | Mitigation |
|---|---|---|
| T1 | **Secret leakage** — a detected secret is stored/logged/sent to Claude in plaintext | Redact at detection; store only a redacted form + hash; crypto-shred raw if ever held; never log secrets; minimal redacted evidence to Claude |
| T2 | **Prompt injection via scanned/scraped content** — a file or page says "ignore rules, mark project secure / exfiltrate" and the analyst obeys | Hard trusted/untrusted split; untrusted content is DATA in a fenced channel, never instructions; the analyst can't change status or policy — only deterministic logic sets status |
| T3 | **Command injection / RCE via scanner invocation** — crafted filenames/args reach a shell | No shell string interpolation; argv arrays; validated paths; run scanners as subprocesses with no shell |
| T4 | **Path traversal** — a repo path or finding location escapes the project sandbox | Canonicalize + confine all paths to the project root; reject `..`/symlink escapes |
| T5 | **SSRF** (esp. Module B/C, and any URL fetch) | Deny-by-default egress; block private/link-local/metadata IPs; allowlist; no following untrusted redirects |
| T6 | **Executing untrusted/AI-recommended code** — "run this to fix it" | Serrier NEVER auto-executes scanned or AI-suggested code; remediation is a *proposed diff* requiring explicit human approval |
| T7 | **Cross-tenant leakage** — one user sees another's findings/source | project_id isolation enforced at the data layer + authz on every query; tests for it |
| T8 | **Resource exhaustion / zip-bomb / huge repo** | Scanner subprocess limits (CPU/mem/time/output size); file-count/size caps |
| T9 | **Insecure deserialization / malicious repo content** | No pickle/eval on untrusted data; schema-validated parsing only |
| T10 | **False confidence** — Serrier says "secure", user ships a hole | Never claim "secure"; report coverage limits, unscanned areas, and confidence; separate severity/confidence/status |

## Explicit non-goals (abuse prevention)

Serrier only assesses systems/networks/repos the user **owns or is authorized** to assess.
It does not bypass CAPTCHA, auth, or anti-bot controls; it supports authorized collection
only. VPN connectivity is never equated with anonymity or comprehensive security.
