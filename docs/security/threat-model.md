# Serrier — Threat Model (security-runtime scope)

This is the **security-runtime** threat model: it extends the repo-root
[`THREAT_MODEL.md`](../../THREAT_MODEL.md) (which covers the scanner/intelligence side, threats
T1–T10) with the **Pre-Send Guardian** surface and ties every threat to a control and a
verification-matrix ID. It is a living risk analysis, not a formal model.

> Continuity: the original T1–T10 IDs from the root threat model are preserved and
> cross-referenced; new Guardian-specific threats are G-prefixed below.

## Assets (what's worth protecting)

1. **Detected secrets** (API keys, tokens, credentials) — the most dangerous asset.
2. **Scanned source** of users' projects (often private).
3. **Findings & evidence** — a map of each project's weaknesses.
4. **Outbound AI-API payloads** — prompts/context a developer is about to send to a provider.
5. **Serrier's own credentials** — Claude key, DB, proxy token.

## Trust boundaries

- **Untrusted:** scanned repos/files, git history, scraped content, scanner stdout, AI output,
  **and every outbound request body/query the Guardian inspects.** Crossing into Serrier = treat
  as hostile data.
- **Semi-trusted:** the authenticated user (may paste hostile content unknowingly).
- **Trusted:** Serrier's core code, security policy, system prompts.
- **Hostile-by-assumption:** any other local process (→ proxy token), any page that can trigger
  a loopback request (→ Host-allowlist, DNS-rebinding defense).

## Threats → controls → evidence

| # | Threat | Control | Matrix / test | Impl / Verification |
|---|---|---|---|---|
| **T1** | Secret leaked (stored/logged/sent in plaintext) | Redact at detection; redacted+hashed storage; never log raw; token→0600 file | LEAK-2, SEC-1,3 | Implemented / Automated-test |
| **T2** | Prompt injection via scanned/scraped content | Trusted/untrusted split; untrusted = fenced DATA; only deterministic logic sets status | (analyst design) | Partially / Not verified |
| **T3** | Command injection / RCE via scanner args | argv arrays, no shell; validated paths | (scanner tests) | Implemented / Automated-test |
| **T4** | Path traversal escapes project root | Canonical + symlink-aware confinement, API **and** scanner boundary | PATH-1..4 | Implemented / Automated-test |
| **T5** | SSRF / DNS rebinding to private/metadata IP | Resolve+reject non-global; **pin to validated IP** (TOCTOU); Host-allowlist | NET-1,2,3 | Implemented / Automated-test |
| **T6** | Executing untrusted/AI-recommended code | Never auto-execute; remediation = proposed diff + human approval | (remediation tests) | Implemented / Automated-test |
| **T7** | Cross-tenant leakage | `project_id` isolation at data layer + authz per query; 404 no existence leak | TEN-1,2 | Implemented / Automated-test |
| **T8** | Resource exhaustion (zip-bomb, huge repo, runaway scanner) | Scanner CPU/FSIZE rlimit + wall-clock timeout; per-file caps; **streaming** body limit | ISO-1..4, REQ-1..4 | Implemented / Automated-test |
| **T9** | Insecure deserialization of hostile content | No pickle/eval on untrusted data; schema-validated parsing | (parsing tests) | Implemented / Automated-test |
| **T10** | False confidence ("secure", user ships a hole) | Never claim "secure"; UNKNOWN≠SAFE; separate severity/confidence/status; documented limits | POL-1..4 | Implemented / Automated-test |

### Guardian-specific threats (new surface)

| # | Threat | Control | Matrix / test | Impl / Verification |
|---|---|---|---|---|
| **G-1** | Secret smuggled in URL query (not body) | Inspect `unquote(query)`; sensitive → block | INS-1,2 | Implemented / Automated-test |
| **G-2** | Secret hidden in gzip/deflate/br body passed as "safe" | Content-Encoding≠identity → UNKNOWN; fail-mode governs; never inspected-safe | INS-3,4 | Implemented / Automated-test |
| **G-3** | Memory-DoS via unbounded request buffering | Streamed byte-count aborts mid-read (chunked/no-CL/lying-CL) | REQ-2,3 | Implemented / Automated-test |
| **G-4** | Another local process abuses the proxy | Loopback-only bind + constant-time token (path or header) | AUTH-4 | Implemented / Automated-test |
| **G-5** | DNS-rebinding against the loopback service | Host-header allowlist (the one defense Origin can't give) | NET-3 | Implemented / Automated-test |
| **G-6** | Insecure config ships (default pw, open auth, net-exposed) | Secure defaults; refuse-insecure-start (lifespan + entrypoint) | CFG-1..4 | Implemented / Automated-test |
| **G-7** | Tampered scanner binary (supply chain) | Pinned version + SHA256 verify (fail-closed); pinned toolchain | SUP-1,2 | Implemented / Automated-test |
| **G-8** | Secret pulled from another app's `.env` | `ladda_nyckel` reads env only; no cross-project file read | SEC-4 | Implemented / Automated-test |

## Residual risk (accepted or deferred)

- **One channel only.** The Guardian covers explicit loopback-routed AI-API traffic; MCP,
  arbitrary HTTP, DNS egress, and **response bodies** are out of scope (see
  [`security-limitations.md`](security-limitations.md) §1).
- **Resource-limited ≠ sandboxed.** Scanner isolation bounds resources but is not a jail (§3).
- **In-memory audit** is bounded and non-durable (§4).
- **Detection recall < 100%** — UNKNOWN exists because detection is fallible (§2).
- **Not independently verified yet** — synthetic tests only; external review pending.

## Non-goals (abuse prevention)

Serrier assesses only systems/repos the user **owns or is authorized** to assess. It does not
bypass CAPTCHA/auth/anti-bot controls, and never equates VPN connectivity with anonymity or
comprehensive security.
