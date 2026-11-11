# Security Limitations (what Serrier does NOT do)

A security tool that hides its gaps is dangerous: it reads as "covered" when it isn't. This
document lists Serrier's **known coverage limits honestly**. Every item here is a deliberate
boundary or an accepted trade-off — not an oversight we're hoping you won't notice.

> Rule (from the red-team brief): wherever a capability is claimed, its limit is stated in the
> same breath. This file is the consolidated version of those limits.

## 1. Coverage ceiling — what traffic is inspected

The Pre-Send Guardian inspects **outbound HTTP(S) that a tool explicitly routes through it**
via `*_BASE_URL` to an allowlisted upstream (Anthropic/OpenAI/Gemini). That is the **same model
and the same ceiling** as the largest incumbent (Cloudflare AI Gateway).

**NOT inspected:**
- **MCP traffic**, arbitrary outbound HTTP, and **DNS-level egress** — anything that does not
  traverse the LLM-API endpoint at the proxy.
- Any tool **not pointed at** the Guardian. "Always-on" means "every AI tool routed through it,"
  not "all traffic on the machine."
- **Response bodies.** Responses are streamed through byte-for-byte; **response content is not
  inspected** (LLM05). Deliberate: inspecting responses would break SSE/streaming semantics and
  is a separate, unbuilt capability.

## 2. Request-inspection gaps (findings D/E boundaries)

- **Header values are not comprehensively inspected.** Auth headers are passed through (so we
  don't break the API call) and raw headers are never logged, but Serrier does **not** scan every
  header value for secrets. Claimed nowhere as covered. (Matrix INS-5.)
- **Binary / multipart bodies.** Bodies are decoded best-effort as UTF-8 for inspection. A secret
  embedded in a genuinely binary or multipart part may be missed. Compression *is* handled: any
  `Content-Encoding` other than `identity` → **UNKNOWN** (never inspected-safe), with the failure
  mode governing. But arbitrary binary content-types are not UNKNOWN-flagged. (Matrix INS-6.)
- **Detection recall is < 100%.** The classifier (regex + entropy + Luhn + evasion-normalization)
  will miss novel secret formats. UNKNOWN exists precisely because detection is fallible; it is
  never treated as SAFE. But "blocked everything sensitive" is not a claim we make.

## 3. Scanner isolation is resource-limiting, NOT sandboxing

`scanners/resurser.py` applies POSIX `rlimit` (CPU time + max file size) to scanner
subprocesses, plus a wall-clock timeout and argv-only (no shell) execution. This bounds a
runaway or hostile scanner's resource use.

It is **not a sandbox.** There is:
- no namespace isolation, no seccomp filter, no cgroup, no filesystem jail;
- a scanner runs with the **same uid** and can read what the parent process can read.

`RLIMIT_AS` (address space) is **deliberately not set** — it starved semgrep/osv (which mmap
large rule trees). This is a conscious trade-off: CPU+FSIZE give DoS protection without breaking
normal operation. Real isolation (cgroups v2 / seccomp / container-per-scan) is a **planned**
upgrade, not a shipped feature. We never call the subprocess boundary a sandbox. (Matrix ISO-1.)

On non-POSIX platforms (Windows) the rlimit preexec is a **no-op**; only the wall-clock timeout
applies. Stated, not hidden. (Matrix ISO-3.)

## 4. Audit is in-memory and bounded

The proxy audit is a **bounded ring buffer** (`deque(maxlen=1000)`) holding redacted verdicts
only. Two honest limits:
- It is **in-memory** — it does not survive a restart. A durable, tamper-evident audit log is
  **planned**, not built.
- Bounded means **old entries are dropped** at the cap. That is the correct DoS trade-off, but it
  means the in-memory audit is not a complete forensic record. (Matrix SEC-2.)

Events are separately reported (redacted) to the control plane for the dashboard; that path is
best-effort and must never block or crash the proxy.

## 5. Path confinement requires configuration

Workspace confinement (`SERRIER_WORKSPACE_ROOT`) is **canonical and symlink-aware** and enforced
at both the API and scanner boundaries. But when the variable is **unset**, there is no root to
confine against — this is the intended **dev mode**, documented as such, not a silent
"allow-all." In any multi-user or hosted deployment the root must be set. (Matrix PATH-1.)

## 6. Supply chain — pinned, checksum-verified, but not fully hermetic

- Scanner binaries are **pinned by version and SHA256-verified** before use (`sha256sum -c`,
  fail-closed). The gitleaks hash comes from the official `checksums.txt`; osv-scanner publishes
  no checksums file for the pinned version, so its hash was derived by fetching the TLS-verified
  release artifact and hashing it. Re-derive on any version bump.
- Base images are **pinned by tag, not by digest.** Digest-pinning (`image@sha256:…`) is the
  stronger form and is a **recommended pre-release upgrade**. (Matrix SUP-1/2.)
- `uv` is pinned (not `:latest`); semgrep is `==`-pinned; Python deps via `uv.lock --frozen`.
- Dependency vulnerability coverage equals the **osv database**; offline mode is optional.

## 7. Secrets found are treated as compromised

Detecting a secret does **not** make it safe. A found secret is treated as **compromised**:
remediation recommends **rotation/revocation**, never "just delete the line" (git history still
holds it). Serrier redacts at the point of detection and never persists/logs/returns the raw
value — but it cannot un-leak a secret that was already exposed before the scan.

## 8. Authentication boundaries

- **Dev mode is intentionally open** (no keys + `SERRIER_REQUIRE_AUTH` unset → a dev owner in a
  dev org) for local friction-free use. Production must set `SERRIER_REQUIRE_AUTH=1` **and** seed
  at least one owner key — and the config gate refuses to start otherwise. (Matrix CFG-1.)
- The proxy loopback token is **optional in dev** (`token=None` → open). The daemon/always-on
  form sets a stable token + Host-allowlist. CORS exists as a **dev-only** convenience for the
  dashboard; the packaged/same-origin form drops it (design 0004 §4).

## 9. What "verified" means here

No control in the verification matrix is `Independently verified` yet. Everything is at most
`Automated-test verified` (a named synthetic test). **216 passing tests prove coded behavior,
not resistance to a motivated attacker.** Independent review is the next milestone, and the
frozen `security-remediation` branch (tag `review-remediation-2026-11-09`) plus this branch's
before/after are structured for exactly that.

## 10. Explicitly out of scope (by design, this release)

- Generations 2–4 (context intelligence, behavioral security, correlation-at-scale) — gated in
  design 0003. Not built; not claimed.
- Agent tool/permission governance (OWASP ASI / LLM06) — planned, not covered.
- Network-layer egress firewalling, endpoint protection, and org-wide IAM — Serrier is a local,
  developer-native runtime, not an enterprise security platform.
