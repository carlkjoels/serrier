# Serrier — Security Architecture

This is the **security view** of the architecture: the enforcement components, the decision
flow, and the invariants that must hold for Serrier to be trustworthy. It extends the repo-root
[`ARCHITECTURE.md`](../../ARCHITECTURE.md) (overall shape, module map, Finding schema).

## Two halves, one control plane

Serrier is two cooperating halves that share a control plane and dashboard:

1. **Security Intelligence** (detect risk in code at rest) — scanners → normalized `Finding`
   schema → correlation/analytics → AI analyst (evidence in, interpretation out).
2. **Prevention Infrastructure** (stop exposure before it's sent) — the **Pre-Send Guardian**:
   a local loopback proxy that inspects outbound AI-API traffic and blocks/redacts/allows.

```
AI tool ──BASE_URL──▶ Guardian proxy (127.0.0.1, token)
                         │  inspect(request)  ── decision core ──▶ block / redact / forward
                         │                                         │
                         ▼                                         ▼ (forward only)
                   control plane ◀── redacted event ──┐     validated upstream (TLS, IP-pinned)
                   (SQLite/PG, RBAC, tenants)         │
                         │                            └── dashboard live feed (redacted only)
                         ▼
                   scanners ──▶ Finding schema ──▶ analytics / analyst
```

## The decision core (shared, deterministic)

One enforcement core is reused by every integration (proxy, CLI, daemon):

- `core/textdetect.py` — detection primitives.
- `guardian/classify.py` — PII + Luhn + entropy + evasion-normalization (homoglyph/zero-width/
  base64/spacing).
- `guardian/policy.py` — the **PDP**: three failure modes (`STRICT`/`BALANCED`/`PERMISSIVE`) and
  **UNKNOWN as a first-class state**; strictest-action-wins.
- `guardian/inspect.py` — chains detection → policy → redaction, returns a `GuardDecision` with
  an opaque `safe_text` (raw hits never leave).

**Invariant: UNKNOWN ≠ SAFE.** Detection failure, an unparsable body, or an encoding we can't
read all produce `analysis_status=unknown`; the failure mode decides the action, and the audit
always carries the status so it never *looks* inspected-safe.

## The Guardian proxy (PEP) — enforcement boundary

`guardian/proxy.py` is a Policy Enforcement Point (NIST 800-207 terms) for the AI-API channel:

- **Routing, not MITM.** Tools point `*_BASE_URL` at the proxy; it forwards to an **allowlisted**
  upstream. No TLS interception, no cert-pinning breakage. (Coverage ceiling: design 0004 §2.)
- **Request inspection** (before forward): body (streamed, size-limited), **query string**
  (`unquote`), and **content-encoding** (→ UNKNOWN if compressed). Response bodies are relayed
  **uninspected** by design.
- **Egress safety:** strict upstream allowlist (no wildcard); SSRF guard resolves + rejects
  non-global IPs and **pins the connection to the validated IP** (DNS-rebinding TOCTOU fix);
  SNI/Host preserved.
- **Loopback hardening:** bound to `127.0.0.1`; constant-time **token** (path or header);
  **Host-header allowlist** against DNS rebinding in daemon mode.
- **Fail-closed everywhere:** oversized → 413; non-global upstream → 502; upstream error → 502;
  redact-can't-produce-safe-JSON → block. Never blind-forward.

## Control plane & tenancy

`api/app.py` + `db/store.py`: FastAPI + SQLAlchemy (SQLite→Postgres), API-key auth
(sha256-hashed, constant-time), RBAC (viewer<member<owner), and **tenant isolation by
`project_id`** enforced at the data layer with authz on every query (cross-tenant → 404, no
existence leak).

**Secure by default (finding A):** `krav_sakra_konfig()` refuses to start a prod config where
auth is required but no key is seeded (lifespan **and** entrypoint); compose binds loopback,
requires an explicit DB password, and sets `SERRIER_REQUIRE_AUTH=1`. Dev stays friction-free.

## Filesystem confinement (finding B)

`core/sokvag.py` provides canonical, symlink-aware confinement (`realpath` + component-wise
`is_relative_to`) against traversal, symlink-escape, and prefix-confusion. Enforced at **both**
the API boundary (`scan`) and the scanner boundary (`kor_skanners`) — defense in depth. Active
when `SERRIER_WORKSPACE_ROOT` is set (unset = documented dev mode).

## Scanner execution (finding F)

External scanners run as subprocesses with **argv arrays (no shell)**, a wall-clock **timeout**,
and POSIX **rlimit** (CPU + file size) via `scanners/resurser.py`. `RLIMIT_AS` is deliberately
unset (it starved semgrep). This is **resource-limiting, not sandboxing** — stated plainly in
code and in [`security-limitations.md`](security-limitations.md) §3.

## Secret & token hygiene (finding G)

- Secrets redacted at detection; stored redacted + hashed; never logged/persisted/returned raw.
- The proxy **token** is written to a **0600 file**, never stdout/logs (`skriv_token`, shared by
  daemon and foreground).
- The audit is an in-memory **bounded ring buffer** (`deque(maxlen=1000)`) of redacted verdicts.
- `ladda_nyckel` reads the API key from the **environment only** — no cross-project `.env`.
- Supply chain: pinned + SHA256-verified scanner binaries; pinned `uv`/semgrep; `uv.lock --frozen`.

## Architectural invariants (must hold)

1. Local-first, prevention-first; **no MITM**.
2. Deterministic policy; **explicit allowlist**; **strictest-wins**.
3. **UNKNOWN ≠ SAFE**; fail-closed on uncertainty.
4. **No raw secret** in logs, audit, persistence, or responses.
5. Model/vendor independence; transparent coverage; **never claim "secure."**
6. **Human approval** for destructive/outward actions (remediation = propose→approve).
7. Four epistemic states kept distinct: **observation ≠ correlation ≠ risk ≠ incident**.

## Reuse (disclosed)

The **crypto-shredding** primitive (per-item AES-256 key in a separate vault; erasure = key
destruction, proof not receipt) is a **pattern** Serrier applies to sensitive evidence at rest.
It is referenced as a design pattern, not a runtime dependency on another project's code or
secrets (see finding G: no cross-project `.env` coupling).
