# Serrier — Security Remediation & Framework Alignment — Final Audit Report

**Date:** 2026-11-09 · **Branch:** `security-hardening` (off `main` @ `2ee540c`) · **Role:**
principal appsec / independent auditor. Nothing merged or pushed; frozen review branch untouched.

## A. Executive summary

The seven previously-identified findings (A–G) were **re-verified against the current `main`
surface** (not assumed from prior audits) and **re-applied + adapted** — `main` had diverged from
the frozen `security-remediation` branch (it gained the daemon, live-events, CORS, Host-allowlist,
event-logging), so a straight merge was wrong. Each fix landed on the newer code, with **at least
one negative regression test per finding** proving the *insecure* path is now refused.

Result: **216 backend tests pass** (171 baseline + 45 new), `ruff check serrier tests` clean,
Alembic migrates to head, frontend builds. Framework mappings were **rebuilt with identifiers
verified against official sources** (NIST CSF 2.0 subcategories, SP 800-207, MITRE ATT&CK/ATLAS,
OWASP Top 10:2025 + LLM Top 10:2025 verbatim; ASVS upgraded from 4.0 to **5.0.0 chapter
structure**). Six security docs are in place, every claim traceable to a file + test.

**No control is independently verified yet** — the work is structured *for* that review, which is
the next milestone. The objective was to make Serrier **more secure and prove what's true**, not
to look secure; coverage gaps (header/binary inspection, in-memory audit, resource-limit-not-
sandbox) are documented as plainly as the fixes.

## B. Security findings

| ID | Issue | Root cause | Fix (files) | Tests | Verification |
|---|---|---|---|---|---|
| **A** | Insecure default config could start silently (default DB pw, net-exposed, dev-owner reachable, open `/orgs`) | Convenience defaults never gated for prod | `docker-compose.yml` (loopback bind, `REQUIRE_AUTH=1`, no default pw), `api/app.py::krav_sakra_konfig` + `/orgs` guard, `docker-entrypoint.sh` | `test_security_hardening.py::test_A_*` (8) | Automated-test |
| **B** | Scan path could escape the workspace (traversal/symlink) | No canonical confinement at API/scanner boundary | `core/sokvag.py` (new), `api/app.py::scan`, `scanners/registry.py` | `test_B_*` (7) | Automated-test |
| **C** | Body size checked *after* buffering → chunked/no-CL bypass, memory-DoS | `await request.body()` buffers whole body first | `guardian/proxy.py::_las_begransad` (streamed abort) | `test_C_*` (5) | Automated-test |
| **D** | Secrets in URL query not inspected | Only body was inspected | `guardian/proxy.py::_hantera` (query `unquote` + block) | `test_D_*` (3) | Automated-test |
| **E** | Compressed body could pass as inspected-safe | No handling of `Content-Encoding` | `guardian/proxy.py::_hantera` (encoding → UNKNOWN; fail-mode governs; forward-unchanged only in permissive) | `test_E_*` (4) | Automated-test |
| **F** | Scanner subprocess unbounded; "sandbox" overclaim | No rlimit; doc imprecision | `scanners/resurser.py` (new, CPU+FSIZE, **no RLIMIT_AS**), 3 adapters; ARCHITECTURE corrected | `test_F_*` (4) | Automated-test |
| **G** | Token to stdout; unbounded audit; cross-project `.env`; unpinned/unchecked supply chain | Multiple hygiene gaps | `guardian/proxy.py::skriv_token` + `deque(maxlen)`, `daemon.py`, `analyst.py`, `Dockerfile` (SHA256-verify, pinned uv), `SECURITY.md` (disclosure) | `test_G_*` (6) | Automated-test |

Checksums are **verified, not invented**: gitleaks from the official `checksums.txt`
(`551f6fc…`), osv-scanner by fetching the TLS-verified release artifact and hashing it
(`8cdb138…`, no upstream checksums file exists for that version).

## C. Framework alignment (verified identifiers)

Full matrix in [`framework-alignment.md`](framework-alignment.md); evidence in
[`security-verification-matrix.md`](security-verification-matrix.md). Highlights:

- **NIST CSF 2.0** — mapped to verified subcategories (PR.AA-01/03/05, PR.DS-01/02, DE.CM-01/09,
  GV.PO-01/02, GV.SC, PR.PS-01/04/06).
- **Zero Trust (SP 800-207)** — proxy = PEP, `policy.py` = local PDP; tenets 2/4/6 mapped. Bounded:
  not a full ZTA.
- **ASVS 5.0.0** — chapter-level (V6 Auth, V8 Authz, V2 Validation, V5 File Handling, V4 API,
  V11 Crypto, V12 Secure Comm, V13 Config, V14 Data Protection, V16 Logging). Requirement-level
  sub-IDs **not** asserted (could not verbatim-verify → omitted, not invented).
- **OWASP Top 10:2025** — A01/A02/A03/A04/A05/A09/A10 mapped. **LLM Top 10:2025** — LLM02/01/03/05/06/10.
- **MITRE ATT&CK** T1041, T1567.001, T1552.001 · **ATLAS** AML.T0024, AML.T0057.
- **Honest verification method note** is in the doc: IDs confirmed via official-domain search
  (raw-spec fetch unavailable); unconfirmed IDs omitted.

Language throughout: *mapped to / informed by / implements selected controls from / partially
addresses* — never *compliant* or *certified*.

## D. Remaining risks (ranked)

| Sev | Risk | Status | Reference |
|---|---|---|---|
| **High** | Coverage ceiling: only loopback-routed AI-API traffic inspected; MCP/arbitrary HTTP/DNS/**response bodies** not covered | Accepted boundary (same as incumbents), documented | limitations §1, LEAK-5 |
| **Medium** | Header values not comprehensively inspected; binary/multipart bodies best-effort UTF-8 (may miss secrets) | Documented gap, not claimed as covered | limitations §2, INS-5/6 |
| **Medium** | Scanner isolation is resource-limiting, **not** a sandbox (same uid, no seccomp/cgroup) | Documented; real isolation is Planned | limitations §3, ISO-1 |
| **Medium** | Detection recall < 100% (novel secret formats) | UNKNOWN≠SAFE mitigates; not eliminated | limitations §2 |
| **Low** | Audit is in-memory + bounded (non-durable) | Durable tamper-evident audit is Planned | limitations §4, SEC-2 |
| **Low** | Base images pinned by tag, not digest | Digest-pinning recommended pre-release | limitations §6, SUP-2 |
| **Low** | Nothing independently verified yet (synthetic tests only) | External review is the next milestone | limitations §9 |

No **critical** open items in the A–G scope.

## E. Test results

```
backend:  uv run ruff check serrier tests   → All checks passed
          uv run pytest -q                   → 216 passed (~90s)
            of which test_security_hardening.py → 45 (A–G regression)
          uv run alembic upgrade head        → head 90a5d08b470f (exit 0)
frontend: npm run build                      → ✓ Compiled successfully; types valid; 5 pages (/ , /guard)
```
(`scanfixtur/` is a deliberately-vulnerable scan fixture and is intentionally outside the lint
scope — `make lint` targets `serrier tests`.) No test was deleted, weakened, skipped, or rewritten
to pass. Every "pass" above was executed in this session.

## F. Release recommendation

**Ready for external review.** The A–G fixes are implemented and each proven by a negative test;
docs are honest and traceable; the suite/build/migrations are green. It is **not** ready for
external *users* or a "secure" claim — that requires the independent review this work is built
for, plus closing the documented Medium risks (header/binary inspection, real scanner isolation,
durable audit). Recommendation tier, explicitly: **Ready for external review** (not "internal
only", not "not ready").

## A-bis. Post-remediation adversarial self-review (same day)

Before handing PR #1 to external review, an adversarial pass tried to get *around* the A–G
fixes. It found one real **fail-open** the regression tests missed, now fixed:

- **FYND 1 (fail-open, fixed) — `SERRIER_REQUIRE_AUTH` split-brain.** Three sites read the var
  differently: `nuvarande_principal` used a raw truthiness check while `krav_sakra_konfig` and
  `skapa_org` used `_sant()`. With `SERRIER_REQUIRE_AUTH="false"` + no keys, `POST /projects`
  returned 401 (looked locked) while `POST /orgs` returned 200 and **minted an owner API key to
  anyone**. Fix: a single shared `_auth_kravs()` helper used by all three sites — falsy now means
  dev-open *consistently*, truthy locks both. Tests: `test_A_require_auth_tolkas_konsekvent_falsy`,
  `test_A_require_auth_sant_laser_bade_orgs_och_projects`.
- **FYND 1b (unusable-config, fixed) — `API_KEYS=","`.** The config gate checked the raw string
  was non-empty, so `","`/whitespace passed but seeded zero keys → auth-required-but-no-key
  brick. Fix: `giltiga_nycklar()` counts real keys (same parse as seed). Test:
  `test_A_konfig_vagrar_nar_api_keys_saknar_giltig_nyckel`.
- **FYND 2 (guarantee-hardening, fixed) — double-encoded query.** A single `unquote()` let a
  double-encoded secret (`?q=%2573k-…`) hide. Not a plaintext leak (upstream doesn't double-decode
  and the key isn't sent there), but it broke the "we see query secrets" guarantee. Fix:
  `_unquote_fixpunkt()` decodes to a fixpoint (max 5 rounds). Test:
  `test_D_dubbelkodad_hemlighet_i_query_blockeras`.

The reviewer also **confirmed it could not break** B (traversal/symlink, API+scanner), C
(streaming limit, lying/missing CL), E (encoding variants), the proxy token/Host-allowlist,
SSRF/IP-pinning, F (rlimit, semgrep not starved), or G (token 0600, bounded audit, env-only
key, Dockerfile checksum) — which strengthens the review. Suite now **233 passed**.

## G. Git state

- **Branch:** `security-hardening` @ `main` (`2ee540c`). **Nothing committed, pushed, or merged.**
- **Modified (14):** ARCHITECTURE.md, SECURITY.md, docker-compose.yml, backend/Dockerfile,
  docker-entrypoint.sh, analyst.py, api/app.py, daemon.py, proxy.py, 3 scanner adapters,
  registry.py, framework-alignment.md.
- **New (7):** `core/sokvag.py`, `scanners/resurser.py`, `tests/test_security_hardening.py`,
  `docs/security/{security-architecture,security-limitations,security-verification-matrix,threat-model}.md`.
- **Frozen review branch untouched:** tag `review-remediation-2026-11-09` (`5cd2c5a`),
  `security-remediation` (`9bfc951`) — both intact.
- **Awaiting explicit approval** before any commit / PR / merge / push.
