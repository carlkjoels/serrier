# Remediation Verification Report — `security-remediation` branch

Independent verification round (2026-11-09) of the fixes for the external static review's
seven findings. **Method:** for each fix, (1) re-attempt the original attack on the new
branch, (2) try negative/adversarial variants, (3) confirm no prior functionality broke,
(4) report unresolved risk **without** calling it fixed. Adversarial tests:
`backend/tests/test_security_verification.py` (7). Fix-pinning tests:
`test_security_fixes.py` (14). Full suite: **174 passed**.

This report is for the reviewer to read *alongside* independently re-reviewing the after
version — not as a substitute for it. The goal is the eighth problem we did not find.

## Per-finding verdict

| # | Original vuln | Re-attempt on new branch | Adversarial variants tried | Verdict |
|---|---|---|---|---|
| **F1** | Docker open admin (no auth, 0.0.0.0, default pw) | Ports loopback-bound; `REQUIRE_AUTH=1`; refuse-start if no keys; open `/orgs` 403 in auth mode | `REQUIRE_AUTH="0"`/any value still enforces (fail-safe), protected endpoint 401 w/o key | **Closed** |
| **F2** | Client picks arbitrary server path | Confined to `SERRIER_WORKSPACE_ROOT` | `../` traversal → 403; string-prefix sibling (`/ws-evil` vs `/ws`) → 403; symlink-out → 403 | **Closed** (residual: TOCTOU on the scan root between validate and walk — reviewer item) |
| **F3** | Large chunked body fully buffered | Streaming read aborts at limit | exact-limit → ok, +1 byte → 413; no-Content-Length chunked → 413 | **Closed** (residual: CL/TE desync *into* the proxy depends on uvicorn/h11 parser — reviewer item) |
| **F4** | Headers & query uninspected | Query now inspected (incl. %-encoded) | URL-encoded secret in query → block; **secret in a header → forwarded (proven)** | **Partial — by design.** Query covered; **headers are NOT prevention** (documented + test). |
| **F5** | Encoded body → `analysis_status=ok` | `Content-Encoding≠identity` → UNKNOWN | casing `GZIP` → unknown; `identity`+secret → inspected (ok) & blocked | **Closed for declared encoding.** Open: see residual below. |
| **F6** | Scanner isolation unproven | CPU + file-size rlimits added; ARCHITECTURE corrected | file-size limit kills over-writing child | **Partial.** No reliable memory cap (RLIMIT_AS removed — it starved semgrep). |
| **F7** | Token in stdout, unbounded audit, thin policy audit, cross-project `.env`, `uv:latest`, no checksums, stale README/SECURITY | token→0600 file; audit=deque(1000); policy audit incl. table; `.env` dependency removed; uv pinned + checksum **mechanism**; disclosure process; README | token never on stdout; audit bounded at 1000 | **Closed in code; release work remains** (real SHA256 values). |

## Regression (new boundaries didn't break old behavior)

- **Full suite 174 passed.** The F2 confinement and F1 auth-gate are env-gated (inactive in
  dev/tests), so they don't affect existing flows.
- **Near-miss caught by existing tests, disclosed:** the first F6 attempt set `RLIMIT_AS=4 GB`,
  which **starved semgrep** (it over-reserves virtual memory) → the matning/semgrep tests went
  red. Fixed by dropping the address-space limit. This is exactly why the memory cap is listed
  as unresolved below, not claimed.

## UNRESOLVED risks — reported, NOT fixed

1. **Headers are not content-inspected (F4).** A secret placed in a request header reaches the
   provider. This is a deliberate coverage boundary (provider auth headers must pass), proven by
   `test_v_f4_header_ar_INTE_prevention_dokumenterat_gap`. Documentation ≠ prevention — the
   reviewer must confirm nothing implies full request inspection.
2. **Encoded-without-declaration body (F5).** A gzip body sent *without* a `Content-Encoding`
   header is inspected as text → can become `analysis_status=ok`
   (`test_v_f5_gzip_utan_header_ar_oloest_residual`). Functional leak is limited (an upstream
   that wasn't told it's gzip won't decode it either), but the *claim* "inspected" is wrong for
   such content. A binary/high-replacement-char heuristic would close it — deferred (would be
   new detection; out of remediation scope).
3. **No reliable memory cap on scanners (F6).** CPU + output-size rlimits exist; a true memory
   limit and process isolation need cgroups/container. Future security work.
4. **Supply-chain checksums are a mechanism, not a completed control (F7).** The Dockerfile now
   *requires* `GITLEAKS_SHA256`/`OSV_SHA256`, but the real published values must be filled in by
   the release process. uv is pinned.
5. **Cross-surface / cross-request splitting.** A secret split across query+body, or across
   multiple requests, is not correlated and can evade. No cross-request state in v1.
6. **TOCTOU items for the reviewer:** scan-root swap between validation and walk (F2); CL/TE
   desync into the proxy (F3) — both depend on components (filesystem race, uvicorn/h11) worth
   independent probing.

## Verdict

P0 (F1) and the High findings F2/F3/F5 are closed with adversarial tests. F4 is **partial by
design** (query closed, headers an explicit non-claim). F6 is **partial** (no memory cap). F7
is **closed in code, pending release values**. This matches the reviewer's own assessment
(F4 partial, F6 partial, F7 release work) — no fix is over-stated. Branch frozen for review.
