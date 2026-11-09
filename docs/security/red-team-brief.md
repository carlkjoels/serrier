# Serrier — Red-Team & External Security Review Brief

Scope: **Pre-Send Guardian (Generation 1 — Prevention Runtime)** — the local loopback proxy
(`backend/serrier/guardian/proxy.py`), CLI wrapper (`run.py`), and decision core
(`inspect`/`classify`/`policy`/`core/textdetect`). This is what gets placed in front of real
AI clients, so it is the live attack surface. Baseline: tag `v0.1.0` + Guardian commits.

## Reviewer mandate (read first)

**Do not confirm that our tests pass. Try to get around them.** Construct new payloads,
new routing paths, new encodings, and new timing conditions that our 160-test suite does not
cover. A finding is valuable precisely when it is something we did not think to test.

The product makes exactly one hard claim and several honest non-claims. Your job is to break
the hard claim and to check that the non-claims are never silently over-stated:

- **Hard claim:** for traffic that *actually routes through* the Guardian, a policy `BLOCK`
  stops the bytes before they reach the upstream (**leak-through = 0**), and the raw secret is
  never written to logs, audit, or persistence.
- **Non-claims (must never be over-stated anywhere):** complete detection recall; protection
  of traffic that bypasses the proxy; inspection of response content; isolation of the host or
  the child process; resistance to a same-user local attacker reading process memory/env.

A result that proves a non-claim false is expected (it's a documented limit). A result that
proves the **hard claim** false, or that finds Serrier **reporting protection it did not
provide**, is a real failure.

## Severity classification

| Severity | Definition |
|---|---|
| **Critical** | Inspect-clean-but-forward-dirty on *routed* traffic (a real secret reaches the upstream through a path we claim to protect); raw secret/token in logs/audit/persistence; `BLOCK` bypass on routed traffic. |
| **High** | SSRF / DNS-rebinding success; proxy auth (token) bypass; detection evasion on a **common** secret format we imply we catch; request-smuggling desync that changes what the upstream receives vs. what we inspected. |
| **Medium** | Recall gap on an uncommon format; policy-logic error with no leak; a fail-open path not matching the configured failure mode; friction/false-positive that would block legitimate work by default. |
| **Low / Info** | A documented coverage limit (bypass by not using the proxy, non-HTTP egress, split-across-requests). Report it, but it is a *coverage* finding, not a vulnerability — unless we over-claim it somewhere. |

## Overall pass / fail criteria

**PASS requires all of:**
- Zero Critical and zero unmitigated High.
- Leak-through = 0 holds for every *routed-traffic* BLOCK case the reviewer can construct.
- No raw secret or proxy token found in any log, audit entry, error trace, or on disk.
- Every coverage limit the reviewer exercises is already documented and **not** contradicted by
  any claim in the UI, README, or design docs.
- `UNKNOWN` (analysis failed) is never reported as "inspected" / "safe" in any mode.

**FAIL on any of:**
- One inspect-clean-forward-dirty on routed traffic (Critical).
- One raw-secret or token leak into logs/audit/persistence (Critical).
- Any place where Serrier states or implies protection it does not deliver.

---

## Test rig (reproducible)

A controlled upstream that counts exact received bytes is in `backend/tests/upstream_harness.py`
(`KontrolleradUpstream`, `LiveServer`). Stand up: upstream on a loopback port, a `GuardProxy`
pointed at it (`validera_ip=False` only to exercise the forward axis against a local upstream —
test SSRF separately with real DNS), and drive it with a real `httpx.Client` over real TCP. The
upstream's `antal_bytes` / `innehaller(fragment)` give you ground truth for leak-through. See
`tests/test_guardian_proxy_e2e.py` for the pattern. **Measure leak-through yourself; do not
trust our assertion.**

---

## Attack targets

Each target below follows: **Goal · Method/repro · Expected behavior · Known limits · Evidence
to collect · Severity if broken · Pass/fail.**

### A. Proxy bypass (get data to the provider without Serrier seeing it)
- **Goal:** deliver a secret to the real provider while Serrier believes it protected the session.
- **Method:** (A1) child ignores `*_BASE_URL` and connects directly; (A2) child unsets/overrides
  the injected env; (A3) target a provider not on the allowlist via another channel; (A4) raw
  socket / WebSocket / non-HTTP egress; (A5) start the child outside `serrier-guard`.
- **Expected:** these succeed in reaching the provider — they are **coverage limits**. Serrier
  must NOT claim to have inspected them. Nothing in audit should imply coverage of un-routed traffic.
- **Known limits:** documented in `docs/design/0002` §2 and the `run.py` docstring.
- **Evidence:** show the bypass path; then show Serrier's audit/reporting for that session —
  confirm it does not assert protection.
- **Severity if broken:** Critical **only if** Serrier reports the bypassed traffic as inspected/
  protected; otherwise Info (coverage).
- **Pass/fail:** PASS if coverage is honestly reported; FAIL if protection is over-claimed.

### B. Proxy auth & local access
- **Goal:** use the proxy from another local process, or recover the token.
- **Method:** (B1) connect to the loopback port with no token / wrong token; (B2) brute/timing
  the token (`X-Serrier-Token` and the `/t/<token>/…` path form); (B3) read the token from the
  child's `/proc/<pid>/environ` as the same user; (B4) find the token in SDK debug logs or in the
  proxy's own logs.
- **Expected:** B1/B2 → 401, nothing forwarded; comparison is constant-time (`hmac.compare_digest`).
  B3 is an OS-level same-user limit (documented — not Serrier's boundary). B4 must find nothing in
  Serrier's logs (child-side SDK logging is outside our control, documented).
- **Evidence:** 401 responses + upstream received 0; `grep` proxy audit/stdout for the token.
- **Severity if broken:** High (token bypass / token in Serrier logs).
- **Pass/fail:** FAIL if any request without the valid token is forwarded, or the token appears in
  Serrier's own logs/audit.

### C. DNS / upstream validation (SSRF, rebinding, redirects)
- **Goal:** make the proxy connect to an internal/unintended host, or forward where it shouldn't.
- **Method:** (C1) point an allowlisted key at a host that resolves to a private/loopback/link-local
  IP; (C2) DNS-rebinding — return a public IP to the validator then a private IP to the actual
  connection; (C3) upstream returns a 3xx redirect to an internal host; (C4) IPv6 forms, zone-ids,
  IPv4-mapped IPv6, decimal/octal/hex IP encodings; (C5) a non-allowlisted key.
- **Expected:** C1 → rejected (all addresses must be `is_global`); C2 → defeated by pin-to-validated-IP
  + SNI (one resolution, connection bound to it); C3 → **not followed** (`follow_redirects=False`),
  302 returned raw; C5 → 404. The validator fails **closed** on resolution error.
- **Known limits:** the pin-IP mitigation closes the common TOCTOU window; verify there is no
  remaining second-resolution path (check that `httpx` connects to the pinned IP, not the hostname).
- **Evidence:** upstream received 0 for rejected cases; packet/connection trace showing the pinned IP;
  redirect not followed.
- **Severity if broken:** High (any successful SSRF/rebinding/redirect-follow).
- **Pass/fail:** FAIL if any non-global destination is reached, or a redirect is followed.

### D. Manipulated requests (inspect-clean, forward-dirty) — the crown jewel
- **Goal:** craft a request Serrier inspects as clean (or redactable) but that delivers the secret
  intact to the upstream. **This is the highest-value target.**
- **Method:** (D1) evade detection so `action=allow` but the body still carries a live secret;
  (D2) a JSON body where `safe_text` still parses as JSON yet retains the secret (e.g. secret
  reassembled by the provider, or a redaction that doesn't cover the whole token); (D3) non-JSON
  content types with a secret (must degrade to BLOCK, never forward); (D4) request smuggling —
  `Content-Length`/`Transfer-Encoding` desync so the proxy inspects one body and the upstream
  receives another; (D5) oversized/compressed body to bypass the 10 MB inspection cap; (D6)
  unicode normalization / encoding so detection misses but the provider reconstructs.
- **Expected:** no body is forwarded with a detectable secret still intact; non-sanitizable →
  BLOCK; `max_body` rejects oversize before inspection; evasion findings (unredactable) force BLOCK.
- **Evidence:** upstream `innehaller(secret)` must be `False` for every BLOCK case; for any
  forwarded body, show it carries no live secret you can detect.
- **Severity if broken:** **Critical** (D1/D2/D4/D6 that deliver a live secret); High (D5 cap bypass).
- **Pass/fail:** FAIL on any routed request that delivers a live secret the policy should have stopped.

### E. Detection gaps (recall)
- **Goal:** secrets/PII that are not detected and so are forwarded.
- **Method:** novel/less-common formats — GitHub fine-grained PATs, GCP service-account keys, JWTs,
  SSH private keys beyond the `BEGIN … PRIVATE KEY` header, Slack/Stripe/Twilio tokens, IBANs,
  non-Swedish national IDs, phone numbers; and encodings we state we don't defend (hex, base32,
  gzip, encrypted); and **split-across-requests** (no cross-request state in v1).
- **Expected:** some of these WILL pass — recall is `< 100%` and this is stated. The requirement is
  that Serrier never claims completeness, and that **common, high-value** formats are caught.
- **Evidence:** list what passed; cross-check against our pattern set and our documented limits.
- **Severity if broken:** High if a **common** credential format (one a developer would plausibly
  paste) passes and we imply coverage; Medium for uncommon formats; Info for explicitly-undefended
  encodings.
- **Pass/fail:** FAIL if a common secret format is silently forwarded while we imply we catch it.

### F. Policy & decision logic
- **Goal:** produce an unsafe decision through policy edge cases.
- **Method:** (F1) crash/timeout the detector to force `UNKNOWN`, in each failure mode — confirm
  STRICT→block, BALANCED→require_approval (never silent forward), PERMISSIVE→allow-but-marked-unknown;
  confirm `UNKNOWN` is never labeled "inspected"; (F2) mix a BLOCK-level and an ALLOW-level finding
  in one request — strictest must win; (F3) owner weakens the org policy to all-ALLOW — confirm the
  change is audited; (F4) `require_approval` in the non-interactive proxy — confirm it's treated as
  block, not forward.
- **Expected:** as above; the four-state contract (observation ≠ correlation ≠ risk ≠ incident) and
  the UNKNOWN discipline hold.
- **Evidence:** audit entries show `analysis_status` and the action taken; policy changes are audited.
- **Severity if broken:** High (UNKNOWN forwarded as inspected; strictest-wins violated).
- **Pass/fail:** FAIL if UNKNOWN is ever reported as inspected or BALANCED silently forwards
  un-analyzed sensitive content.

### G. Data handling (the security tool leaking what it protects)
- **Goal:** find a raw secret, raw request body, or token anywhere it shouldn't be.
- **Method:** drive BLOCK/REDACT traffic, then inspect: proxy audit entries, stdout/stderr, uvicorn
  access logs, any temp files, the SQLite store, exception traces (force an error mid-request).
- **Expected:** audit holds only redacted findings (`first4…last4`) + verdict + upstream host; raw
  body/secret/token never persisted or logged; the decision core never sends raw text to an external
  model.
- **Evidence:** `grep -r` the full known secret string and token across logs/db/temp after a run →
  zero hits.
- **Severity if broken:** **Critical** (a security product leaking secrets is the worst failure).
- **Pass/fail:** FAIL on any raw-secret or token occurrence outside transient request memory.

### H. Availability & failure behavior
- **Goal:** break fail-closed, or exhaust resources.
- **Method:** kill the proxy mid-stream; hang the upstream (slowloris / never-respond); open many
  concurrent connections; send a decompression-bomb body; abort the client mid-stream (confirm
  upstream connection is closed, no leak, no hang).
- **Expected:** explicit-proxy-down → child connection refused (fail-closed; nothing to forward
  through); upstream hang → timeout → 502; aborted stream → `aclose()` releases the upstream;
  oversize → 413 before inspection.
- **Evidence:** behavior under each condition; no partial-inspected forward; no raw data leaked on error.
- **Severity if broken:** High (fail-open under failure) / Medium (DoS).
- **Pass/fail:** FAIL if any failure condition results in un-inspected traffic being forwarded or a
  secret leaking on an error path.

---

## Evidence package the reviewer must return
1. For each target: repro steps, observed behavior, and the raw evidence (captures, greps, byte counts).
2. A leak-through count for every BLOCK case attempted (must be 0 to pass).
3. The list of detection formats/encodings that evaded (recall findings), mapped to our documented limits.
4. Any place where documentation or UI over-claims relative to observed behavior.
5. Severity for each finding per the table above, and an overall PASS/FAIL against the criteria.

## Known limitations (the reviewer should confirm these are the real boundary, not a longer list)
- Only base_url-respecting, routed traffic is covered; everything else bypasses (by design).
- Recall < 100%: hex/base32/gzip/encrypted and split-across-requests are undefended; uncommon
  credential/PII formats may pass.
- Response **content** is not inspected (streaming is relayed, not analyzed).
- REDACT is JSON-only; other content types degrade to BLOCK.
- Same-user local attacker can read the child's env/memory (OS boundary, not Serrier's).
- No MITM; the proxy never terminates arbitrary TLS.
- 160 passing synthetic tests are **not** proof of resistance to a motivated attacker — that is
  what this review is for.
