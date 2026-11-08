# Design 0001 — Pre-Send Guardian

Status: **decision core built** — steps 1–4 done (shared detection core · PII/entropy ·
policy engine with 3 failure modes + UNKNOWN · `inspect()` + `POST /guard/inspect`). Local,
deterministic, zero integration. Remaining before step 6 (proxy): step 5 adversarial recall
suite; per-org policy override via API/RBAC; a formal latency benchmark. Step 6 stays gated
behind the §12 artifacts.
Baseline: tag `v0.1.0` (Phases 0–10). Compare every future change against it.
Author: founding CTO analysis, 2026-11-08.

This document is the deliverable the master directive asks for *before* implementation:
current-state assessment, target architecture, threat model, Guardian design, data flow,
security boundaries, API/data-model changes, test strategy, roadmap, risk register,
definition of done — and the decisions that must be made first.

The directive is explicit on one architectural point, and it is correct:

> Separate **Detection** (sensitive info exists), **Decision** (what policy allows), and
> **Enforcement** (technically guarantee the action is allowed or stopped).
> "Detecting an API key is easy compared to guaranteeing it never gets sent."

Everything below is organized around that spine.

---

## 1. Current architecture assessment (verified, not assumed)

What exists at `v0.1.0`, confirmed against the code:

- **Detection** over *files/repos*: `builtin` secret regex, gitleaks, semgrep, osv,
  git-history. All behind a `Scanner` protocol with graceful degradation + path
  confinement. Evidence is redacted at detection (`Evidence.av` → `redact()`); raw
  secrets never leave the detector or reach storage/logs.
- **Central Finding schema** with *separate* severity / confidence / status, a stable
  deterministic id, and redacted evidence. A transparent `risk_score`.
- **Persistence**: SQLite→Postgres, Alembic, tenant isolation by `project_id`/`org_id`,
  append-only audit, re-scan upsert, auto-verification, regression (`aterkomster`).
- **Auth**: API keys (sha256, never raw), orgs, RBAC (viewer/member/owner).
- **Decision-ish logic** today: `remediation.foresla_atgard` (secret→rotation is
  code-enforced), status transitions are explicit + audited, correlation prioritizes.
- **Analytics/Export/Dashboard/AI-analyst/Remediation/Verification** — all present.

**Reusable for the Guardian (high value):**
- The secret patterns + placeholder filter + span-claiming dedup in `scanners/builtin.py`.
- `redact()` + `Evidence` + `Finding` + `Category`/`Severity`/`Confidence`.
- The "code decides, model only advises" principle already embodied in remediation.
- Audit log, tenant/org model, API surface, test conventions.

**Gap the Guardian fills:** every detector today reads a *file tree at rest*. The Guardian
must inspect *a piece of outbound text in motion*, synchronously, locally, with a latency
budget, and return a **decision**, not just findings.

**Honest weaknesses in the current base, relevant here:**
- Secret detection is regex-only (no entropy/NER); recall on novel formats is unknown and
  untested against *evasion*. For files that is acceptable; for a Guardian that claims to
  *prevent* exposure it is the core risk and must be measured adversarially.
- No concept of "text surface" vs "file surface" — patterns are coupled to the file
  scanner. They must be extracted into a shared, surface-agnostic detection core.
- No PII detection at all. Prevention needs at least a conservative PII layer.

---

## 2. The spine: Detection / Decision / Enforcement

Three layers, three *different* guarantees. Conflating them is how security products lie.

| Layer | Question | Guarantee it can honestly make | Where it runs |
|---|---|---|---|
| **Detection** | Is sensitive info present? | Probabilistic. "We matched X with confidence C." Never "there is nothing." | Local, deterministic |
| **Decision** | What should happen? | Deterministic & explainable. Given findings + policy → exactly one verdict. | Local, deterministic |
| **Enforcement** | Did we actually stop it? | **Only as strong as our control of the egress path.** | At the integration point |

The third row is the whole product honesty. Serrier can *guarantee* a verdict. It can only
*guarantee enforcement at a chokepoint it controls*. This mirrors the existing "VPN ≠
anonymity" and "never claim secure" discipline — we extend it: **"a warning is not a
block, and a block is only real where Serrier owns the wire."**

### UNKNOWN is a first-class state (not "safe")

Detection can fail: the engine errors, times out, or the input is a form it cannot parse.
When that happens the answer is **UNKNOWN**, and UNKNOWN is its own state — it must *never*
collapse into ALLOW / "analyzed" / "approved". A `GuardDecision` therefore carries two
separate fields:

- `analysis_status`: `ok | unknown` — did the analysis actually complete?
- `verdict`: the action (below) — only meaningful when `analysis_status = ok`, or when the
  failure-mode policy has explicitly decided what UNKNOWN maps to.

Serrier may *never* report that traffic was security-checked when it wasn't. "Unknown" and
"safe" are different claims, and the product's credibility depends on keeping them apart.
What happens to UNKNOWN traffic is the failure-mode policy's job (§4.2), not a silent default.

### Enforcement strength is a property of the integration, and must be labeled

| Integration | Controls egress? | Honest max enforcement | Bypass reality |
|---|---|---|---|
| Local HTTP(S) proxy / API gateway the client is configured to use | Yes (for traffic routed through it) | **BLOCK is real** for routed traffic | User can route around the proxy |
| CLI wrapper / stdin filter the user runs | Yes (for calls made through it) | **BLOCK is real** for wrapped calls | User can call the tool directly |
| IDE / Claude Code hook that gates the send | Depends on hook semantics | BLOCK if the hook can veto the send; else WARN | Other channels, disable hook |
| Browser extension (content script) | No | **WARN / REDACT (best-effort)** | Paste elsewhere, other browser, disable |

Design rule: **each enforcement adapter declares its own `enforcement_level`
(`guaranteed` | `best_effort`) and the UI/report never upgrades a best-effort WARN into a
claimed BLOCK.** A browser extension that says "blocked" when the user can trivially paste
into another tab is exactly the false precision the directive forbids.

---

## 3. Local-first, non-negotiable

Detection and decision run **locally**. The candidate text is the thing we are trying to
protect — shipping it to a third-party model "to check if it's sensitive" *is the
exposure*. So:

- v1 detection = local deterministic (regex + entropy + conservative PII), reusing builtin.
- Optional contextual classification may use an LLM **only** when (a) it is a local model,
  or (b) the input has already been redacted so no raw secret/PII leaves. Never the raw
  full message to an external provider. This is enforced in code, not by convention.

---

## 4. Pre-Send Guardian — technical design

### 4.1 Decision core (the MVP; integration-independent)

A pure library + one endpoint. Input: outbound text + context (destination, user/org,
policy). Output: a `GuardDecision`.

```
inspect(text, context) ->
  1. Detect:   findings = detect_in_text(text)          # local, reuses builtin core
  2. Classify: each finding gets sensitivity + category # deterministic rules
  3. Decide:   verdict = policy.evaluate(findings, ctx) # ALLOW/WARN/REDACT/BLOCK/REQUIRE_APPROVAL
  4. Redact:   safe_text = apply_redactions(text, findings) if verdict in {REDACT,...}
  5. Explain:  per-finding reason + which policy rule fired
```

- `detect_in_text(text)` is the **shared detection core** extracted from `builtin.py`:
  `(rule_id, pattern, severity, confidence)` matching + placeholder filter + span dedup,
  now operating on an arbitrary string instead of a file walk. The file scanner is
  refactored to call the same core (no behavior change; its tests pin that).
- Verdicts are deterministic. The **policy engine** maps `(category, sensitivity,
  confidence, destination_trust)` → action, with documented defaults and per-org override.
- LLM is **not** on this path in v1. (Optional, later, local-only, post-redaction.)

### 4.2 Policy engine (deterministic)

- Actions: `ALLOW`, `WARN`, `REDACT`, `BLOCK`, `REQUIRE_APPROVAL`.
- A rule = `match(category, min_confidence, destination) -> action`. First/most-specific
  match wins; default-deny-ish for confirmed secrets, default-warn for heuristics.
- Reuses the "code decides, model advises" invariant. Explainable: every verdict names the
  rule that produced it. Overridable per org (ties into existing RBAC: only owner edits
  policy).

#### Failure-mode policy (what UNKNOWN maps to)

Fail-open vs fail-closed is **not** a universal behavior — it is configurable policy with
three modes. When `analysis_status = unknown` (detection errored / timed out / unparseable),
the mode decides the action, and the decision is always loudly audited and labeled UNKNOWN
(never "analyzed"):

| Mode | UNKNOWN → action | Use |
|---|---|---|
| **STRICT** | `BLOCK` (fail-closed) | Highest assurance; block rather than risk a leak. |
| **BALANCED** | risk-based: sensitive categories (secrets/credentials/PII) `BLOCK` or `REQUIRE_APPROVAL`; the rest per policy | Default. **May never silently pass un-analyzed sensitive content** — the policy must name exactly which risks are tolerable. |
| **PERMISSIVE** | `ALLOW` + explicit warning + redacted audit log (fail-open) | Don't break the dev's flow; still records the gap. |

Enterprise admins can centrally constrain which modes are permitted (e.g. forbid
PERMISSIVE org-wide). The invariant holds in every mode: UNKNOWN is surfaced as UNKNOWN,
and sensitive content is never reported as checked when it wasn't.

### 4.3 Enforcement adapters (separate, later, one at a time)

The **enforcement core is integration-agnostic**: a single `EnforcementAdapter` contract
(capture → `inspect` → apply verdict, declaring `enforcement_level`) that *every* method
implements. Build the contract so Local Proxy/CLI, Browser Extension, Claude Code hook and
IDE integration can all plug into the same decision core without re-architecting.

**First adapter = Local Proxy/CLI** (decision locked): Serrier owns the chokepoint, so BLOCK
is technically verifiable (traffic is stopped before it reaches upstream), analysis stays
local, and the architecture stays provider-agnostic. It is the clearest first proof of real
*prevention*. The other adapters are **not** implemented now — the contract just leaves room
for them. (See §12 for the gating artifacts required before the proxy is built.)

---

## 5. Data flow

```
          outbound text (prompt / paste / API body)
                        │   (never leaves the machine raw)
                        ▼
   ┌─────────────────────────────────────────────┐
   │ DETECTION  (local, deterministic)            │  reuses builtin core
   │  secrets · credentials · PII · entropy       │  raw text stays here
   └───────────────┬─────────────────────────────┘
                   ▼  findings (redacted evidence only)
   ┌─────────────────────────────────────────────┐
   │ DECISION  (policy engine, deterministic)     │  ALLOW/WARN/REDACT/BLOCK/APPROVE
   └───────────────┬─────────────────────────────┘
                   ▼  GuardDecision + safe_text + explanations
   ┌─────────────────────────────────────────────┐
   │ ENFORCEMENT  (integration adapter)           │  level: guaranteed | best_effort
   │  proxy=guaranteed · browser-ext=best_effort  │
   └───────────────┬─────────────────────────────┘
                   ▼
        send safe_text  |  block  |  ask user
                   │
                   ▼  (minimized, redacted) telemetry → audit / analytics
```

Only redacted metadata is ever persisted or sent to the central plane — the raw candidate
text never is. This satisfies the enterprise "don't exfiltrate employees' private content"
requirement from the vision prompt by construction.

---

## 6. Threat model (Guardian-specific)

Assets: the candidate text itself; detection recall; the enforcement guarantee's honesty.

| # | Threat | Mitigation |
|---|---|---|
| G1 | Raw text leaks via Serrier itself (logs, telemetry, LLM classify) | Local-only detection; redact before any persistence/transit; code-enforced "no raw text to external model". |
| G2 | **Evasion** — formatting, newlines, code blocks, base64, split credentials, spacing, homoglyphs, chunked PII | Normalize before matching (strip/zero-width/case); entropy detector for high-entropy blobs; decode-and-rescan common encodings (base64) *locally*; **measure adversarial recall and publish it** — never claim completeness. This is the #1 risk. |
| G3 | False "blocked" claim (best-effort labeled as guaranteed) | `enforcement_level` per adapter; UI never upgrades. |
| G4 | Latency makes users disable it | Hard latency budget (<~50ms typical); detection is regex/entropy, no network; fail-open vs fail-closed is a **policy decision** (see Decisions). |
| G5 | False positives bury real ones / train users to click through | Confidence separation + conservative PII + per-org tuning; measure FPR. |
| G6 | Policy bypass via destination spoofing | Destination trust derived from the adapter, not from user-supplied text. |
| G7 | ReDoS / resource exhaustion on hostile input | Bounded input size, linear-safe patterns, timeouts (reuse T8 posture). |

Explicitly **out of scope / not guaranteed** (state it, don't pretend): we cannot stop a
determined insider who copies text out-of-band; we do not control channels we have no
adapter for; detection recall is < 100%.

---

## 7. API & data-model changes (additive, backward-compatible)

- New module `serrier/guardian/` : `detect.py` (shared core), `classify.py`, `policy.py`,
  `inspect.py`. Refactor `scanners/builtin.py` to call `guardian/detect.py` (tests pin
  identical file-scan behavior).
- New types (not DB-backed in v1): `Sensitivity`, `GuardAction`, `GuardDecision`. Reuse
  `Category`/`Severity`/`Confidence`/`Evidence`.
- New endpoint: `POST /guard/inspect` — body `{text, destination}`, returns
  `GuardDecision` (verdict, per-finding reasons, `safe_text`, `enforcement_level: null`
  since the API itself enforces nothing). Auth + org policy via existing deps.
- New (optional) table later: `guard_event` (redacted, for analytics/audit) — **not** in
  the first step; added only when an enforcement adapter produces real events.
- No changes to existing Finding/Scan/Org tables. No migration needed for the MVP core.

---

## 8. Test strategy

- **Unit**: detection core on secrets/credentials/PII; placeholder suppression; policy
  verdict table; redaction correctness (raw never present in output).
- **Adversarial recall suite** (the important one): a fixture of evasions — base64,
  newline-split keys, spaced digits, code fences, homoglyphs, chunked PII — with a
  published recall/FPR number. Synthetic-fixture results reported *separately* from any
  real-world numbers (directive §9).
- **Property**: `safe_text` never contains any raw matched secret; `inspect` is pure
  (same input → same verdict); latency under budget on representative inputs.
- **API/RBAC**: only owner can edit policy; tenant isolation on policy.
- **Regression pin**: builtin file-scan output byte-identical before/after the refactor.

Metrics tracked: precision, recall, FPR, FNR, detection latency. No claim of prevention
success without an enforcement adapter that actually controls egress.

---

## 9. Implementation roadmap (small, testable steps)

1. **Extract shared detection core** from `builtin.py` → `guardian/detect.py`, operating on
   text. Refactor the file scanner to use it. Pin with existing tests (zero behavior
   change). *Smallest safe step; pure refactor.*
2. **Classification + PII v1** (conservative: emails, cards (Luhn), national-id-shaped,
   internal IPs) + entropy detector. Measured on a fixture.
3. **Policy engine** (deterministic verdict table + per-org override, owner-gated).
4. **`inspect()` + `POST /guard/inspect`** returning `GuardDecision` + `safe_text`.
   *End of MVP: a local, tested decision core with zero integration.*
5. **Adversarial recall suite** + published numbers.
6. **One enforcement adapter** (decided with the user) — declares `enforcement_level`.
7. Guard analytics/audit (redacted) once real events exist.

Everything beyond step 6 (model gateway, agent governance, enterprise control plane,
secure environments, air-gap) is **explicitly deferred** — see Risk R1.

---

## 10. Risk register

| ID | Risk | Severity | Response |
|---|---|---|---|
| R1 | **Scope explosion.** The two vision prompts describe an enormous product (secure environments, air-gap, enterprise control plane, model-agnostic gateway, agent governance). Building any of it now would bury the one thing with near-term value. | High | Hard-gate: build only steps 1–6. Treat the rest as a *target picture*, not a backlog. Revisit after the Guardian MVP earns a real user. |
| R2 | Detection recall oversold → the product "prevents" nothing. | High | Adversarial suite + published recall; honesty labels; never "secure". |
| R3 | Enforcement theater (best-effort shown as guaranteed). | High | `enforcement_level` in the model; UI contract. |
| R4 | Refactor of builtin breaks file-scan. | Med | Byte-identical regression pin before merge. |
| R5 | Latency/FP friction → users turn it off. | Med | Budget + fail-open policy option + FP tuning. |
| R6 | Browser-extension trust/ToS model is murky. | Med | Prefer a chokepoint we own (proxy/CLI) for the *first* adapter; treat extension as best-effort only. |

---

## 11. Definition of Done (for the MVP, steps 1–4)

- Shared detection core; builtin file-scan output unchanged (regression pinned).
- `POST /guard/inspect` returns a deterministic, explainable `GuardDecision` with
  `safe_text` that provably contains no raw matched secret.
- Policy engine with documented defaults, owner-gated per-org overrides, full verdict-table
  tests.
- Local-only guarantee: a test proves no raw candidate text is persisted, logged, or sent
  to any external model.
- Latency budget met on the fixture; recall/FPR measured and reported (synthetic, labeled).
- ruff clean; all prior tests still green; `v0.1.0` behavior unchanged for existing flows.

---

## 12. Decisions — RESOLVED (2026-11-08)

1. **Build the decision-core MVP (steps 1–4), hold the scope gate (R1).** ✅ Locked.
2. **Detection scope v1 = secrets + credentials + conservative PII** (email, card via Luhn,
   national-id-shaped, internal IP), narrow to hold FPR down. ✅ Locked.
3. **First enforcement adapter = Local Proxy/CLI**, with an integration-agnostic
   `EnforcementAdapter` contract so Browser Extension / Claude Code hook / IDE can attach
   later. None of those built now. ✅ Locked (§4.3).
4. **Failure behavior = three-mode policy** (STRICT / BALANCED / PERMISSIVE), enterprise-
   admin-constrainable, with UNKNOWN as a first-class state that never reads as "safe". ✅
   Locked (§2, §4.2).

### Gating artifacts required BEFORE step 6 (the proxy) — not before the core

Build these as design + tests before any proxy enforcement ships:

1. **Proxy threat model & bypass analysis** — how traffic can route around it; what the
   guarantee does and does not cover.
2. **Proxy failure handling** — ties to the three-mode failure policy; UNKNOWN on proxy
   fault is never "checked".
3. **TLS & sensitive-data handling** — how the proxy inspects without unnecessary exposure
   (what is decrypted, where, what is never stored); MITM/TLS trust model stated honestly.
4. **Prevention verification against a controlled upstream** — a test server that proves
   BLOCK actually stops the bytes before upstream receives them.
5. **Covered traffic paths** — an explicit list of exactly which flows the guarantee
   applies to (and which it doesn't).
