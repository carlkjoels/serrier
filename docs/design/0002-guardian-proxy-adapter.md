# Design 0002 — Guardian enforcement adapter: Local Proxy/CLI

Status: **approved** — the five §12 gating artifacts for step 6; decisions resolved (§9);
no implementation yet. Model A (explicit loopback proxy) + C (CLI), proxy first, MITM rejected.
Gates: Phase 11 step 6. Builds on [0001](0001-pre-send-guardian.md) (decision core, steps 1–5).
Baseline: tag `v0.1.0`.

0001 built the decision core: `inspect(text) → GuardDecision` (local, deterministic, evasion-
hardened). This document is what must exist **before** we build the first *enforcement*
adapter, because enforcement is the layer that claims to actually **stop** bytes — and a
block that can be trivially bypassed, or a proxy that silently fails open while reporting
"checked", would be exactly the dishonesty the whole product is built against.

The five artifacts the user gated step 6 behind:
1. Proxy threat model & bypass analysis (§3, §4)
2. Proxy failure handling (§6)
3. TLS & sensitive-data handling without unnecessary exposure (§5)
4. Prevention verification against a controlled upstream (§7)
5. Which traffic paths are actually covered by the guarantee (§2)

---

## 1. Integration model — the decision that shapes everything

To inspect outbound AI requests we must see the request body. There are three ways; they
are **not** equal in honesty or risk.

| Model | How it sees the text | BLOCK is real? | Cost / liability |
|---|---|---|---|
| **A. Explicit loopback forward-proxy** | Client is deliberately configured (`HTTPS_PROXY=http://127.0.0.1:PORT` or SDK `base_url`) to route through Serrier; Serrier is the TLS client to the real upstream | **Yes, for routed traffic** | Honest, bounded. Needs the client to opt in. Does not touch other traffic. |
| **B. Transparent TLS MITM** | Install a local root CA; intercept all TLS, decrypt, inspect, re-encrypt | Yes, for all TLS | **High liability**: Serrier becomes a system-wide TLS-terminating MITM holding plaintext of *everything*; one bug = catastrophic. Breaks cert-pinned apps. Rejected for v1. |
| **C. CLI / SDK wrapper** | A `serrier-guard run -- <cmd>` wrapper or an SDK shim sees the request before TLS | Yes, for wrapped calls | Honest, bounded, even simpler than A — but per-tool. |

**Recommendation (decision to confirm):** build **A (explicit loopback proxy)** as the first
adapter, and **C (CLI wrapper)** as a thin sibling reusing the same core. **Reject B
(transparent MITM) for v1** — becoming a system-wide CA that decrypts all traffic is a
larger security liability than the problem it solves, and it breaks certificate pinning.

Why A is the honest choice: Serrier only ever sees traffic the user **explicitly routed**
to it, over the loopback interface, and it never gains the ability to decrypt traffic it
wasn't given. The trust boundary is small and legible. This mirrors 0001's local-first rule.

Everything below assumes model A (with C sharing the same decision core and contract).

---

## 2. Covered traffic paths — the guarantee boundary (artifact 5)

The guarantee is deliberately narrow and must be stated as such. Serrier never says "you
are protected"; it says "requests routed through Serrier are inspected and enforced."

**Covered (guaranteed BLOCK):**
- HTTP(S) requests whose client is configured to use the Serrier proxy (env `HTTPS_PROXY`/
  `HTTP_PROXY`, or an SDK `base_url` pointed at the loopback endpoint) **and** that reach it.
- For model C: any process launched *through* the `serrier-guard` wrapper.

**NOT covered (must be shown in UI/report — silence here would be a lie):**
- Any process that ignores proxy settings, hardcodes a direct connection, or is not launched
  through the wrapper.
- Traffic after the user disables/stops the proxy.
- Non-HTTP channels; raw sockets; traffic to IPs/hosts the client reaches directly.
- Certificate-pinned clients that refuse any proxy (they will fail closed — see §4).
- Other machines, other users, the browser (that's a *future, best-effort* adapter).

Design rule: the adapter reports **coverage**, not safety. "N requests inspected; Serrier
cannot see traffic that does not route through it."

---

## 3. Proxy threat model (artifact 1)

Assets: the request bodies routed through the proxy (contain the very secrets we protect);
the integrity of the BLOCK guarantee; the honesty of the "inspected" claim.

| # | Threat | Mitigation |
|---|---|---|
| P1 | Proxy itself leaks the plaintext it inspects (logs, crash dumps, telemetry) | Plaintext held only transiently in memory; **never logged/persisted**; audit stores only redacted findings + verdict; no request-body in error traces. Same discipline as 0001. |
| P2 | Proxy is a new attack surface (it terminates connections) | Bind to **loopback only** (127.0.0.1), never 0.0.0.0; no remote admin; drop privileges; strict request-size/time limits (reuse THREAT_MODEL T8). |
| P3 | SSRF / the proxy is abused to reach internal hosts | The proxy forwards only to an **allowlist of configured upstreams** (api.anthropic.com, api.openai.com, …); refuses to proxy arbitrary hosts. |
| P4 | TLS downgrade / the proxy weakens upstream TLS | Serrier is a normal TLS *client* to upstream with full verification; it never disables verify, never downgrades. |
| P5 | Verdict tampering between inspect and forward | Inspect→decide→forward is one in-process path; no external mutable state between decision and action. |
| P6 | Compromised/forged policy raises risk silently | Policy changes are owner-gated + audited (0001 step 5b). |

## 4. Bypass analysis (artifact 1, cont.)

Honest enumeration of how the guarantee is evaded — each is a *coverage limit*, not a bug:

- **Unset the proxy env / don't use the wrapper** → traffic goes direct, uninspected.
- **Hardcoded direct connection** in an app that ignores proxy settings.
- **Certificate pinning**: a pinned client rejects any proxy → it fails to connect (fails
  closed; nothing leaks, but nothing is sent either — see §6).
- **Direct IP / alternate DNS** bypassing allowlist resolution.
- **Non-HTTP egress** (raw socket, WebSocket upgrade we don't parse).
- **Splitting a secret across multiple requests** so no single body trips detection — a real
  limit; noted, not solved in v1.

Consequence: the adapter's `enforcement_level = guaranteed` applies **only to routed HTTP(S)
traffic**. The UI must pair the guarantee with its coverage boundary, always.

---

## 5. TLS & sensitive-data handling (artifact 3)

- **No transparent MITM, no local CA** (model A). The client speaks to Serrier over
  **loopback** (either plain HTTP to 127.0.0.1, or TLS to a loopback cert the user
  explicitly trusts for *that endpoint only* — not a system-wide root). Serrier is then a
  normal, fully-verifying TLS **client** to the real upstream.
- **Plaintext lifetime:** the request body exists in cleartext in proxy memory only for the
  duration of inspect+forward. It is never written to disk, never logged, never sent to any
  external model. Audit records only: timestamp, upstream host, verdict, redacted findings,
  `analysis_status`.
- **REDACT-and-forward is hard — be honest.** Rewriting the body to send `safe_text`
  changes its length and can break `Content-Length`, HMAC request signatures, or JSON the
  SDK expects. For v1: REDACT on a simple re-serializable JSON body is allowed (recompute
  Content-Length); where the body can't be safely rewritten, **REDACT degrades to BLOCK**
  (never forward a body we couldn't cleanly sanitize). This degradation is logged, not silent.
- **Streaming/SSE responses** are not inspected on the response path in v1 (request-side
  prevention only); stated as a coverage limit.

---

## 6. Proxy failure handling (artifact 2)

Failure must obey the three-mode policy from 0001, and **UNKNOWN is never "checked."**

| Situation | STRICT | BALANCED | PERMISSIVE |
|---|---|---|---|
| Inspect errors / times out (per-request) | refuse to forward (block) | hold → `require_approval` | forward + warn + redacted audit, `analysis_status=unknown` |
| Proxy process is down | client connection **refused** → request fails closed (safe default for an explicit proxy) | same | same (an explicit proxy that's down can't fail "open" — there's nothing to forward through) |
| Upstream allowlist miss (P3) | refuse | refuse | refuse (not a failure mode question — it's a hard rule) |

Two invariants: (1) a request is **never** reported as inspected when inspect didn't
complete — the response/audit carries `analysis_status=unknown`; (2) the fail-open path
(PERMISSIVE) still records exactly what slipped and why. Enterprise admins may forbid
PERMISSIVE org-wide (0001 §4.2).

---

## 7. Prevention verification against a controlled upstream (artifact 4)

The empirical proof that BLOCK stops bytes *before upstream*. Test harness design:

- A **controlled upstream** (a local FastAPI "echo/record" server standing in for
  api.anthropic.com) that records the exact bytes of every request body it receives.
- The Serrier proxy is pointed at this controlled upstream via the allowlist.
- Test cases:
  1. **Block proves prevention:** send a request whose body contains a secret, policy=block.
     Assert the controlled upstream received **zero** such requests (the body never arrived),
     and the client got a Serrier block response.
  2. **Clean passes through intact:** send a benign body. Assert the upstream received it
     **byte-identical** (proxy is transparent when it should be).
  3. **Redact rewrites correctly or degrades to block:** a redactable JSON body arrives at
     upstream with the secret replaced and a valid Content-Length; a non-rewritable body is
     blocked, and the upstream receives nothing.
  4. **UNKNOWN honesty:** force an inspect error; assert the mode-appropriate action and that
     the audit/response says `unknown`, never "inspected".
- Metric: **leak-through count must be 0** for blocked cases on the fixture. Published as a
  synthetic measurement (separate from any real-world number), same discipline as 0001.

This harness is itself part of step 6's Definition of Done — the proxy isn't "done" until it
provably stops bytes against a server that counts them.

---

## 8. Enforcement contract (adapter-agnostic, from 0001 §4.3)

```
EnforcementAdapter (Protocol):
    namn: str
    enforcement_level: "guaranteed" | "best_effort"
    covered_paths() -> list[str]            # the §2 boundary, machine-readable
    # capture → inspect() → apply verdict:
    on_request(body, context) -> Outcome    # forward | block | forward(safe_text)
```

The Local Proxy and the CLI wrapper are two implementations; a future Browser Extension
implements the same Protocol with `enforcement_level = best_effort`. The decision core
(`inspect`) is shared and unchanged. This is the "build the enforcement core so all methods
can plug in" reservation, made concrete.

---

## 9. Decisions — RESOLVED (2026-11-09)

1. **Integration model = A (explicit loopback proxy) + C (CLI). Transparent MITM (B) is
   rejected for v1.** ✅ Serrier only ever sees explicitly-routed traffic; never a system CA.
2. **REDACT-and-forward: rewrite re-serializable JSON bodies (recompute Content-Length);
   where a body can't be cleanly sanitized, degrade to BLOCK (logged, never silent).** ✅
3. **First concrete target = the proxy** (the real product surface). The CLI wrapper (C)
   follows, reusing the same decision core + `EnforcementAdapter` contract. ✅
4. **Upstream allowlist for v1 (open):** which hosts the proxy forwards to — default set
   proposed: `api.anthropic.com`, `api.openai.com`, `generativelanguage.googleapis.com`.
   Confirm/trim when step 6 starts.

## 10. Definition of Done — step 6

- One enforcement adapter (proxy or CLI) that calls the unchanged decision core.
- `enforcement_level` + machine-readable covered-paths; UI/report never upgrades best-effort,
  never claims safety beyond the boundary.
- Loopback-only; upstream allowlist; no raw body logged/persisted; verifying TLS client.
- Three-mode failure handling wired; UNKNOWN surfaced, never "inspected".
- **Controlled-upstream verification harness green: leak-through = 0 for blocked cases;
  clean traffic byte-identical; redact rewrites or cleanly degrades to block.**
- ruff clean; all prior tests green; `v0.1.0` + decision-core behavior unchanged.
