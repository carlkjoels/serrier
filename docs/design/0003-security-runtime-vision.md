# Design 0003 — Serrier as an AI Security Runtime (north star, NOT a build plan)

Status: **vision / direction** — records the long-term framing and locks the epistemic
discipline it must obey. **Nothing here beyond Generation 1 is built, and Generations 2–4 are
explicitly gated** (see §6). This doc exists so that when later generations *are* built, they
are built against the honesty rules — constitution before the pressure.

> **Serrier — The Security Runtime for AI.** An intelligent layer that continuously observes,
> understands and governs AI-related activity — from information access to external calls and
> agent actions. **Prevent. Understand. Govern. Verify.**

## 1. The idea, stated honestly

The antivirus/EDR lesson is right: modern security is **several specialized engines feeding
one auditable decision architecture**, not one detector that understands everything. Engines
emit *structured observations*; a shared intelligence correlates them. That keeps the system
modular — an engine can be improved or swapped without rebuilding the whole.

But the EDR analogy is also a **trap to be named**: EDR earns trust through deep OS/kernel
telemetry. Serrier today sees **only what routes through the proxy** (request bodies). A
"behavioral runtime" that claims to watch file access, tool calls or agent actions needs
telemetry Serrier **does not have** — it requires separate integrations (Claude Code hooks,
MCP interception, OS-near sensors). We will not claim visibility we have not built. The
six-engine diagram is a *target*, not a description of current capability.

## 2. The four-state discipline — LOCKED (the most important rule)

Serrier must never conflate these four, in code, UI, or reporting:

| State | Meaning | Evidence required |
|---|---|---|
| **Observation** | something the system actually saw | the raw (redacted) detection |
| **Correlation** | a *relation* between observations | the linking rule + the linked observations |
| **Risk assessment** | an *estimate* of consequence | the dimensional model + its uncertainty |
| **Incident** | a claim that something bad happened | **separate, explicit evidence** |

A correlation is not an incident. An elevated-exposure *estimate* is not a breach. This is the
same discipline as the existing UNKNOWN-state rule and the "said/measured/tested" honesty that
runs through the whole product. **Contextual Intelligence (Gen 2) is dangerous precisely
because it can manufacture scary-but-false "exposure" from benign, unrelated activity.** It
must be built with the same adversarial rigor as detection recall, or not at all.

## 3. How the CURRENT code already maps to the vision

Gen 1 is not aspirational — it exists:

| Vision component | Already built |
|---|---|
| Secret Engine | `core/textdetect.py` (composable pattern engine) |
| Data Exposure Engine | `guardian/classify.py` (PII, entropy, evasion) |
| Context Engine (seed) | `correlation.py` (same-asset, cross-detector) — the *embryo* of Gen 2 |
| Code & Supply Chain | `scanners/` (gitleaks, semgrep, osv, git-history) |
| Network & Tool Engine (seed) | `scanners/natverk.py` (local posture only — no agent/tool telemetry yet) |
| Risk Intelligence & Correlation | `core/risk.py` + `correlation.py` (transparent, rule-based) |
| Policy & Decision Engine | `guardian/policy.py` (ALLOW/WARN/REDACT/BLOCK + 3 failure modes + UNKNOWN) |
| Response & Verification | `remediation.py` + Store auto-verify + regression (`aterkomster`) |
| Prevention Runtime | `guardian/proxy.py` + `guardian/run.py` (streaming, verified) |

So the **feedback loop already runs in miniature**: scan → analyst → remediation
(propose→approve) → rescan → auto-verify → regression. The path to the vision is *evolution of
these*, not a new system. That is the honest strength of the position.

## 4. Local agent + central intelligence (already the shape)

The locked architectural principle — **immediate security decisions must not depend on the
internet or an LLM** — is already how it's built: the decision core is local and
deterministic (an API key is blocked by code, never by asking a model). The control-plane API
+ per-org policy is the seed of the "Intelligence Cloud". Harder questions (is this an
internal-architecture description? is the *combination* sensitive? is this anomalous?) may use
models — but **a model never is the security boundary**. This is settled, not new.

## 5. Risk model — direction, not a formula yet

Split risk into dimensions (severity · exposure · exploitability · asset-criticality ·
confidence · persistence) rather than one opaque number. But **do not start with an arbitrary
multiply-everything formula.** Build a transparent, rule-based model with explicit evidence and
uncertainty, and calibrate against real test cases — the same way detection recall was
measured and published. Credibility comes from the calibration, not the equation.

## 6. Generations & the GATE

| Gen | Capability | Status |
|---|---|---|
| **1. Prevention Runtime** | protect AI requests, control traffic | **built** (proxy + CLI + streaming, verified) |
| 2. Contextual Intelligence | aggregate exposure, relations across a session | ◻ gated |
| 3. Behavioral Security | agent activity sequences & anomalies | ◻ gated — needs tool/file telemetry we don't have |
| 4. Adaptive Security | improve via verified feedback | ◻ gated |

**Gate (locked):** do NOT build Gen 2–4 now. Gen 1 must first be proven in real AI workflows
and **survive external security review**. The next milestone is *not more code* — it is
evidence that Gen 1 holds against a motivated attacker and is usable day-to-day. Only then does
Gen 2 (Contextual Intelligence) become the next differentiation, built on the `correlation.py`
seed, under the §2 four-state discipline.

## 7. Competitive honesty

Every adjacent category has incumbents: DLP, CASB, AI gateways (Cloudflare AI Gateway, Prompt
Security, Protect AI, Lakera), CNAPP, EDR. Serrier's wedge is **not "more engines."** It is the
combination incumbents tend to fake: **developer-native, local-first prevention with verifiable
leak-through = 0, honestly-stated coverage limits, no MITM, and a closed observe→verify loop.**
The thesis to prove is that *this combination produces a concretely better outcome for securing
AI usage* — not that it has more features. If the combination doesn't win on evidence, the
vision doesn't matter.

## 8. One-line thesis to test

> Can Serrier become, for AI workflows, what EDR became for endpoints — **without** overclaiming
> telemetry it doesn't have, and **without** confusing a correlation for an incident?

That is the question worth answering. The answer is earned by proof, not architecture.
