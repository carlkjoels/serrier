# Design 0005 — Browser-extension adapter ("prevention for web AI")

Status: **proposed** (design only; nothing built). A separate, gated track — not part of the
security-hardening work (PR #1, findings A–G).
Builds on [0001](0001-pre-send-guardian.md) (decision core), [0002](0002-guardian-proxy-adapter.md)
(proxy adapter), [0003](0003-security-runtime-vision.md) (runtime vision),
[0004](0004-always-on-runtime.md) (always-on daemon).

Goal: extend **prevention** to **web-based AI usage** — the one place the base_url model
structurally cannot reach.

## 1. The gap this closes (and why base_url can't)

The Guardian's reach today is **tools that point `*_BASE_URL` at the loopback proxy** (CLI,
SDKs). The honest coverage ceiling in [0004 §2] already names the miss: **arbitrary outbound
HTTP / web** is not inspected.

When a developer pastes a secret into **`claude.ai`, `chatgpt.com`, the Gemini web app, or
Copilot in the browser**, that traffic goes **browser → provider directly over TLS** — it never
traverses the loopback endpoint. Yet copy-pasting into a chat box is one of the **most common**
ways secrets and private context actually leave. A browser extension is the only realistic way
to put a Pre-Send check in front of that path.

**This does not widen the product's claims — it widens one specific, named channel**, and it
comes with its own (smaller, brittler) ceiling (§5). "Deepen, don't broaden" still holds: same
decision core, one more integration method.

## 2. Architecture — a thin PEP that calls the existing PDP

The extension is **another Policy Enforcement Point** (0003 language). It holds **no detection
logic of its own**.

```
AI web UI (claude.ai / chatgpt.com / …)
   │  user hits "send" in the compose box
   ▼
content script (intercept submit)  ──POST text──▶  Serrier daemon 127.0.0.1:PORT
   │                                                 (token + Host-allowlist; 0004 §4)
   │                                                 inspect() → decision core (0001)
   ◀──────────── GuardDecision (block / redact / warn / allow) ────────────────────
   │
   ├─ allow   → let the submit proceed
   ├─ redact  → replace the field with safe_text, then proceed (user sees the redaction)
   ├─ warn    → inline banner; require an explicit click-through
   └─ block   → cancel the submit; show why (redacted finding summary)
```

Key properties, inherited from the existing core so they stay in **one** place:
- **Detection stays server-side.** The extension sends the compose text to the local daemon's
  `inspect()` (the same `textdetect`/`classify`/`policy` the proxy uses). No duplicate detector,
  no detection logic shipped to the browser.
- **No MITM.** We read the **DOM compose field**, not TLS. We do not intercept, decrypt, or
  modify network requests of other origins. The no-MITM invariant (0002) is preserved.
- **UNKNOWN ≠ SAFE.** If the extension can't read the field (unknown site layout, rich editor it
  can't parse, daemon unreachable) → **UNKNOWN**, and the failure mode governs (STRICT/BALANCED
  block or require click-through; PERMISSIVE warns). It never silently allows on failure.
- **Fail-closed on daemon-down** in STRICT/BALANCED: if the local daemon isn't running, the
  extension warns/blocks rather than letting the paste through unchecked (configurable; default
  = warn, never silent-allow).

## 3. Why DOM-level, not network-level (Manifest V3 reality)

- **MV3 removed blocking `webRequest`** for extensions; `declarativeNetRequest` can block/redirect
  by URL pattern but **cannot read or rewrite request bodies**. You cannot inspect the JSON a web
  app POSTs to its provider. So network-layer interception in the browser is **not viable** for
  content inspection.
- The workable path is a **content script** that hooks the site's **compose box submit** (button
  click / Enter / paste) in the page's DOM, reads the text, checks it, and lets or stops the
  submit. This is per-site and selector-coupled (§5).
- Messaging: content script → background service worker → `fetch("http://127.0.0.1:PORT/…")`
  with the **daemon token**. The daemon's Host-allowlist + token (0004 §4) is exactly the
  loopback-auth this needs; no new auth mechanism.

## 4. The extension is itself a high-value target

A content script that can read everything a user types into AI sites is **high-privilege** and
holds a map of the user's secrets — the same principle as `SECURITY.md` (a security product that
is itself insecure is worse than none). Non-negotiables:

- **Loopback-only egress.** The extension talks to `127.0.0.1` and **nowhere else**. No
  analytics, no phone-home, no remote config. (Reviewable in the store listing.)
- **Minimal permissions.** `host_permissions` limited to the **explicitly supported AI sites**,
  not `<all_urls>`. `activeTab`/`scripting` scoped as tightly as MV3 allows.
- **Redact locally, send loopback.** Raw text leaves the page only to the local daemon over
  loopback; it is never persisted by the extension and never sent anywhere else.
- **No remote code.** MV3 forbids remote code; we add nothing that fetches executable logic.
- **Tamper/consistency.** The decision shown must match the decision enforced — no "warn but
  send anyway" races; the submit is gated on the daemon's verdict.

## 5. Honest coverage boundary (state it wherever "web AI" is claimed)

- **Supported-sites only.** Coverage = the AI web UIs we explicitly add selectors for. It is
  **not** "all browser AI." New sites are uncovered until added.
- **DOM-brittle.** Providers redesign their compose UIs; selectors break. This needs ongoing
  maintenance and a **fail-UNKNOWN** posture when the layout no longer matches (never
  fail-open-silent).
- **Rich editors / attachments / images.** Contenteditable/rich editors, file attachments, and
  pasted images may be unreadable or only partially readable → UNKNOWN for those parts, not
  inspected-safe.
- **Same recall ceiling** as the core detector (<100%); UNKNOWN exists because detection is
  fallible.
- **Not a replacement** for the proxy/CLI path — it's an **additional** channel. The two together
  cover "SDK/CLI tools pointed at us" **plus** "the AI web UIs we support," still not all traffic.

## 6. Scope guard (what this is NOT)

- Not a generation 2–4 capability; it adds **no new detection**, just a new PEP.
- Not a network interceptor, not a proxy-for-the-browser, not MITM.
- Not bundled into PR #1 (A–G). This is its own track with its own review.
- Not a claim of comprehensive web coverage — see §5.

## 7. Sequence

1. **Daemon inspect endpoint** — confirm/shape a loopback `POST /inspect` on the daemon that
   returns a `GuardDecision` for arbitrary text (the proxy already has `inspect()`; expose it for
   the extension with token + Host-allowlist). One test.
2. **MV3 skeleton** — manifest, background service worker, one supported site (e.g. `claude.ai`),
   content-script submit hook, loopback messaging with token. Block/warn/allow first; redact
   after. **Honest "scaffold, not published"** marker like `desktop/` (0004 §5).
3. **Second site + fail-UNKNOWN** — add a second provider, prove selector-miss → UNKNOWN (not
   silent-allow), daemon-down → warn/block per failure mode.
4. **Store packaging** — only when distributing: Chrome Web Store + Firefox AMO review, privacy
   disclosures, minimal-permission justification. Recurring review cost, like code-signing.

## 8. Definition of Done — step 1+2 (scaffold)

- Daemon exposes a token-authenticated, Host-allowlisted loopback `inspect` for arbitrary text;
  one test proving a secret → block decision and clean text → allow.
- MV3 extension (one site) intercepts compose submit, calls the daemon, and enforces
  block/warn/allow; **block cancels the send** (no leak-through of the field).
- Daemon-unreachable and layout-miss both resolve to **UNKNOWN → warn/block** per failure mode,
  never silent-allow — with a test or a documented manual check.
- Permissions limited to the one supported site; **no non-loopback egress** (reviewable).
- Coverage boundary (§5) printed in the extension's UI/readme; never over-claims.
- Marked **scaffold, not published**; no store submission in this step. Security-hardening branch
  and PR #1 untouched.

## Sources
- Chrome Manifest V3 — `declarativeNetRequest` (no request-body access) vs the removed blocking
  `webRequest`; content scripts & `host_permissions`; remote-code prohibition.
- DNS-rebinding mitigation for loopback services (Host-allowlist + token, no CORS) — [0004 §4].
- Cloudflare AI Gateway coverage note (endpoint routing does not cover non-API/web traffic) —
  [0004 §2], the same ceiling this adapter partially addresses for web UIs.
- Serrier `SECURITY.md` (a security tool is itself a high-value target; least privilege, no
  phone-home).
