# Serrier Pre-Send Guardian — browser extension (scaffold)

> **Status: scaffold, not published.** This is the MV3 skeleton from design
> [`0005`](../docs/design/0005-browser-extension-adapter.md) step 2. It is loaded **unpacked**
> for testing; it is **not** submitted to any store, and it is explicitly **not** comprehensive
> coverage of "web AI." See the coverage boundary below.

## What it does

It extends the Pre-Send Guardian to **web-based AI usage** — the one channel the `base_url`
proxy model structurally can't reach. When you send text in a **supported** AI chat box, a
content script reads the compose field, asks your **local** Serrier daemon over loopback
(`POST http://127.0.0.1:PORT/inspect`, step 1), and enforces the verdict **before** the text is
sent: **block / redact / warn / allow**.

- **Detection stays in the daemon** (same decision core as the proxy). The extension ships no
  detector of its own.
- **No MITM** — it reads the DOM compose field, not TLS. It does not intercept network requests.
- **UNKNOWN ≠ SAFE** — if the daemon is unreachable or the page layout can't be read, it treats
  the send as **UNKNOWN** and warns/blocks per your failure mode. It never silently allows.
- **Loopback-only** — the only outbound call is to `127.0.0.1`. No analytics, no phone-home, no
  remote config, no remote code (MV3-forbidden anyway).

## Install (unpacked, for testing)

1. Start the daemon: `serrier up` (defaults to loopback port **8788**).
2. Get the token: `cat ~/.serrier/proxy-token` (a 0600 file).
3. Chrome/Edge: `chrome://extensions` → enable **Developer mode** → **Load unpacked** →
   select this `extension/` folder.
4. Open the extension's **Options**, paste the token, confirm the port (8788), pick a failure
   mode, and (optionally) **fail-closed when the daemon is down**.
5. Open `claude.ai` and try sending a line containing a fake secret — it should be blocked
   before send. The toolbar **popup** has a "Test connection" button.

## Supported sites (the honest, brittle part)

- `claude.ai` and `chatgpt.com` in this scaffold. Selectors live in one place at the top of
  `content.js` (the `SAJTER` array).
- **DOM-coupled and brittle:** providers redesign their compose UIs; selectors break. When a
  selector no longer matches, the extension returns **UNKNOWN** (warn/block), never
  fail-open-silent. Adding a site = adding a selector entry + a `host_permissions` match +
  a `content_scripts` match. Each new site is uncovered until added.
- Rich editors, file attachments, and pasted images may be unreadable or only partially
  readable → UNKNOWN for those parts, not inspected-safe.

## Security of the extension itself

A content script that can read what you type into AI sites is high-privilege and holds a map of
your secrets (same principle as the repo's `SECURITY.md`). Therefore:

- `host_permissions` is limited to the **supported sites** + `127.0.0.1`, never `<all_urls>`.
- Raw compose text leaves the page **only** to the local daemon over loopback; it is never
  persisted or sent anywhere else by the extension.
- The token is stored in `chrome.storage.local` and sent only to `127.0.0.1`.

## Not in this scaffold (gated)

- Store submission (Chrome Web Store / Firefox AMO), privacy disclosures, permission
  justification — recurring review cost, done only when distributing (0005 §7 step 4).
- Robust re-send into rich editors (the allow/redact path uses a best-effort button click;
  marked brittle in `content.js`).
- More than one supported site; automated end-to-end tests against a live site.

## Tests

The security-critical logic — **an error-UNKNOWN (daemon down, no token, layout-miss) must
never become `allow`** — is extracted into `decision.js` (pure, no DOM/chrome) and tested in
Node, no browser or framework needed:

```bash
node extension/test/decision.test.js
```

It proves: daemon verdicts are followed (block/redact/allow); a reachable daemon's permissive
"unknown" is an explicit allow (marked); and every failure path (unreachable / no-token /
http-error / selector-miss) resolves to **block** (strict/fail-closed) or **confirm** (balanced)
— **never a silent allow**. Browser-level end-to-end (real site interception) still requires
manual unpacked loading.

## Files

| File | Role |
|---|---|
| `manifest.json` | MV3 manifest; minimal permissions; supported sites |
| `background.js` | service worker — the only thing that fetches loopback `/inspect` |
| `decision.js` | **pure** enforcement logic (verdict → action); shared by `content.js` + tests |
| `content.js` | the browser PEP — intercept submit, map decision to DOM (selectors on top) |
| `options.html` / `options.js` | configure port / token / failure mode / fail-closed |
| `popup.html` / `popup.js` | status + "test connection" |
| `test/decision.test.js` | Node test of the UNKNOWN-never-allow invariant |
