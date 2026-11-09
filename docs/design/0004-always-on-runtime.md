# Design 0004 — Always-on Guardian ("acts on start")

Status: **proposed** (best-practice blueprint; step 1 = daemon, to build next).
Builds on [0002](0002-guardian-proxy-adapter.md) (proxy) + [0003](0003-security-runtime-vision.md).
Grounded in a best-practice deep-search (2026-11-09); sources at the end.

Goal (user's words): *"each time I start Serrier, it acts"* — Serrier protects your AI tools
**automatically** when started, instead of wrapping every command (`serrier-guard run -- …`).

## 1. Two separate things — don't conflate them

- **"Acts on start"** = always-on prevention (a persistent daemon that auto-routes AI tools
  through the Guardian). **Lightweight** — we already have most pieces.
- **"Looks like a desktop app"** = a packaged, double-clickable, signed binary. **Heavy** —
  bundling Python + scanners + code-signing. A *separate, later* track (§5).

You get "acts" without "packaged." This doc is about "acts."

## 2. Routing model — base_url endpoint, NOT MITM (validated)

Serrier routes AI traffic by pointing each tool's `*_BASE_URL` at the local Guardian endpoint
— the **same model Cloudflare AI Gateway uses** (apps route all LLM traffic through one
endpoint; always-on detections run on it). Tools that want *full* inspection use **mitmproxy
(MITM)** — which we rejected (0002: liability + breaks cert pinning).

**Honest coverage ceiling — identical to the biggest incumbent.** Cloudflare's own docs state
that MCP traffic, arbitrary outbound HTTP, and DNS-level egress are **not** inspected — "anything
that does not traverse the LLM API at the gateway endpoint is not inspected." So Serrier "acts
on" **every AI tool pointed at it**, not literally all traffic. That boundary is best practice,
not a weakness — but it must be stated wherever "always-on" is claimed (red-team brief rule).

## 3. Architecture — headless core + (optional) tray

Best practice for an always-on local agent: a **headless core process** (the Guardian proxy
daemon) that an *optional, thin* tray/menu-bar client talks to over a **local HTTP API**.

- The daemon is the product; the tray is a nice-to-have. **Tray creation must never block or
  own the daemon's lifecycle** — "the app must never become an unreachable background process."
- Autostart (later) via platform APIs: `setLoginItemSettings` (mac/win), `~/.config/autostart`
  (Linux). Separate *tray-icon-visible* from *background-mode* (icon on, background opt-in).

Step 1 is just the **daemon** (`serrier up`/`down`/`status`). Tray is step 2.

## 4. Loopback hardening — REQUIRED for an always-on service (best practice)

A service that always listens on loopback is exposed to **DNS rebinding**: an attacker page
rebinds its hostname to `127.0.0.1`, so the request is *genuinely same-origin* and ordinary
CSRF/Origin defenses fail. Best-practice defenses, applied together:

1. **Token** on privileged routes — ✅ we have it (`skriv_token`, 0600 file, F7). For the daemon
   the token is **stable** (persisted) so the tool config stays valid across restarts.
2. **Host-header allowlist (TrustedHosts)** — reject any request whose `Host` isn't an expected
   local value (`127.0.0.1:PORT`, `localhost:PORT`). This is the one defense Origin/Sec-Fetch
   structurally cannot provide. **We do NOT have this yet** → add to the proxy for daemon mode.
3. **Origin same-origin check**; **no CORS** on loopback services.

**Course-correction (honest):** the CORS middleware we added for the dev dashboard
(`localhost:3000 → :8000`) is a **dev shortcut** that diverges from this best practice. The
correct packaged/daemon form serves the UI **same-origin** (a Tauri app, or the daemon serving
the UI) — then CORS is unnecessary and the Host-allowlist + token do the work. Keep CORS as a
dev-only convenience; the always-on/desktop form drops it.

## 5. Desktop packaging — the separate, heavy track (for distribution)

If/when we distribute a double-click app: **Tauri v2 + PyInstaller sidecar** is best practice —
Tauri wraps the frontend in a native window and runs the PyInstaller-compiled Python backend as
a managed sidecar; 20–50× smaller than Electron, sub-200 ms start, native installers per OS.

**The real cost is signing, not the window.** Both OSes block/warn on unsigned apps. macOS:
Apple Developer Program ($99/yr) + notarization + hardened runtime. Windows: Azure Trusted
Signing (~$10/mo) / SignPath (free for OSS) / OV cert — and **SmartScreen keeps warning until
the cert earns reputation over weeks.** Recurring cost + reputation lag → a real project, gated
behind "ready to distribute to real users."

## 6. Sequence

1. **Daemon** — `serrier up` / `down` / `status`: persistent proxy on a fixed loopback port +
   stable token, writes a sourced `env` file that points AI tools at it, records events to the
   control plane (#1). **+ Host-allowlist loopback hardening (§4).** ← build next.
2. **Tray client** — thin, optional, over local HTTP; autostart; non-blocking.
3. **Tauri packaging + signing** — only when distributing. **Scaffolded** in `desktop/` +
   `.github/workflows/desktop-release.yml` (Tauri v2 + PyInstaller sidecar + signing CI).
   NOT built/signed/verified in the headless dev env — builds on a machine/CI with the
   toolchain, a display, and certificates. See [`desktop/README.md`](../../desktop/README.md).

## 7. Definition of Done — step 1 (daemon)

- `serrier up` starts a persistent, loopback-only Guardian on a fixed port with a **stable**
  token; writes `~/.serrier/{daemon.pid, env.sh}` and reuses the 0600 token file.
- `env.sh` (sourced) sets `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL`/… at the daemon + `NO_PROXY`.
- Decisions flow to the dashboard live-feed (#1) while the daemon runs.
- **Host-header allowlist** rejects non-loopback Host (DNS-rebinding defense), token enforced.
- `serrier down` stops it and cleans up; `serrier status` reports running/port.
- Coverage boundary (§2) printed on `up` — never over-claims.
- One test per part; no new detection; frozen `security-remediation` branch untouched.

## Sources
- Cloudflare AI Gateway — AI Security reference architecture (endpoint routing + stated
  non-coverage of MCP/arbitrary HTTP/DNS).
- MLflow AI Gateway architecture guide (sidecar vs centralized patterns); AI DLP proxy via
  mitmproxy (the MITM path we reject).
- "Localhost is not a boundary: DNS rebinding & Host authorization"; DNS-rebinding mitigation
  (Host-allowlist + token, no CORS on loopback).
- Tauri v2 + Python server sidecar example; "Production desktop LLM apps: Tauri + FastAPI +
  PyInstaller"; Electron vs Tauri 2026 (bundle size / RAM / start).
- Electron code-signing & notarization; cross-platform code-signing/notarization guide.
- Headless-core + optional-tray background-agent pattern.
