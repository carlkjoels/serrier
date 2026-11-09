# Serrier Desktop (Tauri) — scaffold

> **Status: scaffold, not a built app.** These files are the *correct* Tauri v2 + PyInstaller
> structure per best practice (design [`0004`](../docs/design/0004-always-on-runtime.md) §5),
> but a signed desktop binary is **built in CI / on a machine with the toolchain + a display +
> signing certificates** — not in the headless dev environment where this was scaffolded. None
> of the build/sign/notarize steps below have been run here; they run on your machine or in the
> `desktop-release` CI workflow.

## What this is

A thin Tauri v2 shell that:
1. Serves the existing Next.js dashboard (static export) in a native window.
2. Starts the Python backend as a **managed sidecar** (Tauri starts it on launch, kills it on
   quit) on a fixed loopback port.
3. The window talks to the sidecar over loopback (token + Host-allowlist; §4 of 0004).

Tauri v2 + PyInstaller is the best-practice lightweight path: ~20–50× smaller than Electron,
sub-200 ms start, native installers per OS.

## Prerequisites (on the build machine)

- **Rust + cargo** (`rustup`), **Node 20+**, **Python 3.12 + uv**.
- **Tauri CLI**: `cargo install tauri-cli --version '^2'` (or `npm i -D @tauri-apps/cli@^2`).
- Platform deps: Linux `webkit2gtk`/`libayatana-appindicator`; macOS Xcode CLT; Windows MSVC +
  WebView2.
- **PyInstaller** (`uv pip install pyinstaller`) to compile the backend sidecar.

## Build

```bash
# 1. Build the backend sidecar binary (named for the Rust target triple Tauri expects)
TRIPLE=$(rustc -Vv | sed -n 's/host: //p')
cd backend && uv run pyinstaller ../desktop/sidecar/serrier-backend.spec \
  --distpath ../desktop/src-tauri/binaries
mv ../desktop/src-tauri/binaries/serrier-backend \
   ../desktop/src-tauri/binaries/serrier-backend-$TRIPLE   # Tauri sidecar naming

# 2. Static-export the frontend (set the sidecar URL)
cd ../frontend && NEXT_PUBLIC_API=http://127.0.0.1:8788 npm run build   # needs output: 'export'

# 3. Build the desktop app + installers
cd ../desktop && cargo tauri build
```

Installers land in `desktop/src-tauri/target/release/bundle/`.

**Icons:** `tauri.conf.json` references `icons/icon.png`. Generate the full icon set from a
source logo once: `cd desktop && cargo tauri icon ../path/to/logo.png` (not committed here).

## Scanner binaries (honest TODO)

The backend's scanners (gitleaks/semgrep/osv) are external binaries. For a self-contained app
they must be bundled as **resources** (add to `tauri.conf.json → bundle.resources`) and the
adapters pointed at the bundled paths. Not wired in this scaffold — document + do it before
shipping, or the desktop app degrades gracefully to the built-in scanner only.

## Signing & notarization (the real cost — see 0004 §5)

Unsigned apps are blocked/warned by both OSes. The `desktop-release` CI workflow
(`.github/workflows/desktop-release.yml`) signs on real runners using repo secrets:

- **macOS:** `APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`,
  `APPLE_ID`, `APPLE_PASSWORD` (app-specific), `APPLE_TEAM_ID`. Requires Apple Developer
  Program ($99/yr); hardened runtime + notarization + stapling.
- **Windows:** `WINDOWS_CERTIFICATE` + `WINDOWS_CERTIFICATE_PASSWORD` (Azure Trusted Signing /
  SignPath / OV cert). SmartScreen keeps warning until the cert earns reputation over weeks.
- **Tauri updater (optional):** `TAURI_SIGNING_PRIVATE_KEY` + password.

Without these secrets the workflow still *builds* but produces **unsigned** artifacts (dev/test
only — never distribute unsigned).

## Frontend note

Tauri serves static assets, so the dashboard must be **statically exportable**
(`next.config.mjs → output: 'export'`). The app is a client component that fetches the sidecar
API, so export works. `NEXT_PUBLIC_API` is baked at build time → point it at the sidecar's fixed
loopback port. (In same-origin packaged form the dev CORS is unnecessary; see 0004 §4.)
