# Serrier — sessionssammanfattning (2026-11-09)

Från platform-härdning till en alltid-på säkerhets-runtime. Allt på
`github.com/carlkjoels/serrier`. Den röda tråden: **ärlighet** — säger aldrig "säker",
redaktion hela vägen, UNKNOWN ≠ säkert, dokumenterade täckningsgränser, "scaffold" kallas
scaffold.

## 1. Platformen färdigställd & härdad (Fas 6–10)
- **Deployment:** Postgres-stöd + Alembic-migrationer + Docker/Compose.
- **Multi-tenant:** API-nyckel-auth (sha256, aldrig råa), org-isolering, RBAC (viewer/member/owner).
- **Djup:** cross-detector-korrelation, regressions-spårning, SARIF 2.1.0/JSON-export, live-verifierad Next.js-dashboard.
- Milstolpe **`v0.1.0`** taggad som stabil referenspunkt.

## 2. Pre-Send Guardian — pivoten till *prevention* (Fas 11)
Från "hitta risk i vilande kod" till "stoppa exponering innan den skickas".
- **Design 0001** → beslutskärnan (steg 1–4): delad detektionsmotor, PII+entropi, policy-motor med **tre fel-lägen + UNKNOWN som eget tillstånd**, `inspect()` + `safe_text`.
- **Steg 5:** evasion-härdning (homoglyf/zero-width/base64/mellanslag) — adversarial recall 1.00, + per-org policy.
- **Design 0002** → **loopback-proxyn** (steg 6): strikt allowlist, SSRF/DNS-rebinding-skydd, ingen MITM, **leak-through = 0 verifierat mot en bytes-räknande upstream över riktigt TCP**.
- **CLI-wrappern** (`serrier-guard run -- claude`) + **streaming** (verifierat med riktiga Anthropic-SDK:n).
- Skarp mätning: **0 % falska positiva** på 15 riktiga utvecklar-prompts, ~1 ms overhead.

## 3. Strategi & ärlighet i skrift
- **Design 0003 — "Developer-native AI Security Runtime":** fyra generationer (1 byggd, 2–4 grindade); låst disciplin **observation ≠ korrelation ≠ risk ≠ incident**.
- **Red-team-brief** (8 angreppsmål, "ta dig runt testerna") + **Framework Alignment** (NIST/Zero Trust/OWASP/MITRE/CISA/ENISA — *informed-by, inte certifierad*, varje rad bunden till ett test).

## 4. Extern kodgranskning → åtgärdad på fryst branch
Statisk granskning hittade **7 fynd** (Docker-auth, path-confinement, body-gräns,
query/header-coverage, kodad-body→UNKNOWN, scanner-rlimits, städning). Alla åtgärdade på
**separat `security-remediation`-branch** (ett test per fynd, ingen scope-expansion), plus en
**oberoende verifieringsrunda** med adversariella varianter och **ärligt redovisade olösta
risker**. Fryst som **`review-remediation-2026-11-09`** — orörd för granskaren, med before/after.

## 5. Knöt ihop säcken & gjorde den användbar
- **#1 — Live-koppling:** proxy/inspect skriver **redakterade** beslut till kontrollplanet → `/guard`-dashboardvyn blev en **live prevention-monitor**.
- **Guardian-dashboardvyn** (`/guard`) — prevention fick ett ansikte.
- **#2 — `make dev`:** ett kommando startar hela appen; + `make scan/guard/test/lint`.
- Fångade och fixade en **CORS-bugg** som blockerade dashboardens datahämtning (upptäckt vid live-verifiering).

## 6. Alltid-på & skrivbord (best-practice-styrt)
- **Deep-search** på best practice → **Design 0004-blueprint** (bekräftade att base_url-modellen + den ärliga täckningsgränsen = samma som Cloudflare AI Gateway; gav loopback-härdning vi saknade).
- **Daemon** (`serrier up/down/status`) — Serrier **agerar på start**: live-verifierat att en hemlighet genom daemonen → 403 före Anthropic. + **Host-allowlist mot DNS-rebinding**.
- **Tray** (`serrier tray`) — valfri status-/styr-ikon (logiken testad; GUI kräver display).
- **Tauri-scaffold + signerings-CI** (steg 3) — *ärligt märkt som scaffold, ej byggt här*; byggs på maskin med toolchain + certifikat.

## Siffror & läge
- **~170 tester gröna på main, ruff rent** (181 på granskningsbranchen).
- **Två halvor som nu hänger ihop:** Security Intelligence (scanner-dashboarden) + Prevention Infrastructure (Guardian-proxyn/daemonen), delat kontrollplan och dashboard.
- **main:** allt levande. **`security-remediation`:** fryst för granskare. 

## Nästa riktiga milstolpe (inte mer kod)
Extern granskning av den frysta branchen + att faktiskt köra `serrier up` i dagligt AI-arbete.
Kvar i 0004-sekvensen (gated/separat): scanner-bundling i sidecaren, Tauri-bygge + signering
(Apple $99/år, Windows-cert), tray visuell test, gen 2–4 (kontext/beteende) efter validering.
