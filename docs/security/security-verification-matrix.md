# Security Verification Matrix

Every row ties a **threat** to the **expected behavior**, the **test(s)** that exercise it, the
**evidence** (file/function), and two independent status dimensions. This matrix is the
contract a reviewer uses to check claims against code — nothing here is asserted without a
pointer you can open.

> Branch: `security-hardening` (off `main`). Frozen review branch `security-remediation`
> (tag `review-remediation-2026-11-09`) is **not** the source of these rows — these are
> re-applied and re-verified on the current trunk surface.

## Status dimensions (kept separate on purpose)

**Implementation status** — is the control built?
`Implemented` · `Partially` (built with stated gaps) · `Planned` · `Not covered` · `Not applicable`.

**Verification status** — how do we *know*?
`Independently verified` (external reviewer / third party) · `Automated-test verified` (a named
test in the suite exercises it) · `Manually tested` (run by hand, not in CI) · `Not verified`.

**Honest note on this branch:** nothing here is `Independently verified` yet — that is exactly
what the pending external review is for. Rows below are at most `Automated-test verified`. A
passing synthetic test proves the coded behavior, not resistance to a motivated attacker.

Test IDs are `pytest` node names under `backend/tests/`. Run a single row with
`uv run pytest tests/<file>::<test>`.

---

## 1. Authentication & authorization

| # | Threat | Expected behavior | Test(s) | Evidence | Impl | Verification | Limitation |
|---|---|---|---|---|---|---|---|
| AUTH-1 | Anonymous caller uses the API in prod | No key → 401 when keys exist or `SERRIER_REQUIRE_AUTH` set; dev stays open | `test_auth.py::test_nar_nycklar_finns_kravs_auth`, `::test_dev_lage_utan_nycklar_tillater_flode` | `api/app.py::nuvarande_principal` | Implemented | Automated-test verified | Dev mode is intentionally open (local only) |
| AUTH-2 | API key stored/compared insecurely | sha256-hash at rest, never raw, constant-time compare | `test_auth.py::test_nyckel_hashas_och_matchar_i_konstant_tid` | `auth.py`, `db/store.py` | Implemented | Automated-test verified | — |
| AUTH-3 | Low-privilege role performs privileged action | RBAC viewer<member<owner enforced per endpoint | `test_auth.py::test_rbac_viewer_far_inte_skanna_men_member_far`, `::test_rollhierarki` | `auth.py::far`, `api/app.py` dep-guards | Implemented | Automated-test verified | — |
| AUTH-4 | Proxy used by another local process | Loopback token required (constant-time); path- or header-token | `test_guardian_proxy.py::test_loopback_auth_token_kravs` | `guardian/proxy.py::_auktoriserad` | Implemented | Automated-test verified | Token optional in dev (None = open) |

## 2. Tenant isolation

| # | Threat | Expected behavior | Test(s) | Evidence | Impl | Verification | Limitation |
|---|---|---|---|---|---|---|---|
| TEN-1 | Cross-tenant data access | Other org's data → 404 (existence never leaks) | `test_auth.py::test_cross_tenant_ger_404` | `db/store.py`, `api/app.py::_kravs_projekt` | Implemented | Automated-test verified | — |
| TEN-2 | Open org bootstrap in prod | `/orgs` refuses when keys exist **or** auth required | `test_security_hardening.py::test_A_orgs_bootstrap_stangs_av_nar_auth_kravs` | `api/app.py::skapa_org` | Implemented | Automated-test verified | — |

## 3. Secure defaults / configuration (finding A)

| # | Threat | Expected behavior | Test(s) | Evidence | Impl | Verification | Limitation |
|---|---|---|---|---|---|---|---|
| CFG-1 | Insecure prod config starts silently | Auth required but no keys → refuse to start (fail-closed) | `test_security_hardening.py::test_A_konfig_vagrar_starta_nar_auth_kravs_utan_nycklar` | `api/app.py::krav_sakra_konfig` (lifespan + entrypoint) | Implemented | Automated-test verified | Guards the auth-vs-keys trap; not a full config audit |
| CFG-2 | Default DB password shipped | No `:-serrier` fallback; password required | `test_security_hardening.py::test_A_compose_binder_loopback_och_kraver_auth` | `docker-compose.yml` | Implemented | Automated-test verified | Static assertion on compose text |
| CFG-3 | Service exposed on the network by default | Ports bound to `127.0.0.1` | same as CFG-2 | `docker-compose.yml` | Implemented | Automated-test verified | Operator can still re-expose deliberately |
| CFG-4 | Dev owner-shortcut reachable in prod | `SERRIER_REQUIRE_AUTH=1` disables dev-owner; falsy values don't | `test_security_hardening.py::test_A_konfig_falska_varden_ar_inte_require_auth`, `::test_A_konfig_ror_inte_dev_lage` | `api/app.py::_sant`, `krav_sakra_konfig` | Implemented | Automated-test verified | — |

## 4. Filesystem path confinement (finding B)

| # | Threat | Expected behavior | Test(s) | Evidence | Impl | Verification | Limitation |
|---|---|---|---|---|---|---|---|
| PATH-1 | `..` traversal out of workspace | Canonical resolve + reject outside root → 403/exception | `test_security_hardening.py::test_B_blockar_traversal_ut_ur_roten`, `::test_B_scan_endpoint_ger_403_utanfor_workspace` | `core/sokvag.py::validera_scan_sokvag`, `api/app.py::scan` | Implemented | Automated-test verified | Enforced only when `SERRIER_WORKSPACE_ROOT` set |
| PATH-2 | Symlink inside workspace escapes it | `realpath` follows symlink; reject if resolved target outside | `test_security_hardening.py::test_B_blockar_symlank_escape` | `core/sokvag.py::inom_roten` | Implemented | Automated-test verified | — |
| PATH-3 | Prefix confusion (`/a/ws-evil` vs `/a/ws`) | Component-wise check (`is_relative_to`), not string prefix | `test_security_hardening.py::test_B_blockar_prefix_forvaxling` | `core/sokvag.py::inom_roten` | Implemented | Automated-test verified | — |
| PATH-4 | API-boundary check bypassed internally | Scanner boundary re-validates (defense in depth) | `test_security_hardening.py::test_B_scanner_granssen_enforcar_ocksa` | `scanners/registry.py::kor_skanners` | Implemented | Automated-test verified | — |
| PATH-5 | Scanner reads huge/binary/vendor files | Per-file size cap, binary skipped, VCS/vendor dirs skipped, per-file confinement | `test_builtin_scanner.py` (existing) | `scanners/base.py::las_rader`, `inom_roten` | Implemented | Automated-test verified | — |

## 5. Request limits & streaming (finding C)

| # | Threat | Expected behavior | Test(s) | Evidence | Impl | Verification | Limitation |
|---|---|---|---|---|---|---|---|
| REQ-1 | Oversized body (honest Content-Length) | Reject 413 before reading | `test_guardian_proxy.py::test_body_for_stor_avvisas` | `guardian/proxy.py::_hantera` (CL precheck) | Implemented | Automated-test verified | — |
| REQ-2 | Oversized body, **no** Content-Length (chunked) | Streamed byte-count aborts mid-read → 413 | `test_security_hardening.py::test_C_oversize_utan_content_length_ger_413` | `guardian/proxy.py::_las_begransad` | Implemented | Automated-test verified | — |
| REQ-3 | Memory-DoS via unbounded buffering | Stop pulling chunks the moment the cap is passed (never buffer whole body) | `test_security_hardening.py::test_C_las_begransad_buffrar_inte_hela_vid_overskridande` | `guardian/proxy.py::_las_begransad` | Implemented | Automated-test verified | Buffers up to cap + one chunk (bounded) |
| REQ-4 | Off-by-one at the limit | Exactly-at-limit passes; one over fails | `test_security_hardening.py::test_C_las_begransad_exakt_pa_gransen_passerar`, `::test_C_las_begransad_avbryter_over_gransen` | `guardian/proxy.py::_las_begransad` | Implemented | Automated-test verified | — |

## 6. Network: SSRF, DNS rebinding, upstream validation (existing + A)

| # | Threat | Expected behavior | Test(s) | Evidence | Impl | Verification | Limitation |
|---|---|---|---|---|---|---|---|
| NET-1 | SSRF to private/loopback upstream | Resolve + reject non-global IP; fail-closed on resolve error | `test_guardian_proxy.py::test_ssrf_guard_avvisar_privat_och_loopback`, `::test_proxy_avvisar_privat_upstream_ssrf` | `guardian/proxy.py::validerad_ip` | Implemented | Automated-test verified | IPv4/IPv6 global-address check; not a full egress firewall |
| NET-2 | DNS rebinding TOCTOU (resolve→connect) | Pin connection to the validated IP; SNI/Host preserved | `test_guardian_proxy.py::test_ssrf_guard_slapper_global_och_pinnar_ip`, `::test_ssrf_guard_avvisar_dns_rebinding_till_privat` | `guardian/proxy.py::_forwarda` (IP-pinning) | Implemented | Automated-test verified | — |
| NET-3 | DNS rebinding against loopback service (Host) | Host-header allowlist rejects non-loopback Host (daemon mode) | `test_daemon.py` (host-allowlist) | `guardian/proxy.py::_hantera` (`tillaten_host`), `daemon.py::tillaten_host` | Implemented | Automated-test verified | Enforced only when `tillaten_host` set (daemon) |
| NET-4 | Request to non-allowlisted upstream | Unknown upstream key → 404, nothing leaks | `test_guardian_proxy.py::test_okand_upstream_404_inget_lacker` | `guardian/proxy.py::_upstream` | Implemented | Automated-test verified | Strict allowlist, no wildcard |
| NET-5 | Upstream/network error mid-forward | Fail-closed 502, never blind-forward | `test_guardian_proxy.py` (upstream-fel path) | `guardian/proxy.py::_forwarda` | Implemented | Automated-test verified | — |

## 7. Request inspection coverage (findings D/E)

| # | Threat | Expected behavior | Test(s) | Evidence | Impl | Verification | Limitation |
|---|---|---|---|---|---|---|---|
| INS-1 | Secret smuggled in URL query | Inspect `unquote(query)`; sensitive → block | `test_security_hardening.py::test_D_hemlighet_i_query_blockeras`, `::test_D_procentkodad_hemlighet_i_query_blockeras` | `guardian/proxy.py::_hantera` (query branch) | Implemented | Automated-test verified | Query can't be redacted → block-only |
| INS-2 | Benign query over-blocked | Normal params forwarded byte-identical | `test_security_hardening.py::test_D_ofarlig_query_slapps_igenom` | same | Implemented | Automated-test verified | — |
| INS-3 | Secret hidden in gzip/deflate/br body | Content-Encoding≠identity → UNKNOWN; fail-mode governs | `test_security_hardening.py::test_E_kodad_body_blockeras_i_balanced`, `::test_E_alla_kodningar_blockeras_i_strict` | `guardian/proxy.py::_hantera` (encoding branch) | Implemented | Automated-test verified | We do **not** decompress + inspect; UNKNOWN, not inspected-safe |
| INS-4 | Encoded body silently called "safe" | Permissive forwards **unchanged**, logged UNKNOWN (never redact) | `test_security_hardening.py::test_E_kodad_body_forwardas_orord_i_permissive` | same | Implemented | Automated-test verified | Permissive does forward unknown content — by policy |
| INS-5 | Header-based secret smuggling | Auth headers passed through; raw headers never logged | — (see limitation) | `guardian/proxy.py::_SLOPPA_HEADERS`, `_logga` | Partially | Not verified | **No comprehensive header-value inspection.** Claimed nowhere as covered; see security-limitations.md |
| INS-6 | Binary / multipart body with embedded secret | Decoded as UTF-8 best-effort; may miss secrets in binary parts | — | `guardian/proxy.py` (utf-8 "replace") | Partially | Not verified | Documented gap; not UNKNOWN-flagged for arbitrary binary content-types |

## 8. Policy, UNKNOWN & fail-closed

| # | Threat | Expected behavior | Test(s) | Evidence | Impl | Verification | Limitation |
|---|---|---|---|---|---|---|---|
| POL-1 | UNKNOWN silently treated as SAFE | UNKNOWN is a first-class state, never `ok` | `test_guardian_inspect.py::test_unknown_aldrig_ok_status`, `test_guardian_policy.py::test_unknown_strict_blockerar` | `guardian/policy.py::besluta` | Implemented | Automated-test verified | — |
| POL-2 | UNKNOWN leaks through in balanced | Requires approval → never silently forwarded | `test_guardian_policy.py::test_unknown_balanced_kraver_godkannande_slapper_aldrig_tyst` | `guardian/policy.py` | Implemented | Automated-test verified | Permissive intentionally allows UNKNOWN (marked) |
| POL-3 | Weakest action wins among several | Strictest action wins | `test_guardian_policy.py::test_strangast_vinner`, `::test_strangaste_aktionen_bland_flera` | `guardian/policy.py` | Implemented | Automated-test verified | — |
| POL-4 | Detection failure opens the gate | Exception → UNKNOWN (fail-mode governs) | `test_guardian_inspect.py::test_detektionsfel_ger_unknown` | `guardian/inspect.py::inspect` | Implemented | Automated-test verified | — |

## 9. Data leakage / redaction

| # | Threat | Expected behavior | Test(s) | Evidence | Impl | Verification | Limitation |
|---|---|---|---|---|---|---|---|
| LEAK-1 | Blocked secret reaches upstream | Leak-through = 0 over a byte-counting upstream (real TCP/ASGI) | `test_guardian_proxy.py::test_block_stoppar_bytes_leakthrough_noll`, `::test_leakthrough_noll_over_batteri` | `guardian/proxy.py`, `tests/upstream_harness.py` | Implemented | Automated-test verified | Covers the AI-API channel only (see LIMIT) |
| LEAK-2 | Raw secret in safe_text / response | `safe_text` masks every hit; opaque marker | `test_guardian_inspect.py::test_safe_text_innehaller_aldrig_ra_traff` | `guardian/inspect.py::maska` | Implemented | Automated-test verified | — |
| LEAK-3 | Clean traffic corrupted | Clean body forwarded byte-identical | `test_guardian_proxy.py::test_ren_trafik_gar_igenom_byte_identisk` | `guardian/proxy.py::_forwarda` | Implemented | Automated-test verified | — |
| LEAK-4 | Redact produces invalid/unsafe JSON | Redact degrades to block when it can't rewrite safely | `test_guardian_proxy.py::test_redact_degraderar_till_block_nar_ej_json` | `guardian/proxy.py::_sanera_json` | Implemented | Automated-test verified | — |
| LEAK-5 | Response body carries a secret back | **Response content is not inspected** (stream relayed only) | `test_guardian_proxy.py::test_sse_relayas_och_content_type_bevaras` | design 0002 §streaming | Not covered | Not verified | Deliberate scope boundary; stated, not hidden |

## 10. Token, audit & secret hygiene (finding G)

| # | Threat | Expected behavior | Test(s) | Evidence | Impl | Verification | Limitation |
|---|---|---|---|---|---|---|---|
| SEC-1 | Proxy token printed to stdout/logs | Token → 0600 file; only the path is printed | `test_security_hardening.py::test_G_main_skriver_inte_token_till_stdout`, `::test_G_skriv_token_skapar_0600_fil` | `guardian/proxy.py::skriv_token`, `main` | Implemented | Automated-test verified | — |
| SEC-2 | Audit grows unbounded (memory) | Bounded ring buffer `deque(maxlen=1000)` | `test_security_hardening.py::test_G_audit_ar_bunden_ringbuffert` | `guardian/proxy.py::_AUDIT_MAX`, `audit` | Implemented | Automated-test verified | In-memory audit only; durable audit = Planned |
| SEC-3 | Raw secret in audit record | Audit stores verdict + redacted findings only | `test_guardian_proxy.py::test_unknown_blockeras_och_markt_aldrig_inspekterat` | `guardian/proxy.py::_logga` | Implemented | Automated-test verified | — |
| SEC-4 | Secret pulled from another app's `.env` | `ladda_nyckel` reads env only; no cross-project `.env` | `test_security_hardening.py::test_G_analyst_laser_inte_cross_projekt_env`, `::test_G_analyst_kallkod_namner_inte_selvra_analysis` | `analyst.py::ladda_nyckel` | Implemented | Automated-test verified | — |

## 11. Scanner isolation (finding F)

| # | Threat | Expected behavior | Test(s) | Evidence | Impl | Verification | Limitation |
|---|---|---|---|---|---|---|---|
| ISO-1 | Runaway scanner burns CPU / writes huge file | rlimit `RLIMIT_CPU` + `RLIMIT_FSIZE` in child (preexec) | `test_security_hardening.py::test_F_resursgrans_satter_cpu_och_filstorlek`, `::test_F_adaptrar_anvander_preexec` | `scanners/resurser.py`, adapters | Implemented | Automated-test verified | **Not a sandbox** — no namespace/seccomp/cgroup isolation (see LIMIT) |
| ISO-2 | Resource cap starves the scanner | `RLIMIT_AS` deliberately NOT set; semgrep still runs | `test_security_hardening.py::test_F_semgrep_svalts_inte_av_gransen` | `scanners/resurser.py` (docstring) | Implemented | Automated-test verified | Trade-off documented |
| ISO-3 | Non-POSIX platform | Graceful no-op; timeout still applies | `test_security_hardening.py::test_F_resursgrans_no_op_utan_resource` | `scanners/resurser.py` | Implemented | Automated-test verified | Windows relies on wall-clock timeout only |
| ISO-4 | Scanner crash / hang | Wall-clock `timeout`; graceful degradation (empty result) | `test_semgrep_adapter.py`, `test_gitleaks_adapter.py`, `test_osv_adapter.py` | adapters | Implemented | Automated-test verified | — |

## 12. Supply chain (finding G)

| # | Threat | Expected behavior | Test(s) | Evidence | Impl | Verification | Limitation |
|---|---|---|---|---|---|---|---|
| SUP-1 | Tampered scanner binary in image | SHA256-verify (`sha256sum -c`) before use; fail-closed | `test_security_hardening.py::test_G_dockerfile_pinnar_och_verifierar` | `backend/Dockerfile` | Implemented | Automated-test verified | Values verified from release source (gitleaks checksums.txt; osv via TLS-fetch+hash) |
| SUP-2 | Unpinned toolchain drift | `uv` pinned (not `:latest`); semgrep `==` pinned; deps via `uv.lock --frozen` | same | `backend/Dockerfile`, `uv.lock` | Implemented | Automated-test verified | Base images pinned by tag, not digest (stronger form = Planned) |
| SUP-3 | Vulnerable dependency shipped | osv-scanner flags known CVEs in lockfiles | `test_osv_adapter.py` | `scanners/osv_adapter.py` | Implemented | Automated-test verified | Coverage = osv DB; offline mode optional |
| SUP-4 | Sensitive files committed to VCS | `.gitignore` excludes `.env*`, keys, secrets/, db, scanner binaries; token lives in `~/.serrier` (outside repo) | — (static) | `.gitignore` | Implemented | Manually tested | — |

---

## How to reproduce the whole matrix

```bash
cd backend
uv run pytest -q                 # full suite (216 tests)
uv run pytest tests/test_security_hardening.py -q   # the A–G regression rows (45)
uv run ruff check serrier tests  # lint
```

Record what you ran and the counts; do not mark a row verified you did not execute.
