# Security Framework Alignment

Serrier's security architecture and engineering practices are **informed by** established
cybersecurity frameworks, application-security standards, and adversarial threat knowledge
bases. These references give a common foundation for threat modeling, architecture,
technical verification, and continuous improvement.

> **Framework alignment does not imply certification, accreditation, or full compliance.**
> Each mapping is bounded to the capabilities and controls **implemented and verified** in the
> relevant Serrier release. Named frameworks are a shared vocabulary and a design compass —
> not a claim that every requirement or technique is covered.

**Status legend:** `Implemented` (built + tested) · `Partially` (some controls, with stated
gaps) · `Pending review` (built on the frozen `security-remediation` branch, tag
`review-remediation-2026-11-09`, awaiting independent review before merge) · `Planned`
(future generation) · `Not covered`.

---

## 1. Frameworks referenced

### Cybersecurity risk management
- [NIST Cybersecurity Framework (CSF) 2.0](https://www.nist.gov/cyberframework) — Govern · Identify · Protect · Detect · Respond · Recover.
- [NIST SP 800-218 — Secure Software Development Framework (SSDF)](https://csrc.nist.gov/pubs/sp/800/218/final).

### Zero Trust
- [NIST SP 800-207 — Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final).

### Secure by Design / Default
- [CISA — Secure by Design](https://www.cisa.gov/securebydesign).
- [ENISA — Secure by Design and Default Playbook (2026)](https://www.enisa.europa.eu/publications/enisa-secure-by-design-and-default-playbook).
- [OWASP Secure by Design Framework](https://owasp.org/projects/secure-by-design-framework) (OWASP incubator project, not a certification).

### Application security
- [OWASP Top 10:2025](https://top10.owasp.org/2025/).
- [OWASP Application Security Verification Standard (ASVS) 5.0](https://asvs.owasp.org/).
- [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org/model/).

### AI / LLM security
- [OWASP Top 10 for LLM Applications:2025](https://genai.owasp.org/llm-top-10/).
- [OWASP Top 10 for Agentic Applications:2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).
- [MITRE ATLAS](https://atlas.mitre.org/).

### Adversarial threat intelligence
- [MITRE ATT&CK](https://attack.mitre.org/) · [MITRE ATLAS](https://atlas.mitre.org/).

**Primary foundation (5):** NIST CSF 2.0 · NIST SP 800-207 (Zero Trust) · OWASP ASVS 5.0 ·
OWASP LLM Top 10 + MITRE ATLAS · CISA/ENISA Secure by Design/Default.
**Complementary:** MITRE ATT&CK · NIST SSDF · OWASP SAMM.

---

## 2. NIST CSF 2.0 — function mapping (high level)

| CSF function | Serrier linkage | Status |
|---|---|---|
| **Govern** | Org policy, three failure modes, UNKNOWN discipline, four-state contract | Implemented (local/per-org); org-wide governance = Planned |
| **Identify** | Scanners (secrets, deps, insecure code), findings, correlation | Implemented |
| **Protect** | Pre-Send Guardian (block/redact), API-key auth, RBAC, redaction, allowlist | Implemented (Guardian); secure *defaults* Pending review |
| **Detect** | Detection engines, transparent risk model, cross-detector correlation | Implemented |
| **Respond** | Block, remediation (propose→approve), rotation-for-secrets | Implemented |
| **Recover** | Regression tracking, rescan, auto-verification of remediation | Implemented |

Serrier implements *parts of these outcomes for AI-development workflows* — not CSF for a whole
organization.

---

## 3. Zero Trust (NIST SP 800-207) — principle mapping

| ZT principle | Serrier application | Evidence | Status |
|---|---|---|---|
| Verify explicitly | Proxy requires a token (constant-time compare); API keys hashed | `guardian/proxy.py`, `auth.py`; `test_guardian_proxy.py`, `test_auth.py` | Implemented |
| Least privilege | RBAC (viewer<member<owner); per-project/workspace confinement | `auth.py`, `api/app.py`; `test_auth.py` / workspace: Pending review | Partially |
| Resource-centric / minimize implicit trust | Strict upstream allowlist; per-org policy; no wildcard | `guardian/proxy.py`; `test_guardian_proxy.py` | Implemented |
| No trust by network location | Proxy bound to loopback; validating TLS client upstream; no MITM | `guardian/proxy.py` · compose loopback bind: Pending review | Partially |
| Assume breach | Found secret treated as compromised → rotation; UNKNOWN never "safe" | `remediation.py`, `guardian/policy.py` | Implemented |
| Continuous evaluation | Every request re-inspected; regression re-opens verified findings | `guardian/inspect.py`, `db/store.py` | Implemented |

**Bounding statement:** a local proxy with a token implements *some* Zero Trust principles;
it is **not** a full Zero Trust Architecture (which requires identity-, device- and
resource-based access control across an environment). Stated, not implied.

---

## 4. Control-level matrix (the part a CISO can follow to a test)

Each row: framework + reference → Serrier control → evidence → status. Bounded; no over-claim.

| Framework ref | Serrier control | Evidence (test / file) | Status |
|---|---|---|---|
| **ASVS V2 Authentication** | API keys: sha256-hashed, never stored raw, constant-time compare; proxy loopback token | `auth.py`, `guardian/proxy.py`; `test_auth.py`, `test_guardian_proxy.py` | Implemented |
| **ASVS V4 Access Control** | Org/tenant isolation; cross-tenant → 404 (no existence leak); RBAC per endpoint | `db/store.py`, `api/app.py`; `test_auth.py` (`test_cross_tenant_ger_404`) | Implemented |
| **ASVS V5 Validation** | argv (no shell); scan path confinement; query inspected; streaming body limit | scanners, `guardian/proxy.py`; `test_guardian_proxy.py` · workspace/body-limit: Pending review | Partially |
| **ASVS V7 Cryptography** | No plaintext secrets; sha256 for keys/dedup; crypto-shred pattern for evidence-at-rest (design) | `auth.py`, `core/findings.py`, SECURITY.md | Partially (shred reused from selvra, not yet wired here) |
| **ASVS V8 Data Protection** | Redaction at detection; raw secret never in logs/audit/persistence/response | `core/findings.py`, `guardian/proxy.py`; `test_guardian_inspect.py`, `test_security_verification.py` (G) | Implemented |
| **ASVS V9 Logging** | Append-only audit; redacted-only; bounded retention (deque) | `db/store.py`, `guardian/proxy.py`; audit-cap: Pending review | Partially |
| **OWASP Top10 A01 Broken Access Control** | RBAC + tenant isolation + path confinement | `test_auth.py` · confinement: Pending review | Partially |
| **A02 Security Misconfiguration** | Secure defaults: no default password, loopback bind, auth required, refuse-start | compose, `api/app.py` (`krav_sakra_konfig`); `test_security_fixes.py` (F1) | Pending review |
| **A03 Software Supply Chain** | osv-scanner for deps; pinned `uv`; scanner-binary checksum mechanism | `scanners/osv_adapter.py`, Dockerfile | Partially (real SHA256 values pending release) |
| **A04 Cryptographic Failures** | No secrets in plaintext; verifying TLS client; no MITM | `auth.py`, `guardian/proxy.py` | Implemented |
| **A09 Logging/Alerting Failures** | Audit of scans/approvals/policy changes; secret-safe | `db/store.py` | Partially (no alerting pipeline) |
| **A10 Mishandling Exceptional Conditions** | UNKNOWN as a first-class state; fail-closed per policy | `guardian/policy.py`; `test_guardian_policy.py`, `test_guardian_inspect.py` | Implemented |
| **NIST SSDF (PW/PS/RV)** | argv build, pinned deps, 174-test suite, dep scanning, red-team brief | repo-wide; `docs/security/red-team-brief.md` | Partially |
| **OWASP LLM02 Sensitive Info Disclosure** | Pre-Send Guardian blocks/redacts secrets & PII before provider | `guardian/*`; `test_guardian_proxy.py` (leak-through = 0) | Partially (recall < 100%, documented limits) |
| **OWASP LLM01 Prompt Injection** | Untrusted input (files/evidence) never becomes instructions; analyst trust boundary | `analyst.py`, ARCHITECTURE §trust boundary | Partially |
| **OWASP LLM03 Supply Chain (models/deps)** | Dependency vuln scanning (osv); build pinning | `scanners/osv_adapter.py` | Partially |
| **OWASP LLM05 Improper Output Handling** | Response content is **not** inspected (streaming relayed only) | 0002 §streaming | Not covered |
| **OWASP LLM06 Excessive Agency** | Agent tool/permission control | — | Planned (Gen 3, design 0003) |
| **MITRE ATT&CK TA0010 Exfiltration** | Guardian blocks secret exfiltration via the AI-API channel | `guardian/proxy.py`; red-team brief | Partially (one channel; others out of scope) |
| **MITRE ATT&CK TA0006 Credential Access** | Secret/credential detection + block | `core/textdetect.py`, `guardian/classify.py` | Partially |
| **MITRE ATLAS (AI exfiltration / sensitive-info disclosure)** | Prevent sensitive data leaving to inference APIs | `guardian/*` | Partially |
| **CISA / ENISA Secure by Default** | "Security is built into default behavior, not left to customer configuration" | compose + `krav_sakra_konfig`; `test_security_fixes.py` (F1) | Pending review |
| **OWASP SAMM** | Verification (reproducible tests), red-team brief, remediation-verification report | `docs/security/*` | Partially (practice exists, not formally assessed) |

---

## 5. Scope and limitations

Framework references are **not** evidence that every requirement is implemented. Serrier
separately documents:

- **Implemented and tested** capabilities (this matrix + the test suite).
- **Known coverage limits** — [`red-team-brief.md`](red-team-brief.md) and design docs
  [`0002`](../design/0002-guardian-proxy-adapter.md)/[`0003`](../design/0003-security-runtime-vision.md);
  the remediation-verification report lives on the `security-remediation` branch (tag
  `review-remediation-2026-11-09`).
- **Planned** capabilities (Gen 2–4, gated in [`0003`](../design/0003-security-runtime-vision.md)).
- **Evidence** supporting each claim (named tests).

Security claims remain **bounded by demonstrated enforcement coverage and independently
verifiable test results.** Where a control is `Pending review`, it is built and tested on the
frozen `security-remediation` branch but must survive external review before it is claimed as
production-ready. 174 passing synthetic tests are not proof of resistance to a motivated
attacker — that is what the external review is for.
