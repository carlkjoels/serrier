# Security Framework Alignment

Serrier's architecture and engineering practices are **informed by** and **implement selected
controls from** established cybersecurity frameworks, application-security standards, and
adversarial threat knowledge bases. These give a shared vocabulary for threat modeling,
architecture, verification, and improvement.

> **Framework alignment does not imply certification, accreditation, or full compliance.**
> Each mapping is bounded to the controls **implemented and test-verified** in the relevant
> Serrier release. Named frameworks are a design compass and a shared language — not a claim
> that every requirement or technique is covered. Language used here is deliberate: *mapped to*,
> *informed by*, *implements selected controls from*, *partially addresses* — never *compliant*
> or *certified*.

## Identifier verification provenance (read this before trusting an ID)

Every framework identifier below was checked against its **official source domain**
(`csrc.nist.gov`/`nvlpubs.nist.gov`, `github.com/OWASP/ASVS`, `owasp.org`, `genai.owasp.org`,
`attack.mitre.org`, `atlas.mitre.org`) in Nov 2026. Verification was by search against those
domains; direct raw-spec fetch was not available in the build environment. Consequence,
stated honestly:

- **NIST CSF 2.0, SP 800-207, MITRE ATT&CK/ATLAS, OWASP Top 10:2025 and LLM Top 10:2025** —
  identifiers **and** titles were confirmed (verbatim where shown).
- **OWASP ASVS 5.0.0** — the **chapter structure** (17 chapters, renumbered from 4.0) is
  verified; individual **requirement-level IDs (VX.Y.Z) are NOT individually verified**, so we
  map at **chapter level** and do not assert specific sub-IDs. (The prior version of this file
  used ASVS 4.0 chapter numbers — corrected below.)
- **NIST SSDF (SP 800-218)** — practice IDs `PW.4`, `PS.1`, `RV.1` confirmed verbatim; other
  practice titles are the known SSDF 1.1 headings but were not line-verified, and are marked.

Where a specific identifier could not be confirmed, it is **omitted rather than invented.**

**Status legend — two independent dimensions** (same as the verification matrix):
*Implementation* = `Implemented` · `Partially` · `Planned` · `Not covered` · `Not applicable`.
*Verification* = `Independently verified` · `Automated-test verified` · `Manually tested` ·
`Not verified`. Nothing on this branch is `Independently verified` yet — that is the pending
external review. Rows cite the verification-matrix ID (e.g. `AUTH-2`) so each maps to a test.

---

## 1. Frameworks referenced

**Primary foundation (5):** NIST CSF 2.0 · NIST SP 800-207 (Zero Trust) · OWASP ASVS 5.0.0 ·
OWASP LLM Top 10:2025 + MITRE ATLAS · CISA/ENISA Secure by Design/Default.
**Complementary:** MITRE ATT&CK · NIST SSDF (SP 800-218) · OWASP SAMM · OWASP Top 10:2025.

- NIST CSF 2.0 — https://www.nist.gov/cyberframework (CSWP 29).
- NIST SP 800-207 Zero Trust Architecture — https://csrc.nist.gov/pubs/sp/800/207/final.
- NIST SP 800-218 SSDF 1.1 — https://csrc.nist.gov/pubs/sp/800/218/final.
- OWASP ASVS 5.0.0 — https://github.com/OWASP/ASVS (5.0.0, May 2025).
- OWASP Top 10:2025 — https://owasp.org/Top10/2025/.
- OWASP Top 10 for LLM Applications 2025 — https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/.
- OWASP SAMM — https://owaspsamm.org/model/.
- MITRE ATT&CK — https://attack.mitre.org/ · MITRE ATLAS — https://atlas.mitre.org/.
- CISA Secure by Design — https://www.cisa.gov/securebydesign · ENISA Secure by Design/Default.

---

## 2. NIST CSF 2.0 — subcategory mapping (verified IDs)

Subcategory IDs and text verified against CSF 2.0 (CSWP 29). CSF numbering is intentionally
sparse (e.g. `PR.DS` skips 03–09) — not an error.

| CSF 2.0 subcategory (verbatim) | Serrier linkage | Matrix | Impl / Verification |
|---|---|---|---|
| **PR.AA-01** Identities and credentials … are managed | API-key lifecycle, sha256 at rest | AUTH-2 | Implemented / Automated-test |
| **PR.AA-03** Users, services, and hardware are authenticated | API-key auth + proxy loopback token | AUTH-1, AUTH-4 | Implemented / Automated-test |
| **PR.AA-05** Access permissions … least privilege and separation of duties | RBAC viewer<member<owner; detection≠interpretation | AUTH-3 | Implemented / Automated-test |
| **PR.DS-01** Confidentiality/integrity/availability of data-at-rest | Redacted+hashed storage; no plaintext secrets | LEAK-2, SEC-3 | Implemented / Automated-test |
| **PR.DS-02** … data-in-transit | Verifying TLS to upstream; no MITM; loopback bind | NET-1, CFG-3 | Partially / Automated-test |
| **DE.CM-01** Networks and network services are monitored … | Guardian inspects outbound AI-API traffic | LEAK-1, INS-1 | Partially / Automated-test |
| **DE.CM-09** Computing hardware and software, runtime environments … monitored | Scanners (secrets/deps/insecure code) | PATH-5, SUP-3 | Implemented / Automated-test |
| **GV.PO-01/02** Policy for managing cybersecurity risks is established … enforced | Per-org policy, 3 failure modes, UNKNOWN discipline | POL-1..4 | Implemented (local/per-org) / Automated-test |
| **GV.SC** (Cybersecurity Supply Chain Risk Management) | Pinned deps, checksum-verified scanners, osv scanning | SUP-1..3 | Partially / Automated-test |
| **PR.PS-01** Configuration management practices are established and applied | Secure defaults, refuse-insecure-start | CFG-1..4 | Implemented / Automated-test |
| **PR.PS-04** Log records are generated and made available … | Redacted audit, bounded retention | SEC-2, SEC-3 | Partially / Automated-test |
| **PR.PS-06** Secure software development practices are integrated … | argv-not-shell, 216-test suite, red-team brief | SUP-2 | Partially / Automated-test |

Serrier implements *parts of these outcomes for AI-development workflows* — not CSF for a whole
organization. `Govern`/`Recover` are mostly out of a local tool's scope.

---

## 3. Zero Trust (NIST SP 800-207) — principle mapping

Component terms and the seven tenets verified against SP 800-207.

| ZT tenet / component | Serrier application | Matrix | Impl / Verification |
|---|---|---|---|
| **Tenet 2** "All communication is secured regardless of network location" | Loopback token + Host-allowlist; no trust by network position | AUTH-4, NET-3 | Partially / Automated-test |
| **Tenet 6** "All resource authentication and authorization are dynamic and strictly enforced before access" | Every request re-inspected; token + policy before forward | POL-1, LEAK-1 | Implemented / Automated-test |
| **Tenet 4** "Access … determined by dynamic policy" | Per-org failure mode + policy; strictest-wins | POL-3 | Implemented / Automated-test |
| **Least privilege / minimize implicit trust** | RBAC; strict upstream allowlist (no wildcard); workspace confinement | AUTH-3, NET-4, PATH-1 | Partially / Automated-test |
| **Assume breach** | Found secret = compromised → rotation; UNKNOWN never "safe" | POL-1 | Implemented / Automated-test |

Serrier's proxy is a **Policy Enforcement Point (PEP)** in 800-207 terms; the policy engine
(`guardian/policy.py`) is a local **PDP** (PE+PA) for the AI-API channel. **Bounding
statement:** a local PEP with a token implements *some* Zero Trust tenets; it is **not** a full
Zero Trust Architecture (no enterprise-wide identity-, device- and resource-based access
control). Stated, not implied.

---

## 4. OWASP ASVS 5.0.0 — chapter-level mapping (verified structure)

Mapped at **chapter level** (5.0.0 renumbered chapters, verified). Requirement-level IDs are
**not individually asserted** here — see provenance note.

| ASVS 5.0.0 chapter | Serrier control | Matrix | Impl / Verification |
|---|---|---|---|
| **V6 Authentication** | API keys sha256-hashed, constant-time; proxy token | AUTH-1,2,4 | Implemented / Automated-test |
| **V8 Authorization** | RBAC per endpoint; tenant isolation (404, no existence leak) | AUTH-3, TEN-1,2 | Implemented / Automated-test |
| **V2 Validation and Business Logic** | argv-not-shell; query inspection; schema-validated input | INS-1,2 | Partially / Automated-test |
| **V5 File Handling** | Workspace confinement, canonical+symlink-aware; size/vendor skips | PATH-1..5 | Implemented / Automated-test |
| **V4 API and Web Service** | Streaming body limit; strict upstream allowlist; SSRF guard | REQ-1..4, NET-1,4 | Implemented / Automated-test |
| **V11 Cryptography** | No plaintext secrets; sha256 keys/dedup; crypto-shred (design) | AUTH-2, LEAK-2 | Partially / Automated-test |
| **V12 Secure Communication** | Verifying TLS to upstream; IP-pinning (DNS-rebind); no MITM | NET-1,2 | Implemented / Automated-test |
| **V13 Configuration** | Secure defaults; refuse-insecure-start; loopback bind | CFG-1..4 | Implemented / Automated-test |
| **V14 Data Protection** | Redaction at detection; raw secret never in logs/audit/response | LEAK-1,2, SEC-1,3 | Implemented / Automated-test |
| **V16 Security Logging and Error Handling** | Redacted-only audit; bounded ring buffer; fail-closed on error | SEC-2,3, NET-5, POL-4 | Partially / Automated-test |

---

## 5. OWASP Top 10:2025 (web) — verified IDs

| ID (verbatim title) | Serrier control | Matrix | Impl / Verification |
|---|---|---|---|
| **A01:2025** Broken Access Control | RBAC + tenant isolation + path confinement | AUTH-3, TEN-1, PATH-1 | Partially / Automated-test |
| **A02:2025** Security Misconfiguration | Secure defaults, no default password, refuse-insecure-start | CFG-1..4 | Implemented / Automated-test |
| **A03:2025** Software Supply Chain Failures | Pinned `uv`/semgrep, checksum-verified scanners, osv scan | SUP-1..3 | Partially / Automated-test |
| **A04:2025** Cryptographic Failures | No plaintext secrets; verifying TLS; no MITM | AUTH-2, NET-1 | Implemented / Automated-test |
| **A05:2025** Injection | argv-not-shell across scanners; untrusted content never executed | — (scanner tests) | Implemented / Automated-test |
| **A09:2025** Security Logging and Alerting Failures | Redacted, bounded audit (no alerting pipeline yet) | SEC-2,3 | Partially / Automated-test |
| **A10:2025** Mishandling of Exceptional Conditions | UNKNOWN first-class; fail-closed per policy | POL-1,4 | Implemented / Automated-test |

---

## 6. AI/LLM — OWASP LLM Top 10:2025 + MITRE ATLAS (verified IDs)

| ID (verbatim) | Serrier control | Matrix | Impl / Verification |
|---|---|---|---|
| **LLM02:2025** Sensitive Information Disclosure | Pre-Send Guardian blocks/redacts secrets & PII before provider | LEAK-1, INS-1,3 | Partially / Automated-test (recall <100%, documented) |
| **LLM01:2025** Prompt Injection | Untrusted files/evidence never become instructions (analyst trust boundary) | — (analyst design) | Partially / Not verified |
| **LLM03:2025** Supply Chain | osv dependency scanning; build pinning | SUP-3 | Partially / Automated-test |
| **LLM05:2025** Improper Output Handling | Response content **not** inspected (stream relayed only) | LEAK-5 | Not covered / Not verified (deliberate boundary) |
| **LLM06:2025** Excessive Agency | Agent tool/permission control | — | Planned (Gen 3) / Not verified |
| **LLM10:2025** Unbounded Consumption | Streaming body limit; scanner CPU/file rlimits | REQ-1..4, ISO-1 | Partially / Automated-test |
| **MITRE ATLAS AML.T0057** LLM Data Leakage | Prevent sensitive data leaving to inference APIs | LEAK-1 | Partially / Automated-test (one channel) |
| **MITRE ATLAS AML.T0024** Exfiltration via AI Inference API | Guardian is the enforcement point on that channel | LEAK-1 | Partially / Automated-test |

---

## 7. Adversarial — MITRE ATT&CK (verified technique IDs)

| Technique (verbatim) | Serrier control | Matrix | Impl / Verification |
|---|---|---|---|
| **T1041** Exfiltration Over C2 Channel | Guardian blocks secret exfiltration over the AI-API channel | LEAK-1 | Partially / Automated-test (one channel; others out of scope) |
| **T1567.001** Exfiltration to Code Repository | Scanner flags secrets in source before they reach a repo | PATH-5, SUP-3 | Partially / Automated-test |
| **T1552.001** Unsecured Credentials: Credentials In Files | Secret detection in code/config files | PATH-5 | Implemented / Automated-test |

**Bounding statement:** Serrier covers **one** exfiltration channel (explicit loopback-routed
AI-API traffic). MCP, arbitrary outbound HTTP, and DNS-level egress are **not** inspected — the
same coverage ceiling as the largest incumbent gateway (see design 0004 §2, red-team brief).

---

## 8. Secure by Design/Default & SSDF

| Reference | Serrier control | Matrix | Impl / Verification |
|---|---|---|---|
| **CISA/ENISA Secure by Default** — "security built into default behavior, not left to customer configuration" | Loopback bind, no default password, auth required, refuse-insecure-start | CFG-1..4 | Implemented / Automated-test |
| **SSDF PW.4** Reuse Existing, Well-Secured Software … | Vetted scanners (gitleaks/semgrep/osv), pinned + checksum-verified | SUP-1,2 | Partially / Automated-test |
| **SSDF PS.1** Protect All Forms of Code from Unauthorized Access and Tampering | Checksum verification; `.gitignore` excludes secrets; token 0600 | SUP-1,4, SEC-1 | Partially / Automated-test |
| **SSDF RV.1** Identify and Confirm Vulnerabilities on an Ongoing Basis | osv dependency scanning; regression tracking | SUP-3 | Partially / Automated-test |
| SSDF secure-coding / build (PW.5/PW.6 — titles not line-verified) | argv-not-shell; `uv.lock --frozen` reproducible build | SUP-2 | Partially / Automated-test |

**Agentic (OWASP ASI01–ASI10:2026)** is referenced for **future** generations (agent behavior,
Gen 3) and is **Planned / Not covered** today — not claimed.

---

## 9. Scope and limitations

Framework references are **not** evidence that every requirement is implemented. Serrier
separately documents:

- **Implemented and tested** capabilities — [`security-verification-matrix.md`](security-verification-matrix.md) + the 216-test suite.
- **Known coverage limits** — [`security-limitations.md`](security-limitations.md), [`red-team-brief.md`](red-team-brief.md), design [`0002`](../design/0002-guardian-proxy-adapter.md)/[`0004`](../design/0004-always-on-runtime.md).
- **Planned** capabilities — [`0003`](../design/0003-security-runtime-vision.md) (Gen 2–4, gated).
- **Threat model** — [`threat-model.md`](threat-model.md); **architecture** — [`security-architecture.md`](security-architecture.md).

Security claims are **bounded by demonstrated enforcement coverage and reproducible test
results.** 216 passing synthetic tests are not proof of resistance to a motivated attacker —
that is what independent review is for. No row above is `Independently verified` yet.
