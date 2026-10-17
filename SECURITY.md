# Security Policy & Responsible Use Guidelines

## 1. Legal Disclaimer & Ethical Use

**Hunt_Chain** is engineered exclusively for **authorized security testing**, educational research, and legitimate bug bounty program participation where explicit, prior authorization has been granted by the target organization.

- **Explicit Authorization Required**: Never run Hunt_Chain against any system, network, host, domain, or API without verified permission. Unauthorized scanning, testing, or exploitation of computer systems is illegal under cybercrime laws globally (including the US Computer Fraud and Abuse Act, UK Computer Misuse Act, and equivalent international legislation).
- **Scope Enforcement**: The pipeline includes **ScopeGuard (Stage 1)** as a mandatory zero-trust gate. Do not bypass or disable target authorization checks.
- **Liability**: The authors and maintainers of Hunt_Chain assume no liability and are not responsible for any misuse, unauthorized activity, service degradation, or damage caused by this software.

---

## 2. Safe Validation Guarantees

Hunt_Chain enforces strict architectural boundaries to avoid unintended collateral impact:
- **Non-Destructive Payloads**: Validation and exploitation probes (Stage 4) are designed to verify vulnerabilities using non-destructive tokens (e.g., cryptographic canaries, mathematical operations, status indicators) without altering persistent database records, corrupting state, or executing destructive OS commands.
- **Fail-Loud Secret Redaction**: Before writing findings to disk (Stage 5), reports are scanned by an automated redaction safety net to prevent sensitive live credentials, session tokens, or customer PII from leaking into submissions.

---

## 3. Reporting a Vulnerability in Hunt_Chain

If you discover a security vulnerability within Hunt_Chain itself (e.g., unintended bypasses in ScopeGuard, insecure temporary file handling, or unsafe command execution), please report it responsibly:

1. **GitHub Private Security Advisory**: Use the [GitHub Security Advisory reporting tab](https://github.com/Atharva-g19/Hunt_Chain/security/advisories/new) to submit a confidential report.
2. **Details to Include**:
   - Component affected (Stage 1 ScopeGuard, Stage 2 Recon, Stage 3 Tester Family, Stage 4 Validation, Stage 5 Reporting, or Core Orchestrator).
   - Clear description and steps to reproduce.
   - Proof of Concept (PoC) or suggested fix.
3. **Response Timeline**:
   - Maintainers will acknowledge receipt within 48 hours.
   - We will collaborate with you to evaluate impact and draft a patch before public disclosure.

---

## 4. Supported Versions

| Version | Supported | Notes |
|:---|:---:|:---|
| `0.1.x` / `main` | :white_check_mark: | Actively supported and patched |
| Older releases | :x: | Please upgrade to the latest commit on `main` |
