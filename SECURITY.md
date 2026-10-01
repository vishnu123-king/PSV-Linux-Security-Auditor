# Security Policy & Vulnerability Disclosure

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

The PSV Linux Security Auditor project takes the security of our software and its deployment seriously.

If you discover a security vulnerability in this project, please follow these guidelines:

1. **Do NOT open a public GitHub issue.**
2. Send a detailed report to the security team at `security-disclosure@psv-auditor.local` (or your organization's primary SOC security contact).
3. Include:
   - Vulnerability classification (e.g. IDOR, Authentication Bypass, Command Injection, Privilege Escalation)
   - Step-by-step reproduction instructions or proof-of-concept
   - Affected collector, API endpoint, or component
   - Proposed mitigation or patch if available

## Response SLAs
- **Initial Acknowledgment**: Within 24 hours.
- **Triage & Severity Rating**: Within 72 hours.
- **Remediation Release**: Critical vulnerabilities patched within 7 business days.

## Security Architecture & Invariants
- **Immutable Safe Command Registry**: Only static predefined command tokens are executable against remote Linux targets.
- **Fail-Closed Evaluation**: Unavailable or failing collectors strictly evaluate to `UNKNOWN` and never `PASS`.
- **Approval-Gated Remediation**: No automated changes occur without explicit administrator sign-off.
- **Multi-Tenant Scoping**: All target hosts, assessments, findings, and remediations are strictly scoped to the authenticated organization.
