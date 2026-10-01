# PSV Linux Security Auditor - Architecture Specification

## Overview

PSV Linux Security Auditor is a production-grade, agentless Linux security auditing and configuration compliance system. It employs an automated collector pipeline, a YAML-based deterministic rule engine, and safe, approval-gated remediation workflows.

```text
               ┌───────────────────────┐
               │  Web Console (React)  │
               └───────────┬───────────┘
                           │
                     REST / WebSocket
                           │
                           ▼
               ┌───────────────────────┐
               │    FastAPI Backend    │◄─── psv CLI (Typer)
               │     Control Plane     │
               └───────────┬───────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
         Host Svc     Assess Svc    Finding Svc
                           │
                           ▼
                    RabbitMQ Broker
              (with memory queue fallback)
                           │
                           ▼
               ┌───────────────────────┐
               │   Assessment Worker   │
               └───────────┬───────────┘
                           │
                      SSH (AsyncSSH)
                           │
                           ▼
              ┌─────────────────────────┐
              │  Authorized Linux Host  │
              └────────────┬────────────┘
                           │
                   Safe Collector Set
                           │
                           ▼
                      Observations
                           │
                           ▼
                      Rule Engine
                           │
                           ▼
                   PostgreSQL / SQLite
```

## Security Pipeline Stages

1. **Connect**: Authenticates via AsyncSSH using verified host keys and SSH private keys.
2. **Discover**: Gathers system release, kernel, architecture, and virtualization facts.
3. **Collect**: Executes immutable, predefined commands and reads system configs through 12 modular collectors.
4. **Normalize**: Transforms raw command stdout and configuration files into standardized `Observation` records.
5. **Evaluate**: Tests observations against external YAML security benchmark rules using deterministic operators (`equals`, `contains`, `regex`, etc.).
6. **Generate Findings**: Produces structured findings with severity categorization (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
7. **Store Evidence**: Retains verbatim command output and file snippets linked directly to findings.
8. **Report**: Synthesizes formal compliance reports in JSON and printable HTML.
9. **Remediation Plan**: Synthesizes dry-run diffs, rollback instructions, and required commands without executing.
10. **Approval Gate**: Demands explicit operator sign-off (`APPROVED`) prior to modification.
11. **Remediate**: Creates backup configuration and applies hardening commands.
12. **Verify**: Specifically re-evaluates the affected control on the host to confirm resolution.
