# PSV Linux Security Auditor - Threat Model & Trust Boundaries

## 1. System Overview & Trust Boundaries

```text
[ Browser / Operator ]
        │
        ▼ (HTTPS / WSS - JWT Bearer Auth)
[ Reverse Proxy / API Gateway ]
        │
        ▼ (Strict Host Headers / Rate Limiting)
[ FastAPI Control Plane ]
        ├── PostgreSQL (Parameterized async queries)
        ├── RabbitMQ AMQP Broker (Encrypted / Isolated VHost)
        └── Background Assessment Worker
                │
                ▼ (SSH - Key Auth / Known Hosts / Registered Commands)
        [ Target Linux Host ]
```

### Trust Boundary Definitions:
1. **Browser / Web Console -> API Control Plane**: Untrusted -> Authenticated. All inputs validated with Pydantic schemas.
2. **API Control Plane -> Message Broker -> Worker**: Internal trusted messaging bus with isolated task queues.
3. **Assessment Worker -> Audited Linux Target**: Untrusted remote host boundary. Output from target is treated as potentially adversarial.

---

## 2. Threat Analysis Matrix

| Asset | Threat Scenario | Potential Impact | Implemented Mitigation | Residual Risk |
| :--- | :--- | :--- | :--- | :--- |
| **SSH Private Keys & Passwords** | Target credential theft via logs or API responses | Unauthorized remote host access | Stored in `CredentialReference` abstraction; stripped from all API outputs; redacted from logs | Physical memory dump of worker process |
| **Target Host Command Execution** | Remote command injection via target parameters or collector fields | Arbitrary command execution on audited host | Predefined immutable `SafeCommand` registry; strict argument arrays; no shell interpolation | Compromise of audited host's existing binaries |
| **Control Plane Network Infrastructure** | SSRF attack via malicious host registration | Scanning of cloud metadata (169.254.169.254) or localhost control plane | `validate_network_target` blocks link-local, cloud metadata, and loopback in production | Intentionally registered internal jump hosts |
| **Audit Reports & Evidence** | Stored XSS via malicious Linux hostnames or process banners | Admin session hijacking in web console | HTML entity escaping on all report fields; React JSX DOM auto-escaping; strict CSP | Out-of-band export to unescaped 3rd party tools |
| **Benchmark Security Rules** | Malicious rule injection via YAML | Code execution in evaluation engine | Safe YAML loader (`yaml.safe_load`); schema verification in `validate_rules.py`; no `eval()` | Modification of rules directory on disk |
| **Auditor Control Plane Database** | SQL Injection via search filters or IDs | Data leakage / privilege escalation | SQLAlchemy ORM parameterized queries; no string concatenated SQL | Zero-day vulnerability in database driver |
| **Auditor Service Daemon** | Container breakout / privilege escalation on control plane | Host system compromise | Unprivileged service accounts (`psv:psv`), systemd sandboxing (`ProtectSystem=strict`, `NoNewPrivileges=true`) | Kernel zero-day local privilege escalation |
| **Remediation Commands** | Operator lockout via incorrect SSH or firewall rules | Loss of management connectivity to audited server | SSH syntax check (`sshd -t`); explicit `ufw allow 22/tcp` before enable; rollback scripts | Target server kernel panic during sysctl apply |

---

## 3. Threat Handling for Adversarial Linux Targets

When auditing a compromised or hostile Linux target:
- **Malicious Output**: Terminal escape sequences and binary characters are truncated and sanitized.
- **Output Bombing / Exhaustion**: SSH command outputs are strictly capped at 1MB per command.
- **Hang / Tarpit**: Strict 15s connection timeouts and 30s command timeouts terminate hanging SSH sessions.
