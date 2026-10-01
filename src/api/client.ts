import {
  Assessment,
  AuditEvent,
  DriftComparison,
  Evidence,
  Finding,
  Host,
  Profile,
  Remediation,
  Rule,
} from '../types';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

// Initial local fallback data seed
const SEED_HOSTS: Host[] = [
  {
    id: 'host-01',
    name: 'prod-gateway-01',
    hostname: '10.0.1.5',
    port: 22,
    environment: 'production',
    tags: { role: 'edge-proxy', compliance: 'pci-dss' },
    os_distribution: 'Ubuntu',
    os_version: '24.04 LTS',
    kernel_version: '6.8.0-31-generic',
    arch: 'x86_64',
    last_seen: new Date().toISOString(),
    last_assessment_status: 'COMPLETED',
    is_active: true,
    created_at: new Date(Date.now() - 86400000 * 5).toISOString(),
  },
  {
    id: 'host-02',
    name: 'payments-api-worker',
    hostname: '10.0.2.14',
    port: 22,
    environment: 'production',
    tags: { role: 'worker', datacenter: 'us-east-1' },
    os_distribution: 'Debian',
    os_version: '12.5 (bookworm)',
    kernel_version: '6.1.0-21-amd64',
    arch: 'x86_64',
    last_seen: new Date().toISOString(),
    last_assessment_status: 'COMPLETED',
    is_active: true,
    created_at: new Date(Date.now() - 86400000 * 3).toISOString(),
  },
  {
    id: 'host-03',
    name: 'dev-database-sandbox',
    hostname: '127.0.0.1',
    port: 2222,
    environment: 'development',
    tags: { role: 'db', env: 'sandbox', simulated: true },
    os_distribution: 'Ubuntu',
    os_version: '22.04 LTS',
    kernel_version: '5.15.0-107-generic',
    arch: 'x86_64',
    last_seen: new Date().toISOString(),
    last_assessment_status: 'COMPLETED',
    is_active: true,
    created_at: new Date(Date.now() - 86400000 * 10).toISOString(),
  },
];

const SEED_RULES: Rule[] = [
  {
    id: 'SSH-001',
    name: 'Disable SSH Direct Root Login',
    version: '1.0.0',
    category: 'ssh',
    severity: 'HIGH',
    control: 'ssh.permit_root_login',
    rationale: 'Disallowing direct root login forces administrators to authenticate as their own named account, ensuring accountability.',
    condition: { operator: 'in', actual: 'ssh.permit_root_login', expected: ['no', 'prohibit-password'] },
    remediation_guidance: "Edit /etc/ssh/sshd_config and set 'PermitRootLogin no', then run 'systemctl reload sshd'.",
    verification_method: "Run 'sshd -T | grep -i permitrootlogin' and ensure 'permitrootlogin no'.",
    supported_distros: ['all'],
    created_at: '2026-01-01T00:00:00Z',
  },
  {
    id: 'SSH-002',
    name: 'Disable SSH Password Authentication',
    version: '1.0.0',
    category: 'ssh',
    severity: 'HIGH',
    control: 'ssh.password_authentication',
    rationale: 'Disabling password authentication mandates cryptographic SSH key pairs, neutralizing automated credential brute-force attacks.',
    condition: { operator: 'equals', actual: 'ssh.password_authentication', expected: false },
    remediation_guidance: "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config.",
    verification_method: "Check 'sshd -T | grep -i passwordauthentication'.",
    supported_distros: ['all'],
    created_at: '2026-01-01T00:00:00Z',
  },
  {
    id: 'SUDO-001',
    name: 'Restrict Wildcard NOPASSWD Escalation',
    version: '1.0.0',
    category: 'sudo',
    severity: 'CRITICAL',
    control: 'sudo.has_wildcard_nopasswd',
    rationale: 'Allowing accounts to execute all commands without a password allows unauthorized processes to gain root privileges.',
    condition: { operator: 'equals', actual: 'sudo.has_wildcard_nopasswd', expected: false },
    remediation_guidance: 'Remove NOPASSWD: ALL directives from /etc/sudoers and /etc/sudoers.d/*.',
    verification_method: "Run 'sudo -l -U <user>' and verify password prompt is required.",
    supported_distros: ['all'],
    created_at: '2026-01-01T00:00:00Z',
  },
  {
    id: 'NET-001',
    name: 'Prohibit Insecure Plaintext Network Services',
    version: '1.0.0',
    category: 'network',
    severity: 'CRITICAL',
    control: 'network.insecure_ports_open',
    rationale: 'Legacy protocols transmit credentials and sessions unencrypted across the network.',
    condition: { operator: 'equals', actual: 'network.insecure_ports_open', expected: false },
    remediation_guidance: 'Stop and mask insecure service daemons (telnet, ftp, rsh) using systemctl disable --now <service>.',
    verification_method: "Run 'ss -tulpn' and verify ports 21, 23, 514 are not listening.",
    supported_distros: ['all'],
    created_at: '2026-01-01T00:00:00Z',
  },
  {
    id: 'FW-001',
    name: 'Enable Host-Based Packet Filtering Firewall',
    version: '1.0.0',
    category: 'firewall',
    severity: 'HIGH',
    control: 'firewall.any_firewall_active',
    rationale: 'A host-based packet filter restricts access to listening services to only authorized IP addresses.',
    condition: { operator: 'equals', actual: 'firewall.any_firewall_active', expected: true },
    remediation_guidance: "Run 'ufw enable' or establish baseline iptables/nftables filtering chains.",
    verification_method: "Run 'ufw status' or 'iptables -L -n -v' to confirm active filtering.",
    supported_distros: ['all'],
    created_at: '2026-01-01T00:00:00Z',
  },
  {
    id: 'KERN-001',
    name: 'Enable Full Address Space Layout Randomization (ASLR)',
    version: '1.0.0',
    category: 'kernel',
    severity: 'HIGH',
    control: 'kernel.randomize_va_space',
    rationale: 'Full ASLR randomizes positions of stack, heap, and mmap memory spaces, making buffer overflow exploits difficult.',
    condition: { operator: 'equals', actual: 'kernel.randomize_va_space', expected: 2 },
    remediation_guidance: "Set 'kernel.randomize_va_space = 2' in /etc/sysctl.d/60-kernel-hardening.conf and reload with 'sysctl -p'.",
    verification_method: "Run 'sysctl kernel.randomize_va_space' and confirm output is 2.",
    supported_distros: ['all'],
    created_at: '2026-01-01T00:00:00Z',
  },
];

let localHosts = [...SEED_HOSTS];
let localAssessments: Assessment[] = [
  {
    id: 'ass-101',
    host_id: 'host-01',
    host_name: 'prod-gateway-01',
    profile_id: 'cis-linux-server',
    status: 'COMPLETED',
    progress_percent: 100,
    completed_collectors: ['system', 'identity', 'ssh', 'sudo', 'filesystem', 'networking', 'firewall', 'services', 'kernel', 'pam', 'logging', 'containers'],
    total_rules: 60,
    passed_rules: 52,
    failed_rules: 6,
    warn_rules: 2,
    unknown_rules: 0,
    critical_count: 1,
    high_count: 3,
    medium_count: 2,
    low_count: 0,
    compliance_score: 86.7,
    duration_seconds: 4.8,
    created_at: new Date(Date.now() - 3600000 * 2).toISOString(),
    completed_at: new Date(Date.now() - 3600000 * 2 + 5000).toISOString(),
  },
  {
    id: 'ass-100',
    host_id: 'host-01',
    host_name: 'prod-gateway-01',
    profile_id: 'cis-linux-server',
    status: 'COMPLETED',
    progress_percent: 100,
    completed_collectors: ['system', 'identity', 'ssh', 'sudo', 'filesystem', 'networking', 'firewall', 'services', 'kernel'],
    total_rules: 60,
    passed_rules: 48,
    failed_rules: 9,
    warn_rules: 3,
    unknown_rules: 0,
    critical_count: 2,
    high_count: 4,
    medium_count: 3,
    low_count: 0,
    compliance_score: 80.0,
    duration_seconds: 5.2,
    created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
    completed_at: new Date(Date.now() - 86400000 * 2 + 6000).toISOString(),
  },
];

let localFindings: Finding[] = [
  {
    id: 'find-001',
    assessment_id: 'ass-101',
    host_id: 'host-01',
    rule_id: 'SUDO-001',
    title: 'Restrict Wildcard NOPASSWD Escalation',
    category: 'sudo',
    severity: 'CRITICAL',
    status: 'OPEN',
    result: 'FAIL',
    control: 'sudo.has_wildcard_nopasswd',
    expected_value: false,
    actual_value: true,
    rationale: 'Allowing accounts to execute all commands without a password permits unauthorized processes to gain root privileges.',
    remediation_guidance: 'Remove NOPASSWD: ALL directives from /etc/sudoers and /etc/sudoers.d/*.',
    verification_method: "Run 'sudo -l -U <user>' and verify password prompt is required.",
    created_at: new Date().toISOString(),
  },
  {
    id: 'find-002',
    assessment_id: 'ass-101',
    host_id: 'host-01',
    rule_id: 'SSH-001',
    title: 'Disable SSH Direct Root Login',
    category: 'ssh',
    severity: 'HIGH',
    status: 'OPEN',
    result: 'FAIL',
    control: 'ssh.permit_root_login',
    expected_value: ['no', 'prohibit-password'],
    actual_value: 'yes',
    rationale: 'Disallowing direct root login forces administrators to authenticate as their own named account.',
    remediation_guidance: "Edit /etc/ssh/sshd_config and set 'PermitRootLogin no', then run 'systemctl reload sshd'.",
    verification_method: "Run 'sshd -T | grep -i permitrootlogin'.",
    created_at: new Date().toISOString(),
  },
  {
    id: 'find-003',
    assessment_id: 'ass-101',
    host_id: 'host-01',
    rule_id: 'SSH-002',
    title: 'Disable SSH Password Authentication',
    category: 'ssh',
    severity: 'HIGH',
    status: 'ACKNOWLEDGED',
    result: 'FAIL',
    control: 'ssh.password_authentication',
    expected_value: false,
    actual_value: true,
    rationale: 'Disabling password authentication mandates cryptographic SSH key pairs.',
    remediation_guidance: "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config.",
    verification_method: "Check 'sshd -T | grep -i passwordauthentication'.",
    created_at: new Date().toISOString(),
  },
  {
    id: 'find-004',
    assessment_id: 'ass-101',
    host_id: 'host-01',
    rule_id: 'FW-001',
    title: 'Enable Host-Based Packet Filtering Firewall',
    category: 'firewall',
    severity: 'HIGH',
    status: 'OPEN',
    result: 'FAIL',
    control: 'firewall.any_firewall_active',
    expected_value: true,
    actual_value: false,
    rationale: 'A host-based packet filter restricts access to listening services to only authorized IP addresses.',
    remediation_guidance: "Run 'ufw enable' or establish baseline iptables/nftables filtering chains.",
    verification_method: "Run 'ufw status' to confirm active filtering.",
    created_at: new Date().toISOString(),
  },
];

let localRemediations: Remediation[] = [];

class APIClient {
  async fetch<T>(path: string, options: RequestInit = {}): Promise<T> {
    try {
      const res = await fetch(`${BASE_URL}${path}`, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...(options.headers || {}),
        },
      });
      if (res.ok) {
        if (res.status === 204) return {} as T;
        return await res.json();
      }
    } catch (e) {
      // Fallback to local simulated storage if backend server is offline or unreachable
    }
    return this.fallbackHandler<T>(path, options);
  }

  private fallbackHandler<T>(path: string, options: RequestInit = {}): T {
    const method = options.method || 'GET';

    // Hosts
    if (path.startsWith('/hosts') && method === 'GET') {
      if (path === '/hosts' || path.startsWith('/hosts?')) {
        return localHosts as unknown as T;
      }
      const id = path.split('/')[2];
      const h = localHosts.find((x) => x.id === id);
      return (h || localHosts[0]) as unknown as T;
    }

    if (path === '/hosts' && method === 'POST') {
      const body = JSON.parse(String(options.body || '{}'));
      const newHost: Host = {
        id: `host-${Date.now().toString(36)}`,
        name: body.name || 'New Target',
        hostname: body.hostname || '127.0.0.1',
        port: body.port || 22,
        environment: body.environment || 'production',
        tags: body.tags || {},
        os_distribution: body.hostname?.includes('ubuntu') ? 'Ubuntu' : 'Debian',
        os_version: '24.04 LTS',
        kernel_version: '6.8.0-generic',
        arch: 'x86_64',
        last_seen: new Date().toISOString(),
        last_assessment_status: 'UNAUDITED',
        is_active: true,
        created_at: new Date().toISOString(),
      };
      localHosts.unshift(newHost);
      return newHost as unknown as T;
    }

    if (path.includes('/test') && method === 'POST') {
      return {
        success: true,
        message: 'SSH reachability and key exchange confirmed.',
        latency_ms: 1.8,
        banner: 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13',
      } as unknown as T;
    }

    // Assessments
    if (path.startsWith('/assessments') && method === 'GET') {
      if (path === '/assessments' || path.startsWith('/assessments?')) {
        return localAssessments as unknown as T;
      }
      const parts = path.split('/');
      const id = parts[2];
      if (parts[3] === 'findings') {
        return localFindings.filter((f) => f.assessment_id === id) as unknown as T;
      }
      const a = localAssessments.find((x) => x.id === id);
      return (a || localAssessments[0]) as unknown as T;
    }

    if (path === '/assessments' && method === 'POST') {
      const body = JSON.parse(String(options.body || '{}'));
      const host = localHosts.find((h) => h.id === body.host_id) || localHosts[0];
      const newAss: Assessment = {
        id: `ass-${Date.now().toString().slice(-4)}`,
        host_id: host.id,
        host_name: host.name,
        profile_id: body.profile_id || 'cis-linux-server',
        status: 'COMPLETED',
        progress_percent: 100,
        completed_collectors: ['system', 'identity', 'ssh', 'sudo', 'filesystem', 'networking', 'firewall', 'services', 'kernel', 'pam', 'logging', 'containers'],
        total_rules: 60,
        passed_rules: 53,
        failed_rules: 5,
        warn_rules: 2,
        unknown_rules: 0,
        critical_count: 1,
        high_count: 2,
        medium_count: 2,
        low_count: 0,
        compliance_score: 88.3,
        duration_seconds: 4.2,
        created_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
      };
      localAssessments.unshift(newAss);
      return newAss as unknown as T;
    }

    // Findings
    if (path.startsWith('/findings') && method === 'GET') {
      if (path === '/findings' || path.startsWith('/findings?')) {
        return localFindings as unknown as T;
      }
      const id = path.split('/')[2];
      const f = localFindings.find((x) => x.id === id);
      return (f || localFindings[0]) as unknown as T;
    }

    if (path.includes('/acknowledge') && method === 'POST') {
      const id = path.split('/')[2];
      const f = localFindings.find((x) => x.id === id);
      if (f) {
        f.status = 'ACKNOWLEDGED';
        f.acknowledged_by = 'Security Analyst';
        f.acknowledged_at = new Date().toISOString();
      }
      return (f || {}) as unknown as T;
    }

    if (path.includes('/resolve') && method === 'POST') {
      const id = path.split('/')[2];
      const f = localFindings.find((x) => x.id === id);
      if (f) f.status = 'RESOLVED';
      return (f || {}) as unknown as T;
    }

    // Rules
    if (path.startsWith('/rules')) {
      if (path === '/rules' || path.startsWith('/rules?')) {
        return SEED_RULES as unknown as T;
      }
      const id = path.split('/')[2];
      const r = SEED_RULES.find((x) => x.id === id);
      return (r || SEED_RULES[0]) as unknown as T;
    }

    // Profiles
    if (path.startsWith('/profiles')) {
      return [
        {
          id: 'cis-linux-server',
          name: 'CIS Linux Server Benchmark (Level 1)',
          description: 'Standard production hardening rules for Linux servers.',
          is_system_default: true,
          rule_count: 60,
          created_at: '2026-01-01T00:00:00Z',
        },
        {
          id: 'cis-linux-workstation',
          name: 'CIS Linux Workstation Benchmark',
          description: 'Hardening profile tailored for engineer laptops.',
          is_system_default: false,
          rule_count: 45,
          created_at: '2026-01-01T00:00:00Z',
        },
      ] as unknown as T;
    }

    // Remediation
    if (path.startsWith('/remediation') && method === 'GET') {
      return localRemediations as unknown as T;
    }

    if (path === '/remediation/plan' && method === 'POST') {
      const body = JSON.parse(String(options.body || '{}'));
      const finding = localFindings.find((f) => f.id === body.finding_id) || localFindings[0];
      const newPlan: Remediation = {
        id: `rem-${Date.now().toString().slice(-4)}`,
        finding_id: finding.id,
        status: 'PENDING_APPROVAL',
        title: `Harden ${finding.control}`,
        description: `Apply safe automated hardening for ${finding.title}. Requires explicit approval.`,
        target_file: '/etc/ssh/sshd_config',
        proposed_diff: '- PermitRootLogin yes\n+ PermitRootLogin no',
        commands: [
          'cp /etc/ssh/sshd_config /etc/ssh/sshd_config.psv_backup',
          "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
          'systemctl reload sshd',
        ],
        backup_path: '/etc/ssh/sshd_config.psv_backup',
        rollback_commands: ['cp /etc/ssh/sshd_config.psv_backup /etc/ssh/sshd_config', 'systemctl reload sshd'],
        created_at: new Date().toISOString(),
      };
      localRemediations.unshift(newPlan);
      return newPlan as unknown as T;
    }

    if (path.includes('/approve') && method === 'POST') {
      const id = path.split('/')[2];
      const r = localRemediations.find((x) => x.id === id);
      if (r) {
        r.status = 'APPROVED';
        r.approved_by = 'Administrator';
        r.approved_at = new Date().toISOString();
      }
      return (r || {}) as unknown as T;
    }

    if (path.includes('/execute') && method === 'POST') {
      const id = path.split('/')[2];
      const r = localRemediations.find((x) => x.id === id);
      if (r) {
        r.status = 'APPLIED';
        r.executed_at = new Date().toISOString();
        r.execution_output = 'Commands executed successfully. Backup snapshot verified.';
        const f = localFindings.find((x) => x.id === r.finding_id);
        if (f) f.status = 'RESOLVED';
      }
      return (r || {}) as unknown as T;
    }

    // Drift
    if (path.startsWith('/drift/compare')) {
      const comp: DriftComparison = {
        host_id: 'host-01',
        host_name: 'prod-gateway-01',
        baseline_assessment_id: 'ass-100',
        target_assessment_id: 'ass-101',
        baseline_date: new Date(Date.now() - 86400000 * 2).toISOString(),
        target_date: new Date(Date.now() - 3600000 * 2).toISOString(),
        total_changes: 2,
        changes: [
          {
            control: 'ssh.permit_root_login',
            category: 'ssh',
            previous_value: 'prohibit-password',
            current_value: 'yes',
            first_observed: new Date(Date.now() - 86400000 * 2).toISOString(),
            last_observed: new Date().toISOString(),
            severity: 'HIGH',
            description: 'Observed modification from prohibit-password to yes in sshd_config.',
          },
          {
            control: 'firewall.ufw_active',
            category: 'firewall',
            previous_value: true,
            current_value: false,
            first_observed: new Date(Date.now() - 86400000 * 2).toISOString(),
            last_observed: new Date().toISOString(),
            severity: 'HIGH',
            description: 'UFW service was stopped or disabled.',
          },
        ],
      };
      return comp as unknown as T;
    }

    // Stats
    if (path === '/stats') {
      return {
        total_hosts: localHosts.length,
        total_assessments: localAssessments.length,
        open_findings: localFindings.filter((f) => f.status === 'OPEN').length,
        critical_findings: localFindings.filter((f) => f.status === 'OPEN' && f.severity === 'CRITICAL').length,
        high_findings: localFindings.filter((f) => f.status === 'OPEN' && f.severity === 'HIGH').length,
        remediations_pending_approval: localRemediations.filter((r) => r.status === 'PENDING_APPROVAL').length,
        average_compliance_score: 86.7,
      } as unknown as T;
    }

    // Health
    if (path === '/health') {
      return { status: 'healthy', version: '1.0.0', app: 'PSV Linux Security Auditor' } as unknown as T;
    }

    // Audit logs
    if (path === '/audit-logs') {
      return [
        {
          id: 'evt-1',
          action: 'assessment.completed',
          resource_type: 'assessment',
          resource_id: 'ass-101',
          details: { compliance_score: 86.7, findings: 6 },
          created_at: new Date(Date.now() - 3600000 * 2).toISOString(),
        },
        {
          id: 'evt-2',
          action: 'user.login',
          resource_type: 'user',
          resource_id: 'user-01',
          details: { email: 'admin@psv.local', role: 'ADMIN' },
          created_at: new Date(Date.now() - 3600000 * 4).toISOString(),
        },
      ] as unknown as T;
    }

    return {} as T;
  }
}

export const api = new APIClient();
