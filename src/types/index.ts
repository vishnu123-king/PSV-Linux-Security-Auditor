export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type AssessmentStatus =
  | 'QUEUED'
  | 'CONNECTING'
  | 'DISCOVERING'
  | 'COLLECTING'
  | 'NORMALIZING'
  | 'EVALUATING'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED';

export type FindingStatus = 'OPEN' | 'ACKNOWLEDGED' | 'SUPPRESSED' | 'RESOLVED';

export type RuleResult = 'PASS' | 'FAIL' | 'WARN' | 'UNKNOWN' | 'NOT_APPLICABLE';

export type RemediationStatus =
  | 'PLANNED'
  | 'PENDING_APPROVAL'
  | 'APPROVED'
  | 'EXECUTING'
  | 'APPLIED'
  | 'FAILED'
  | 'ROLLED_BACK';

export interface Host {
  id: string;
  name: string;
  hostname: string;
  port: number;
  environment: 'production' | 'staging' | 'development';
  tags: Record<string, any>;
  os_distribution?: string;
  os_version?: string;
  kernel_version?: string;
  arch?: string;
  last_seen?: string;
  last_assessment_status?: string;
  is_active: boolean;
  created_at: string;
}

export interface Assessment {
  id: string;
  host_id: string;
  host_name?: string;
  profile_id: string;
  triggered_by?: string;
  status: AssessmentStatus;
  progress_percent: number;
  current_collector?: string;
  completed_collectors: string[];
  total_rules: number;
  passed_rules: number;
  failed_rules: number;
  warn_rules: number;
  unknown_rules: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  compliance_score: number;
  started_at?: string;
  completed_at?: string;
  duration_seconds?: number;
  error_message?: string;
  created_at: string;
}

export interface Finding {
  id: string;
  assessment_id: string;
  host_id: string;
  rule_id: string;
  title: string;
  category: string;
  severity: Severity;
  status: FindingStatus;
  result: RuleResult;
  control: string;
  expected_value: any;
  actual_value: any;
  rationale: string;
  remediation_guidance: string;
  verification_method: string;
  acknowledged_by?: string;
  acknowledged_at?: string;
  suppressed_reason?: string;
  created_at: string;
}

export interface Rule {
  id: string;
  name: string;
  version: string;
  category: string;
  severity: Severity;
  control: string;
  rationale: string;
  condition: Record<string, any>;
  remediation_guidance: string;
  verification_method: string;
  supported_distros: string[];
  created_at: string;
}

export interface Profile {
  id: string;
  name: string;
  description: string;
  is_system_default: boolean;
  rule_count?: number;
  created_at: string;
}

export interface Remediation {
  id: string;
  finding_id: string;
  status: RemediationStatus;
  title: string;
  description: string;
  target_file?: string;
  proposed_diff?: string;
  commands: string[];
  backup_path?: string;
  rollback_commands: string[];
  approved_by?: string;
  approved_at?: string;
  executed_at?: string;
  execution_output?: string;
  created_at: string;
}

export interface DriftItem {
  control: string;
  category: string;
  previous_value: any;
  current_value: any;
  first_observed: string;
  last_observed: string;
  severity?: string;
  description: string;
}

export interface DriftComparison {
  host_id: string;
  host_name: string;
  baseline_assessment_id: string;
  target_assessment_id: string;
  baseline_date: string;
  target_date: string;
  total_changes: number;
  changes: DriftItem[];
}

export interface Evidence {
  id: string;
  finding_id: string;
  raw_output: string;
  normalized_data: Record<string, any>;
  collected_at: string;
}

export interface AuditEvent {
  id: string;
  user_id?: string;
  action: string;
  resource_type: string;
  resource_id: string;
  ip_address?: string;
  details: Record<string, any>;
  created_at: string;
}
