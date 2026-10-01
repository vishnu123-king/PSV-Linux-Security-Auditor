from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

try:
    import email_validator  # noqa: F401
    from pydantic import EmailStr
except Exception:
    EmailStr = str  # type: ignore[assignment,misc]
from backend.app.models.entities import (
    AssessmentStatus,
    FindingSeverity,
    FindingStatus,
    RemediationStatus,
    RuleResult,
    UserRole,
    VerificationStatus,
)


class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# Auth & User schemas
class UserLogin(BaseModel):
    email: Optional[str] = None
    username: Optional[str] = None
    password: str


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str
    password: str
    role: UserRole = UserRole.VIEWER
    organization_name: Optional[str] = "Default Organization"


class UserResponse(BaseSchema):
    id: str
    email: str
    full_name: str
    role: UserRole
    organization_id: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class TokenData(BaseModel):
    user_id: Optional[str] = None
    role: Optional[UserRole] = None
    org_id: Optional[str] = None


# Credential schemas
class CredentialCreate(BaseModel):
    name: str
    auth_type: str = "ssh_key"  # ssh_key, password, agent
    username: str
    secret: str  # private key content or password
    key_passphrase: Optional[str] = None


class CredentialResponse(BaseSchema):
    id: str
    name: str
    auth_type: str
    username: str
    fingerprint: Optional[str] = None
    created_at: datetime


# Host schemas
class HostCreate(BaseModel):
    name: str
    hostname: str
    port: int = 22
    environment: str = "production"
    tags: Dict[str, Any] = Field(default_factory=dict)
    credential_id: Optional[str] = None
    # Inline credential option for fast onboarding
    username: Optional[str] = None
    private_key: Optional[str] = None
    password: Optional[str] = None


class HostUpdate(BaseModel):
    name: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None
    environment: Optional[str] = None
    tags: Optional[Dict[str, Any]] = None
    credential_id: Optional[str] = None
    is_active: Optional[bool] = None


class HostResponse(BaseSchema):
    id: str
    organization_id: str
    project_id: Optional[str] = None
    credential_id: Optional[str] = None
    name: str
    hostname: str
    port: int
    environment: str
    tags: Dict[str, Any]
    os_family: Optional[str] = None
    os_distribution: Optional[str] = None
    os_version: Optional[str] = None
    kernel_version: Optional[str] = None
    arch: Optional[str] = None
    last_seen: Optional[datetime] = None
    last_assessment_status: Optional[str] = None
    is_active: bool
    created_at: datetime
    updated_at: datetime


class HostTestResult(BaseModel):
    success: bool
    message: str
    host_id: Optional[str] = None
    hostname: Optional[str] = None
    latency_ms: Optional[float] = None
    banner: Optional[str] = None
    fingerprint: Optional[str] = None


# Profile schemas
class ProfileCreate(BaseModel):
    id: str
    name: str
    description: str
    rule_ids: List[str] = Field(default_factory=list)


class ProfileResponse(BaseSchema):
    id: str
    name: str
    description: str
    is_system_default: bool
    rule_count: Optional[int] = 0
    created_at: datetime


# Rule schemas
class RuleCreate(BaseModel):
    id: str
    name: str
    version: str = "1.0.0"
    category: str
    severity: FindingSeverity
    control: str
    rationale: str
    condition: Dict[str, Any]
    remediation_guidance: str
    verification_method: str
    supported_distros: List[str] = Field(default_factory=list)


class RuleResponse(BaseSchema):
    id: str
    name: str
    version: str
    category: str
    severity: FindingSeverity
    control: str
    rationale: str
    condition: Dict[str, Any]
    remediation_guidance: str
    verification_method: str
    supported_distros: List[str]
    created_at: datetime


# Assessment schemas
class AssessmentCreate(BaseModel):
    host_id: str
    profile_id: Optional[str] = "cis-linux-server"
    triggered_by: str = "manual"


class AssessmentResponse(BaseSchema):
    id: str
    host_id: str
    profile_id: str
    triggered_by: Optional[str] = None
    status: AssessmentStatus
    progress_percent: int
    current_collector: Optional[str] = None
    completed_collectors: List[str]
    total_rules: int
    passed_rules: int
    failed_rules: int
    warn_rules: int
    unknown_rules: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    compliance_score: float
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None
    created_at: datetime
    host_name: Optional[str] = None


# Observation schema
class ObservationResponse(BaseSchema):
    id: str
    assessment_id: str
    collector: str
    category: str
    control: str
    value: Any
    source: str
    command_executed: Optional[str] = None
    collected_at: datetime


# Finding schemas
class FindingResponse(BaseSchema):
    id: str
    assessment_id: str
    host_id: str
    rule_id: str
    title: str
    category: str
    severity: FindingSeverity
    status: FindingStatus
    result: RuleResult
    control: str
    expected_value: Any
    actual_value: Any
    rationale: str
    remediation_guidance: str
    verification_method: str
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    suppressed_reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class FindingAcknowledge(BaseModel):
    acknowledged_by: Optional[str] = "admin"


FindingAcknowledgeRequest = FindingAcknowledge


class FindingSuppress(BaseModel):
    reason: str


FindingSuppressRequest = FindingSuppress


# Evidence schema
class EvidenceResponse(BaseSchema):
    id: str
    finding_id: str
    source_file: Optional[str] = None
    command_executed: Optional[str] = None
    raw_output: str
    normalized_data: Dict[str, Any]
    collected_at: datetime


# Remediation schemas
class RemediationPlanRequest(BaseModel):
    finding_id: str


class RemediationApproveRequest(BaseModel):
    approved_by: Optional[str] = "admin"


class RemediationResponse(BaseSchema):
    id: str
    finding_id: str
    status: RemediationStatus
    title: str
    description: str
    target_file: Optional[str] = None
    proposed_diff: Optional[str] = None
    commands: List[str]
    backup_path: Optional[str] = None
    rollback_commands: List[str]
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    execution_output: Optional[str] = None
    created_at: datetime


# Verification schema
class VerificationResponse(BaseSchema):
    id: str
    finding_id: str
    status: VerificationStatus
    command_used: str
    output: str
    verified_at: datetime


# Drift schemas
class DriftItem(BaseModel):
    control: str
    category: str
    previous_value: Any
    current_value: Any
    first_observed: datetime
    last_observed: datetime
    severity: Optional[str] = None
    description: str


class DriftComparisonResponse(BaseModel):
    host_id: str
    host_name: str
    baseline_assessment_id: str
    target_assessment_id: str
    baseline_date: datetime
    target_date: datetime
    total_changes: int
    changes: List[DriftItem]


# Report schemas
class ReportGenerateRequest(BaseModel):
    assessment_id: str
    format: str = "json"  # "json" or "html"


class ReportResponse(BaseSchema):
    id: str
    assessment_id: str
    format: str
    summary: Dict[str, Any]
    content: str
    generated_at: datetime


# Audit log schemas
class AuditEventResponse(BaseSchema):
    id: str
    user_id: Optional[str] = None
    action: str
    resource_type: str
    resource_id: str
    ip_address: Optional[str] = None
    details: Dict[str, Any]
    created_at: datetime
