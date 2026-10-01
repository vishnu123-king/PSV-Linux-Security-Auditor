"""
PSV Linux Security Auditor - Findings Router

Hardening Requirements #13, #14:
- Strict RBAC: VIEWER can read, SECURITY_ANALYST and ADMIN can triage (acknowledge, suppress, resolve).
- IDOR Protection: Scoped to authenticated user's organization.
"""

from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.api.deps import get_current_user, require_role, verify_org_ownership
from backend.app.core.database import get_db
from backend.app.models.entities import (
    AuditEvent,
    Evidence,
    Finding,
    FindingStatus,
    Host,
    User,
    UserRole,
)
from backend.app.schemas.schemas import (
    EvidenceResponse,
    FindingAcknowledgeRequest,
    FindingResponse,
    FindingSuppressRequest,
)

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("", response_model=List[FindingResponse])
async def list_findings(
    host_id: Optional[str] = None,
    assessment_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.VIEWER))
):
    query = (
        select(Finding)
        .join(Host, Finding.host_id == Host.id)
        .where(Host.organization_id == current_user.organization_id)
        .order_by(Finding.created_at.desc())
    )
    if host_id:
        query = query.where(Finding.host_id == host_id)
    if assessment_id:
        query = query.where(Finding.assessment_id == assessment_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)
    if category:
        query = query.where(Finding.category == category)

    result = await db.execute(query)
    findings = result.scalars().all()
    return [FindingResponse.model_validate(f) for f in findings]


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.VIEWER))
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    host_res = await db.execute(select(Host).where(Host.id == finding.host_id))
    host = host_res.scalar_one_or_none()
    if host:
        verify_org_ownership(host.organization_id, current_user)

    return FindingResponse.model_validate(finding)


@router.get("/{finding_id}/evidence", response_model=List[EvidenceResponse])
async def get_finding_evidence(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.VIEWER))
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    host_res = await db.execute(select(Host).where(Host.id == finding.host_id))
    host = host_res.scalar_one_or_none()
    if host:
        verify_org_ownership(host.organization_id, current_user)

    ev_res = await db.execute(select(Evidence).where(Evidence.finding_id == finding_id))
    evidence_list = ev_res.scalars().all()
    return [EvidenceResponse.model_validate(e) for e in evidence_list]


@router.post("/{finding_id}/acknowledge", response_model=FindingResponse)
async def acknowledge_finding(
    finding_id: str,
    ack_in: FindingAcknowledgeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.SECURITY_ANALYST))
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    host_res = await db.execute(select(Host).where(Host.id == finding.host_id))
    host = host_res.scalar_one_or_none()
    if host:
        verify_org_ownership(host.organization_id, current_user)

    finding.status = FindingStatus.ACKNOWLEDGED
    finding.acknowledged_by = current_user.email
    finding.acknowledged_at = datetime.now(timezone.utc)

    audit_log = AuditEvent(
        user_id=current_user.id,
        action="finding.acknowledged",
        resource_type="finding",
        resource_id=finding.id,
        details={"acknowledged_by": current_user.email}
    )
    db.add(audit_log)
    await db.commit()
    await db.refresh(finding)
    return FindingResponse.model_validate(finding)


@router.post("/{finding_id}/suppress", response_model=FindingResponse)
async def suppress_finding(
    finding_id: str,
    supp_in: FindingSuppressRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.SECURITY_ANALYST))
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    host_res = await db.execute(select(Host).where(Host.id == finding.host_id))
    host = host_res.scalar_one_or_none()
    if host:
        verify_org_ownership(host.organization_id, current_user)

    finding.status = FindingStatus.SUPPRESSED
    finding.suppressed_reason = supp_in.reason

    audit_log = AuditEvent(
        user_id=current_user.id,
        action="finding.suppressed",
        resource_type="finding",
        resource_id=finding.id,
        details={"reason": supp_in.reason, "suppressed_by": current_user.email}
    )
    db.add(audit_log)
    await db.commit()
    await db.refresh(finding)
    return FindingResponse.model_validate(finding)


@router.post("/{finding_id}/resolve", response_model=FindingResponse)
async def resolve_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.SECURITY_ANALYST))
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    host_res = await db.execute(select(Host).where(Host.id == finding.host_id))
    host = host_res.scalar_one_or_none()
    if host:
        verify_org_ownership(host.organization_id, current_user)

    finding.status = FindingStatus.RESOLVED

    audit_log = AuditEvent(
        user_id=current_user.id,
        action="finding.resolved",
        resource_type="finding",
        resource_id=finding.id,
        details={"resolved_by": current_user.email}
    )
    db.add(audit_log)
    await db.commit()
    await db.refresh(finding)
    return FindingResponse.model_validate(finding)
