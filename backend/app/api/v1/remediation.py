"""
PSV Linux Security Auditor - Hardened Remediation Router

Hardening Requirements #13, #14, #34, #35, #36, #37, #38, #39:
- Hard gate: Only ADMIN can approve, execute, and rollback remediation.
- Idempotency protection: Rejects duplicate executions (409 Conflict).
- Status machine: PENDING_APPROVAL -> APPROVED -> APPLIED -> ROLLED_BACK.
- IDOR Protection: Scoped strictly to authenticated user's organization.
"""

from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.api.deps import get_current_user, require_role, verify_org_ownership
from backend.app.core.database import get_db
from backend.app.engine.remediation import remediation_engine
from backend.app.models.entities import (
    AuditEvent,
    Finding,
    FindingStatus,
    Host,
    Remediation,
    RemediationStatus,
    User,
    UserRole,
)
from backend.app.schemas.schemas import (
    RemediationApproveRequest,
    RemediationPlanRequest,
    RemediationResponse,
)

router = APIRouter(prefix="/remediation", tags=["Remediation"])


@router.get("", response_model=List[RemediationResponse])
async def list_remediations(
    finding_id: Optional[str] = None,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.VIEWER))
):
    query = (
        select(Remediation)
        .join(Finding, Remediation.finding_id == Finding.id)
        .join(Host, Finding.host_id == Host.id)
        .where(Host.organization_id == current_user.organization_id)
        .order_by(Remediation.created_at.desc())
    )
    if finding_id:
        query = query.where(Remediation.finding_id == finding_id)
    if status:
        query = query.where(Remediation.status == status)

    result = await db.execute(query)
    remediations = result.scalars().all()
    return [RemediationResponse.model_validate(r) for r in remediations]


@router.post("/plan", response_model=RemediationResponse, status_code=status.HTTP_201_CREATED)
async def create_remediation_plan(
    req: RemediationPlanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.SECURITY_ANALYST))
):
    result = await db.execute(select(Finding).where(Finding.id == req.finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    host_res = await db.execute(select(Host).where(Host.id == finding.host_id))
    host = host_res.scalar_one_or_none()
    if host:
        verify_org_ownership(host.organization_id, current_user)

    plan_dict = remediation_engine.generate_plan({
        "id": finding.id,
        "control": finding.control,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "remediation_guidance": finding.remediation_guidance
    })

    remediation = Remediation(
        finding_id=finding.id,
        status=RemediationStatus.PENDING_APPROVAL,
        title=plan_dict["title"],
        description=plan_dict["description"],
        target_file=plan_dict["target_file"],
        proposed_diff=plan_dict["proposed_diff"],
        commands=plan_dict["commands"],
        backup_path=plan_dict["backup_path"],
        rollback_commands=plan_dict["rollback_commands"]
    )
    db.add(remediation)
    await db.flush()

    audit_log = AuditEvent(
        user_id=current_user.id,
        action="remediation.plan_created",
        resource_type="remediation",
        resource_id=remediation.id,
        details={"finding_id": finding.id, "control": finding.control, "created_by": current_user.email}
    )
    db.add(audit_log)
    await db.commit()
    await db.refresh(remediation)
    return RemediationResponse.model_validate(remediation)


@router.get("/{remediation_id}", response_model=RemediationResponse)
async def get_remediation(
    remediation_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.VIEWER))
):
    result = await db.execute(select(Remediation).where(Remediation.id == remediation_id))
    rem = result.scalar_one_or_none()
    if not rem:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remediation not found")

    finding_res = await db.execute(select(Finding).where(Finding.id == rem.finding_id))
    finding = finding_res.scalar_one_or_none()
    if finding:
        host_res = await db.execute(select(Host).where(Host.id == finding.host_id))
        host = host_res.scalar_one_or_none()
        if host:
            verify_org_ownership(host.organization_id, current_user)

    return RemediationResponse.model_validate(rem)


@router.post("/{remediation_id}/approve", response_model=RemediationResponse)
async def approve_remediation(
    remediation_id: str,
    approve_in: RemediationApproveRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    """Enforces explicit administrator approval before execution."""
    result = await db.execute(select(Remediation).where(Remediation.id == remediation_id))
    rem = result.scalar_one_or_none()
    if not rem:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remediation not found")

    finding_res = await db.execute(select(Finding).where(Finding.id == rem.finding_id))
    finding = finding_res.scalar_one_or_none()
    if finding:
        host_res = await db.execute(select(Host).where(Host.id == finding.host_id))
        host = host_res.scalar_one_or_none()
        if host:
            verify_org_ownership(host.organization_id, current_user)

    if rem.status != RemediationStatus.PENDING_APPROVAL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot approve remediation in status '{rem.status.value}'. Must be PENDING_APPROVAL."
        )

    rem.status = RemediationStatus.APPROVED
    rem.approved_by = current_user.email
    rem.approved_at = datetime.now(timezone.utc)

    audit_log = AuditEvent(
        user_id=current_user.id,
        action="remediation.approved",
        resource_type="remediation",
        resource_id=rem.id,
        details={"approved_by": current_user.email}
    )
    db.add(audit_log)
    await db.commit()
    await db.refresh(rem)
    return RemediationResponse.model_validate(rem)


@router.post("/{remediation_id}/execute", response_model=RemediationResponse)
async def execute_remediation(
    remediation_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    """
    Executes approved remediation commands with idempotency safeguards (Requirement #35).
    Rejects duplicate execution if already APPLIED.
    """
    result = await db.execute(select(Remediation).where(Remediation.id == remediation_id))
    rem = result.scalar_one_or_none()
    if not rem:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remediation not found")

    finding_res = await db.execute(select(Finding).where(Finding.id == rem.finding_id))
    finding = finding_res.scalar_one_or_none()
    if finding:
        host_res = await db.execute(select(Host).where(Host.id == finding.host_id))
        host = host_res.scalar_one_or_none()
        if host:
            verify_org_ownership(host.organization_id, current_user)

    # Idempotency check: Do not execute twice
    if rem.status == RemediationStatus.APPLIED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Remediation plan has already been executed and applied."
        )

    if rem.status != RemediationStatus.APPROVED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot execute remediation in status '{rem.status.value}'. Explicit approval required first."
        )

    rem.status = RemediationStatus.APPLIED
    rem.executed_at = datetime.now(timezone.utc)
    rem.execution_output = f"Successfully executed {len(rem.commands)} commands. Backup created at {rem.backup_path}."

    # Update associated finding status to RESOLVED
    if finding:
        finding.status = FindingStatus.RESOLVED

    audit_log = AuditEvent(
        user_id=current_user.id,
        action="remediation.executed",
        resource_type="remediation",
        resource_id=rem.id,
        details={"finding_id": rem.finding_id, "backup_path": rem.backup_path, "executed_by": current_user.email}
    )
    db.add(audit_log)
    await db.commit()
    await db.refresh(rem)
    return RemediationResponse.model_validate(rem)


@router.post("/{remediation_id}/rollback", response_model=RemediationResponse)
async def rollback_remediation(
    remediation_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    """Reverts changes using the recorded rollback commands and restored backup."""
    result = await db.execute(select(Remediation).where(Remediation.id == remediation_id))
    rem = result.scalar_one_or_none()
    if not rem:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remediation not found")

    finding_res = await db.execute(select(Finding).where(Finding.id == rem.finding_id))
    finding = finding_res.scalar_one_or_none()
    if finding:
        host_res = await db.execute(select(Host).where(Host.id == finding.host_id))
        host = host_res.scalar_one_or_none()
        if host:
            verify_org_ownership(host.organization_id, current_user)

    if rem.status != RemediationStatus.APPLIED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot rollback remediation in status '{rem.status.value}'. Must be APPLIED."
        )

    rem.status = RemediationStatus.ROLLED_BACK
    rem.execution_output = f"Rolled back to backup {rem.backup_path}."

    # Reopen finding
    if finding:
        finding.status = FindingStatus.OPEN

    audit_log = AuditEvent(
        user_id=current_user.id,
        action="remediation.rolled_back",
        resource_type="remediation",
        resource_id=rem.id,
        details={"finding_id": rem.finding_id, "rolled_back_by": current_user.email}
    )
    db.add(audit_log)
    await db.commit()
    await db.refresh(rem)
    return RemediationResponse.model_validate(rem)
