"""
PSV Linux Security Auditor - Assessments Router

Hardening Requirements #13, #14, #33:
- Strict RBAC: VIEWER can read, OPERATOR can launch and cancel assessments.
- IDOR Protection: Scoped to authenticated user's organization.
"""

from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.api.deps import get_current_user, require_role, verify_org_ownership
from backend.app.core.database import get_db
from backend.app.core.event_bus import event_bus
from backend.app.models.entities import (
    Assessment,
    AssessmentStatus,
    AuditEvent,
    Finding,
    Host,
    Profile,
    User,
    UserRole,
)
from backend.app.schemas.schemas import (
    AssessmentCreate,
    AssessmentResponse,
    FindingResponse,
)

router = APIRouter(prefix="/assessments", tags=["Assessments"])


@router.get("", response_model=List[AssessmentResponse])
async def list_assessments(
    host_id: Optional[str] = None,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.VIEWER))
):
    query = (
        select(Assessment)
        .join(Host, Assessment.host_id == Host.id)
        .where(Host.organization_id == current_user.organization_id)
        .order_by(Assessment.created_at.desc())
    )
    if host_id:
        query = query.where(Assessment.host_id == host_id)
    if status:
        query = query.where(Assessment.status == status)

    result = await db.execute(query)
    assessments = result.scalars().all()
    return [AssessmentResponse.model_validate(a) for a in assessments]


@router.post("", response_model=AssessmentResponse, status_code=status.HTTP_201_CREATED)
async def create_assessment(
    assessment_in: AssessmentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.OPERATOR))
):
    # IDOR Check: Ensure target host belongs to user's organization
    host_res = await db.execute(select(Host).where(Host.id == assessment_in.host_id))
    host = host_res.scalar_one_or_none()
    if not host:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")
    verify_org_ownership(host.organization_id, current_user)

    # Ensure profile exists
    prof_res = await db.execute(select(Profile).where(Profile.id == assessment_in.profile_id))
    profile = prof_res.scalar_one_or_none()
    if not profile:
        profile = Profile(
            id=assessment_in.profile_id,
            name=f"Profile {assessment_in.profile_id}",
            description="Compliance security profile"
        )
        db.add(profile)
        await db.flush()

    new_assessment = Assessment(
        host_id=host.id,
        profile_id=profile.id,
        triggered_by=current_user.email,
        status=AssessmentStatus.QUEUED,
        progress_percent=0,
        completed_collectors=[],
        total_rules=0,
        compliance_score=0.0
    )
    db.add(new_assessment)
    await db.flush()

    # Log audit event
    audit_log = AuditEvent(
        user_id=current_user.id,
        action="assessment.created",
        resource_type="assessment",
        resource_id=new_assessment.id,
        details={"host_id": host.id, "host_name": host.name, "profile_id": profile.id}
    )
    db.add(audit_log)
    await db.commit()
    await db.refresh(new_assessment)

    # Publish job to message broker (RabbitMQ / Memory Queue)
    await event_bus.publish_assessment_job({
        "assessment_id": new_assessment.id,
        "host_id": host.id,
        "profile_id": profile.id
    })

    resp = AssessmentResponse.model_validate(new_assessment)
    resp.host_name = host.name
    return resp


@router.get("/{assessment_id}", response_model=AssessmentResponse)
async def get_assessment(
    assessment_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.VIEWER))
):
    result = await db.execute(select(Assessment).where(Assessment.id == assessment_id))
    assessment = result.scalar_one_or_none()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    host_res = await db.execute(select(Host).where(Host.id == assessment.host_id))
    host = host_res.scalar_one_or_none()
    if host:
        verify_org_ownership(host.organization_id, current_user)

    resp = AssessmentResponse.model_validate(assessment)
    if host:
        resp.host_name = host.name
    return resp


@router.get("/{assessment_id}/findings", response_model=List[FindingResponse])
async def get_assessment_findings(
    assessment_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.VIEWER))
):
    result = await db.execute(select(Assessment).where(Assessment.id == assessment_id))
    assessment = result.scalar_one_or_none()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    host_res = await db.execute(select(Host).where(Host.id == assessment.host_id))
    host = host_res.scalar_one_or_none()
    if host:
        verify_org_ownership(host.organization_id, current_user)

    findings_res = await db.execute(select(Finding).where(Finding.assessment_id == assessment_id))
    findings = findings_res.scalars().all()
    return [FindingResponse.model_validate(f) for f in findings]


@router.post("/{assessment_id}/cancel", response_model=AssessmentResponse)
async def cancel_assessment(
    assessment_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.OPERATOR))
):
    result = await db.execute(select(Assessment).where(Assessment.id == assessment_id))
    assessment = result.scalar_one_or_none()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    host_res = await db.execute(select(Host).where(Host.id == assessment.host_id))
    host = host_res.scalar_one_or_none()
    if host:
        verify_org_ownership(host.organization_id, current_user)

    if assessment.status not in (AssessmentStatus.COMPLETED, AssessmentStatus.FAILED):
        assessment.status = AssessmentStatus.CANCELLED
        assessment.completed_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(assessment)

    return AssessmentResponse.model_validate(assessment)
