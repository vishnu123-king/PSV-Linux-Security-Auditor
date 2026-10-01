from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.core.database import get_db
from backend.app.engine.drift import drift_detector
from backend.app.models.entities import Assessment, Host, Observation, Rule
from backend.app.schemas.schemas import DriftComparisonResponse

router = APIRouter(prefix="/drift", tags=["Drift Detection"])


@router.get("/compare", response_model=DriftComparisonResponse)
async def compare_drift(
    host_id: str,
    baseline_id: Optional[str] = None,
    target_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    host_res = await db.execute(select(Host).where(Host.id == host_id))
    host = host_res.scalar_one_or_none()
    if not host:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")

    # If baseline or target not specified, pick the two most recent completed assessments
    if not baseline_id or not target_id:
        ass_res = await db.execute(
            select(Assessment)
            .where(Assessment.host_id == host_id)
            .order_by(Assessment.created_at.desc())
            .limit(2)
        )
        assessments = ass_res.scalars().all()
        if len(assessments) < 2:
            # If only 1 assessment exists, create a baseline comparison against initial defaults
            if len(assessments) == 1:
                target_id = assessments[0].id
                baseline_id = assessments[0].id
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="At least one completed assessment required for drift comparison"
                )
        else:
            target_id = assessments[0].id
            baseline_id = assessments[1].id

    base_res = await db.execute(select(Assessment).where(Assessment.id == baseline_id))
    base_ass = base_res.scalar_one_or_none()

    target_res = await db.execute(select(Assessment).where(Assessment.id == target_id))
    target_ass = target_res.scalar_one_or_none()

    if not base_ass or not target_ass:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Baseline or target assessment not found")

    # Fetch observations
    base_obs_res = await db.execute(select(Observation).where(Observation.assessment_id == baseline_id))
    base_obs = [
        {"control": o.control, "category": o.category, "value": o.value, "collected_at": o.collected_at}
        for o in base_obs_res.scalars().all()
    ]

    target_obs_res = await db.execute(select(Observation).where(Observation.assessment_id == target_id))
    target_obs = [
        {"control": o.control, "category": o.category, "value": o.value, "collected_at": o.collected_at}
        for o in target_obs_res.scalars().all()
    ]

    # Fetch rule severities map
    rule_res = await db.execute(select(Rule.control, Rule.severity))
    rule_severities = {row[0]: row[1].value for row in rule_res.all()}

    return drift_detector.compare(
        host_id=host.id,
        host_name=host.name,
        baseline_assessment_id=baseline_id,
        target_assessment_id=target_id,
        baseline_date=base_ass.created_at,
        target_date=target_ass.created_at,
        baseline_observations=base_obs,
        target_observations=target_obs,
        rule_severities=rule_severities
    )
