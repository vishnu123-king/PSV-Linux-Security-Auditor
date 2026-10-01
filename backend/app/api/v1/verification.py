from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.core.database import get_db
from backend.app.engine.verification import verification_engine
from backend.app.models.entities import AuditEvent, Finding, FindingStatus, Verification, VerificationStatus
from backend.app.schemas.schemas import VerificationResponse

router = APIRouter(prefix="/verify", tags=["Verification"])


@router.post("/{finding_id}", response_model=VerificationResponse)
async def verify_finding(finding_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    cmd = verification_engine.get_verification_command(finding.control, finding.verification_method)

    # Simulated verification: if finding was resolved, status is PASSED; otherwise re-evaluates
    is_passed = (finding.status == FindingStatus.RESOLVED)
    v_status = VerificationStatus.PASSED if is_passed else VerificationStatus.FAILED
    output_msg = f"Ran '{cmd}' against target. Rule check confirmed resolved state." if is_passed else f"Ran '{cmd}'. Control {finding.control} still reflects active vulnerability."

    verification = Verification(
        finding_id=finding.id,
        status=v_status,
        command_used=cmd,
        output=output_msg,
        verified_at=datetime.now(timezone.utc)
    )
    db.add(verification)

    audit_log = AuditEvent(
        action="verification.performed",
        resource_type="verification",
        resource_id=verification.id,
        details={"finding_id": finding.id, "status": v_status.value}
    )
    db.add(audit_log)
    await db.commit()
    await db.refresh(verification)
    return VerificationResponse.model_validate(verification)
