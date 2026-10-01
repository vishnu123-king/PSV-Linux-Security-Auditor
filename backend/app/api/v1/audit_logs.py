from typing import List, Optional
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.core.database import get_db
from backend.app.models.entities import AuditEvent
from backend.app.schemas.schemas import AuditEventResponse

router = APIRouter(prefix="/audit-logs", tags=["Audit Trail"])


@router.get("", response_model=List[AuditEventResponse])
async def list_audit_logs(
    resource_type: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    query = select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)
    if resource_type:
        query = query.where(AuditEvent.resource_type == resource_type)
    if action:
        query = query.where(AuditEvent.action == action)

    result = await db.execute(query)
    events = result.scalars().all()
    return [AuditEventResponse.model_validate(e) for e in events]
