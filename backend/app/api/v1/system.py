"""
PSV Linux Security Auditor - System & Observability Router

Hardening Requirements #60, #61, #68:
- Readiness probe /ready: Checks both DB and RabbitMQ; returns HTTP 503 if unavailable in production.
- Health probe /health: Fast process liveness check.
- Version endpoint /version: Canonical application and rule engine version source.
- Prometheus metrics endpoint /metrics.
"""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.core.config import get_settings
from backend.app.core.database import get_db
from backend.app.core.event_bus import event_bus
from backend.app.models.entities import Assessment, Finding, Host, Remediation

router = APIRouter(tags=["System & Observability"])


@router.get("/health")
async def health():
    settings = get_settings()
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV
    }


@router.get("/version")
async def version():
    settings = get_settings()
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "api_version": "v1",
        "rules_pack_version": "1.0.0",
        "environment": settings.APP_ENV
    }


@router.get("/ready")
async def ready(db: AsyncSession = Depends(get_db)):
    settings = get_settings()
    is_prod = settings.APP_ENV.lower() == "production"

    # 1. Check database connectivity
    try:
        await db.execute(select(func.count(Host.id)))
        db_ready = True
    except Exception:
        db_ready = False

    # 2. Check message broker / RabbitMQ connectivity
    broker_ready = event_bus.is_connected
    if not broker_ready and not is_prod and settings.RABBITMQ_URL.startswith("memory://"):
        broker_ready = True  # Memory broker is always ready in dev/test

    is_overall_ready = db_ready and broker_ready

    payload = {
        "ready": is_overall_ready,
        "database": "connected" if db_ready else "disconnected",
        "broker": "connected" if broker_ready else "disconnected",
        "environment": settings.APP_ENV,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    if not is_overall_ready and is_prod:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=payload
        )

    return payload


@router.get("/stats")
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    hosts_count = (await db.execute(select(func.count(Host.id)))).scalar() or 0
    assessments_count = (await db.execute(select(func.count(Assessment.id)))).scalar() or 0
    open_findings = (await db.execute(select(func.count(Finding.id)).where(Finding.status == "OPEN"))).scalar() or 0
    critical_findings = (await db.execute(select(func.count(Finding.id)).where(Finding.status == "OPEN", Finding.severity == "CRITICAL"))).scalar() or 0
    high_findings = (await db.execute(select(func.count(Finding.id)).where(Finding.status == "OPEN", Finding.severity == "HIGH"))).scalar() or 0
    remediations_planned = (await db.execute(select(func.count(Remediation.id)).where(Remediation.status == "PENDING_APPROVAL"))).scalar() or 0

    # Average compliance score
    avg_score = (await db.execute(select(func.avg(Assessment.compliance_score)).where(Assessment.status == "COMPLETED"))).scalar() or 0.0

    return {
        "total_hosts": hosts_count,
        "total_assessments": assessments_count,
        "open_findings": open_findings,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "remediations_pending_approval": remediations_planned,
        "average_compliance_score": round(float(avg_score), 1),
    }


@router.get("/metrics")
async def metrics(db: AsyncSession = Depends(get_db)):
    """Prometheus-compatible metrics endpoint."""
    total_assessments = (await db.execute(select(func.count(Assessment.id)))).scalar() or 0
    failed_assessments = (await db.execute(select(func.count(Assessment.id)).where(Assessment.status == "FAILED"))).scalar() or 0
    total_findings = (await db.execute(select(func.count(Finding.id)))).scalar() or 0
    total_remediations = (await db.execute(select(func.count(Remediation.id)))).scalar() or 0

    lines = [
        "# HELP psv_assessments_total Total count of assessments executed",
        "# TYPE psv_assessments_total counter",
        f"psv_assessments_total {total_assessments}",
        "# HELP psv_assessments_failed_total Total count of failed assessments",
        "# TYPE psv_assessments_failed_total counter",
        f"psv_assessments_failed_total {failed_assessments}",
        "# HELP psv_findings_total Total findings discovered",
        "# TYPE psv_findings_total counter",
        f"psv_findings_total {total_findings}",
        "# HELP psv_remediation_total Total remediations planned or executed",
        "# TYPE psv_remediation_total counter",
        f"psv_remediation_total {total_remediations}",
        "# HELP psv_worker_jobs_total Number of worker jobs queued or processed",
        "# TYPE psv_worker_jobs_total counter",
        f"psv_worker_jobs_total {total_assessments}",
    ]
    return Response(content="\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")
