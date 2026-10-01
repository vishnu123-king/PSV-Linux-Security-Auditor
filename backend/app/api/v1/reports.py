import json
from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.core.database import get_db
from backend.app.engine.reports import report_generator
from backend.app.models.entities import Assessment, Finding, Host, Report
from backend.app.schemas.schemas import ReportGenerateRequest, ReportResponse

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post("/generate", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
async def generate_report(req: ReportGenerateRequest, db: AsyncSession = Depends(get_db)):
    ass_res = await db.execute(select(Assessment).where(Assessment.id == req.assessment_id))
    assessment = ass_res.scalar_one_or_none()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    host_res = await db.execute(select(Host).where(Host.id == assessment.host_id))
    host = host_res.scalar_one_or_none()

    findings_res = await db.execute(select(Finding).where(Finding.assessment_id == req.assessment_id))
    findings = findings_res.scalars().all()

    assessment_data = {
        "id": assessment.id,
        "profile_id": assessment.profile_id,
        "compliance_score": assessment.compliance_score,
        "total_rules": assessment.total_rules,
        "passed_rules": assessment.passed_rules,
        "failed_rules": assessment.failed_rules,
        "warn_rules": assessment.warn_rules,
        "unknown_rules": assessment.unknown_rules,
        "critical_count": assessment.critical_count,
        "high_count": assessment.high_count,
        "medium_count": assessment.medium_count,
        "low_count": assessment.low_count,
    }

    host_data = {
        "id": host.id if host else "",
        "name": host.name if host else "Host",
        "hostname": host.hostname if host else "unknown",
        "os_distribution": host.os_distribution if host else "Linux",
        "os_version": host.os_version if host else "",
        "environment": host.environment if host else "production"
    }

    findings_data = [
        {
            "id": f.id,
            "rule_id": f.rule_id,
            "title": f.title,
            "category": f.category,
            "severity": f.severity.value,
            "status": f.status.value,
            "control": f.control,
            "actual_value": f.actual_value,
            "expected_value": f.expected_value,
            "rationale": f.rationale,
            "remediation_guidance": f.remediation_guidance,
            "verification_method": f.verification_method
        }
        for f in findings
    ]

    fmt = req.format.lower()
    if fmt == "html":
        content_str = report_generator.generate_html_report(assessment_data, host_data, findings_data)
        summary = {"format": "html", "finding_count": len(findings_data), "score": assessment.compliance_score}
    else:
        json_obj = report_generator.generate_json_report(assessment_data, host_data, findings_data)
        content_str = json.dumps(json_obj, indent=2)
        summary = json_obj.get("executive_summary", {})

    report = Report(
        assessment_id=assessment.id,
        format=fmt,
        summary=summary,
        content=content_str
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    return ReportResponse.model_validate(report)


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(report_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return ReportResponse.model_validate(report)


@router.get("/{report_id}/download")
async def download_report(report_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    if report.format == "html":
        return Response(content=report.content, media_type="text/html")
    else:
        return Response(content=report.content, media_type="application/json")
