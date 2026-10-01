from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.models.entities import Assessment, Evidence, Finding, Host


class SecurityAnalystAIService:
    """
    Safe security analyst abstraction adhering to requirements #51 & #52:
    - Never bypasses authorization or executes arbitrary shell commands.
    - Never automatically approves remediation plans.
    - MCP-friendly tool contracts for AI agents and assistants.
    """

    async def get_assessment_summary(self, db: AsyncSession, assessment_id: str) -> Dict[str, Any]:
        """Provides a natural language and structured security summary of an assessment."""
        result = await db.execute(select(Assessment).where(Assessment.id == assessment_id))
        assessment = result.scalar_one_or_none()
        if not assessment:
            return {"error": "Assessment not found"}

        host_res = await db.execute(select(Host).where(Host.id == assessment.host_id))
        host = host_res.scalar_one_or_none()

        findings_res = await db.execute(select(Finding).where(Finding.assessment_id == assessment_id))
        findings = findings_res.scalars().all()

        crit_findings = [f.title for f in findings if f.severity.value == "CRITICAL"]
        high_findings = [f.title for f in findings if f.severity.value == "HIGH"]

        analysis = (
            f"Host '{host.name if host else 'Unknown'}' achieved a compliance score of {assessment.compliance_score}%. "
            f"Evaluated {assessment.total_rules} benchmark controls: {assessment.passed_rules} passed, "
            f"{assessment.failed_rules} failed, and {assessment.unknown_rules} unknown. "
        )

        if crit_findings:
            analysis += f"Urgent attention required: {len(crit_findings)} CRITICAL controls breached ({', '.join(crit_findings[:3])}). "
        if high_findings:
            analysis += f"{len(high_findings)} HIGH severity findings observed ({', '.join(high_findings[:3])}). "

        return {
            "assessment_id": assessment_id,
            "host_name": host.name if host else "Unknown",
            "compliance_score": assessment.compliance_score,
            "analysis_text": analysis,
            "critical_items": crit_findings,
            "high_items": high_findings,
            "recommendation": "Review critical SSH and Sudo findings immediately and generate remediation plans for approval."
        }

    async def explain_finding(self, db: AsyncSession, finding_id: str) -> Dict[str, Any]:
        """Explains finding vulnerability impact and remediation guidance."""
        result = await db.execute(select(Finding).where(Finding.id == finding_id))
        finding = result.scalar_one_or_none()
        if not finding:
            return {"error": "Finding not found"}

        ev_res = await db.execute(select(Evidence).where(Evidence.finding_id == finding_id))
        evidence = ev_res.scalar_one_or_none()

        explanation = (
            f"The control '{finding.control}' was flagged with severity {finding.severity.value}. "
            f"Expected value was '{finding.expected_value}', but observed value was '{finding.actual_value}'. "
            f"Rationale: {finding.rationale}"
        )

        return {
            "finding_id": finding_id,
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity.value,
            "explanation": explanation,
            "observed_evidence": evidence.raw_output if evidence else "No raw evidence captured",
            "actionable_fix": finding.remediation_guidance,
            "safe_workflow": "Generate remediation plan -> Request administrator review -> Execute after explicit sign-off."
        }


ai_analyst_service = SecurityAnalystAIService()
