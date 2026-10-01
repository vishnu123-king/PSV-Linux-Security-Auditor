from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from backend.app.engine.rule_loader import rule_loader
from backend.app.schemas.schemas import RuleResponse

router = APIRouter(prefix="/rules", tags=["Rules"])


@router.get("", response_model=List[RuleResponse])
async def list_rules(
    category: Optional[str] = None,
    severity: Optional[str] = None
):
    rules = rule_loader.load_all_rules()
    filtered = rules
    if category:
        filtered = [r for r in filtered if r.get("category") == category]
    if severity:
        filtered = [r for r in filtered if r.get("severity") == severity]

    # Map to schema
    output = []
    for r in filtered:
        output.append(RuleResponse(
            id=r["id"],
            name=r["name"],
            version=r.get("version", "1.0.0"),
            category=r.get("category", "general"),
            severity=r.get("severity", "MEDIUM"),
            control=r["control"],
            rationale=r.get("rationale", ""),
            condition=r.get("condition", {}),
            remediation_guidance=r.get("remediation_guidance", ""),
            verification_method=r.get("verification_method", ""),
            supported_distros=r.get("supported_distros", ["all"]),
            created_at="2026-01-01T00:00:00Z"
        ))
    return output


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(rule_id: str):
    rules = rule_loader.load_all_rules()
    for r in rules:
        if r["id"] == rule_id:
            return RuleResponse(
                id=r["id"],
                name=r["name"],
                version=r.get("version", "1.0.0"),
                category=r.get("category", "general"),
                severity=r.get("severity", "MEDIUM"),
                control=r["control"],
                rationale=r.get("rationale", ""),
                condition=r.get("condition", {}),
                remediation_guidance=r.get("remediation_guidance", ""),
                verification_method=r.get("verification_method", ""),
                supported_distros=r.get("supported_distros", ["all"]),
                created_at="2026-01-01T00:00:00Z"
            )
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found")
