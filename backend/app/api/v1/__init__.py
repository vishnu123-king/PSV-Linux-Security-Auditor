from fastapi import APIRouter
from backend.app.api.v1.auth import router as auth_router
from backend.app.api.v1.hosts import router as hosts_router
from backend.app.api.v1.assessments import router as assessments_router
from backend.app.api.v1.findings import router as findings_router
from backend.app.api.v1.rules import router as rules_router
from backend.app.api.v1.profiles import router as profiles_router
from backend.app.api.v1.remediation import router as remediation_router
from backend.app.api.v1.verification import router as verification_router
from backend.app.api.v1.drift import router as drift_router
from backend.app.api.v1.reports import router as reports_router
from backend.app.api.v1.audit_logs import router as audit_logs_router
from backend.app.api.v1.system import router as system_router

api_v1_router = APIRouter()

api_v1_router.include_router(auth_router)
api_v1_router.include_router(hosts_router)
api_v1_router.include_router(assessments_router)
api_v1_router.include_router(findings_router)
api_v1_router.include_router(rules_router)
api_v1_router.include_router(profiles_router)
api_v1_router.include_router(remediation_router)
api_v1_router.include_router(verification_router)
api_v1_router.include_router(drift_router)
api_v1_router.include_router(reports_router)
api_v1_router.include_router(audit_logs_router)
api_v1_router.include_router(system_router)

__all__ = ["api_v1_router"]
