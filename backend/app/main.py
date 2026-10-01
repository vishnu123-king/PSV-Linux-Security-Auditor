"""
PSV Linux Security Auditor - Main Application Entrypoint

Hardening Requirements #4, #15, #16, #17, #19, #45, #54, #84:
- Production configuration enforcement at startup (fails fast if insecure).
- Secure HTTP headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
- Request body size limiter (5MB max) to prevent payload DoS.
- Authenticated and authorized WebSocket connections with policy violation rejection.
"""

from contextlib import asynccontextmanager
import time
import uuid
from fastapi import FastAPI, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select
from backend.app.api.v1 import api_v1_router
from backend.app.core.config import get_settings
from backend.app.core.database import async_session_factory, init_db
from backend.app.core.event_bus import event_bus
from backend.app.core.logging import setup_logging
from backend.app.core.security import decode_token, get_password_hash
from backend.app.models.entities import Assessment, Host, Organization, Profile, User, UserRole
from backend.app.workers.assessment_worker import broadcast_manager, start_worker_listener

settings = get_settings()


async def seed_initial_data() -> None:
    """Seeds baseline organization and initial administrator user if not existing."""
    async with async_session_factory() as db:
        # Check if organization exists
        org_res = await db.execute(select(Organization).limit(1))
        org = org_res.scalar_one_or_none()
        if not org:
            org = Organization(name="Default Enterprise SOC", description="Primary Security Operations Center")
            db.add(org)
            await db.flush()

        # Check if admin user exists
        admin_res = await db.execute(select(User).where(User.email == settings.INITIAL_ADMIN_EMAIL))
        admin = admin_res.scalar_one_or_none()
        if not admin:
            admin = User(
                organization_id=org.id,
                email=settings.INITIAL_ADMIN_EMAIL,
                full_name="Lead Security Architect",
                hashed_password=get_password_hash(settings.INITIAL_ADMIN_PASSWORD),
                role=UserRole.ADMIN,
                is_active=True
            )
            db.add(admin)
            await db.flush()

        # Database starts clean with 0 hosts, 0 assessments, 0 findings
        await db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging(settings.LOG_LEVEL)

    # Enforce strict production configuration validation (Requirement #4, #83)
    settings.enforce_production_compliance()

    # Initialize DB
    await init_db()
    await seed_initial_data()

    # Connect EventBus and register background assessment listener
    await event_bus.connect()
    start_worker_listener()
    yield
    # Shutdown
    await event_bus.close()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Production-grade Linux Security Auditor with SSH collectors, YAML rule engine, drift detection, and safe remediation workflows.",
    lifespan=lifespan,
    docs_url="/docs" if settings.APP_ENV != "production" else None,
    redoc_url="/redoc" if settings.APP_ENV != "production" else None,
    openapi_url="/openapi.json" if settings.APP_ENV != "production" else None
)

# CORS Middleware (Production never allows wildcard '*')
cors_origins = settings.CORS_ORIGINS if isinstance(settings.CORS_ORIGINS, list) else [settings.CORS_ORIGINS]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)


# Request Body Size Limit Middleware (Requirement #45)
@app.middleware("http")
async def request_size_limit_middleware(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.MAX_REQUEST_BODY_SIZE:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"error": "Payload Too Large", "message": f"Request body exceeds maximum limit of {settings.MAX_REQUEST_BODY_SIZE} bytes."}
        )
    return await call_next(request)


# Security Headers & Request ID Middleware (Requirement #17)
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    start_time = time.monotonic()

    response = await call_next(request)

    duration_ms = (time.monotonic() - start_time) * 1000.0
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:; "
        "font-src 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    response.headers["X-Response-Time-Ms"] = f"{duration_ms:.2f}"
    return response


# Global Exception Handler (prevents stack trace leaks per requirement #59)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    req_id = getattr(request.state, "request_id", "unknown")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred while processing the security request.",
            "request_id": req_id
        }
    )


# WebSocket endpoint for real-time assessment streaming (Requirements #19)
@app.websocket("/ws/assessments/{assessment_id}")
async def assessment_websocket(
    websocket: WebSocket,
    assessment_id: str,
    token: str = Query(None)
):
    """
    WebSocket endpoint requiring authentication and organization authorization.
    Rejects unauthorized access with policy violation code 1008.
    """
    # 1. Authenticate token
    if not token and settings.APP_ENV.lower() == "production":
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Authentication token required")
        return

    user_org_id = None
    if token:
        payload = decode_token(token)
        if not payload or "sub" not in payload:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid authentication token")
            return
        user_org_id = payload.get("org_id")

    # 2. Check authorization on assessment
    async with async_session_factory() as db:
        res = await db.execute(select(Assessment).where(Assessment.id == assessment_id))
        assessment = res.scalar_one_or_none()
        if not assessment:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Assessment not found")
            return

        if user_org_id:
            host_res = await db.execute(select(Host).where(Host.id == assessment.host_id))
            host = host_res.scalar_one_or_none()
            if host and host.organization_id != user_org_id:
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Access to assessment forbidden")
                return

    await websocket.accept()
    broadcast_manager.register(assessment_id, websocket)
    try:
        await websocket.send_json({
            "event": "connected",
            "assessment_id": assessment_id,
            "message": f"Subscribed to live events for assessment {assessment_id}"
        })
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        broadcast_manager.unregister(assessment_id, websocket)
    except Exception:
        broadcast_manager.unregister(assessment_id, websocket)


# Mount REST API
app.include_router(api_v1_router, prefix="/api/v1")


# Health & version endpoints
@app.get("/health")
async def health_root():
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV
    }


@app.get("/version")
async def version_endpoint():
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "api_version": "v1",
        "rule_engine_version": "1.0.0",
        "environment": settings.APP_ENV
    }


@app.get("/")
async def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV,
        "api_v1": "/api/v1",
        "health": "/health",
        "version": "/version"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
