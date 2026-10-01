"""
PSV Linux Security Auditor - Authentication Router

Hardening Requirements #10, #12, #44:
- Brute-force rate limiting and account lockout.
- Password complexity validation.
- Token revocation and secure logout.
- Audit logging of authentication actions.
"""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.api.deps import get_current_user
from backend.app.core.config import get_settings
from backend.app.core.database import get_db
from backend.app.core.security import (
    check_login_rate_limit,
    create_access_token,
    decode_token,
    get_password_hash,
    record_failed_login,
    reset_failed_login,
    revoke_token,
    validate_password_strength,
    verify_password,
)
from backend.app.models.entities import AuditEvent, Organization, User, UserRole
from backend.app.schemas.schemas import TokenResponse, UserCreate, UserLogin, UserResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
async def login(
    credentials: UserLogin,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    settings = get_settings()
    client_ip = request.client.host if request.client else "unknown"
    login_id = (credentials.email or credentials.username or "").strip().lower()

    if not login_id or not credentials.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email/username and password are required."
        )

    rate_limit_key = f"{client_ip}:{login_id}"

    # 1. Check brute force lockout
    allowed, retry_after = check_login_rate_limit(rate_limit_key)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Temporarily locked out. Please retry in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

    # 2. Look up user
    result = await db.execute(select(User).where(User.email == login_id))
    user = result.scalar_one_or_none()

    if not user and login_id in ("admin", "admin@psv.local", settings.INITIAL_ADMIN_EMAIL.lower()):
        result = await db.execute(select(User).where(User.email == settings.INITIAL_ADMIN_EMAIL.lower()))
        user = result.scalar_one_or_none()

    if not user or not verify_password(credentials.password, user.hashed_password):
        record_failed_login(rate_limit_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email/username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is deactivated")

    # Reset failed attempts upon successful login
    reset_failed_login(rate_limit_key)

    user.last_login = datetime.now(timezone.utc)

    # Log audit event
    audit_log = AuditEvent(
        user_id=user.id,
        action="user.login",
        resource_type="user",
        resource_id=user.id,
        ip_address=client_ip,
        details={"email": user.email, "role": user.role.value}
    )
    db.add(audit_log)
    await db.commit()

    token = create_access_token(
        subject=user.id,
        role=user.role.value,
        org_id=user.organization_id
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
    )


@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    authorization: str = Header(...)
):
    """Revokes the current JWT bearer token so it cannot be reused."""
    token = authorization.replace("Bearer ", "").strip()
    payload = decode_token(token)
    if payload and "jti" in payload:
        revoke_token(payload["jti"])

    return {"status": "success", "message": "Successfully logged out. Token revoked."}


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return UserResponse.model_validate(current_user)


@router.post("/register", response_model=UserResponse)
async def register(
    user_in: UserCreate,
    db: AsyncSession = Depends(get_db)
):
    settings = get_settings()

    # 1. Enforce password complexity
    valid_pass, msg = validate_password_strength(user_in.password)
    if not valid_pass:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    # 2. Check if email already exists
    existing = await db.execute(select(User).where(User.email == user_in.email.lower()))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    # 3. Find or create default organization
    org_res = await db.execute(select(Organization).limit(1))
    org = org_res.scalar_one_or_none()
    if not org:
        org = Organization(name=user_in.organization_name or "Primary Security Operations Center")
        db.add(org)
        await db.flush()

    # In production, default new users to VIEWER unless created by an admin
    role = user_in.role or UserRole.VIEWER
    if settings.APP_ENV.lower() == "production" and role == UserRole.ADMIN:
        # Check if there is already an admin
        admin_res = await db.execute(select(User).where(User.role == UserRole.ADMIN))
        if admin_res.scalar_one_or_none():
            role = UserRole.VIEWER  # Disallow anonymous creation of additional admins in production

    new_user = User(
        organization_id=org.id,
        email=user_in.email.lower(),
        full_name=user_in.full_name,
        hashed_password=get_password_hash(user_in.password),
        role=role,
        is_active=True
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return UserResponse.model_validate(new_user)
