"""
PSV Linux Security Auditor - Authentication & Authorization Dependencies

Hardening Requirements #13, #14:
- Mandatory authentication in production mode.
- 4-Tier RBAC enforcement (VIEWER, OPERATOR, SECURITY_ANALYST, ADMIN).
- Scoping and IDOR protection: verifies organization ownership of targets and assessments.
"""

from typing import Optional
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.core.config import get_settings
from backend.app.core.database import get_db
from backend.app.core.security import decode_token
from backend.app.models.entities import User, UserRole

security_scheme = HTTPBearer(auto_error=False)


async def get_current_user_optional(
    auth: Optional[HTTPAuthorizationCredentials] = Security(security_scheme),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    if not auth:
        return None
    token = auth.credentials
    payload = decode_token(token)
    if not payload or "sub" not in payload:
        return None
    user_id = payload["sub"]
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    return user


async def get_current_user(
    auth: Optional[HTTPAuthorizationCredentials] = Security(security_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    settings = get_settings()

    if not auth:
        # In development/test mode, fallback to default admin if unauthenticated
        if settings.APP_ENV.lower() in ("development", "test"):
            result = await db.execute(select(User).where(User.role == UserRole.ADMIN).limit(1))
            admin = result.scalar_one_or_none()
            if admin:
                return admin

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await get_current_user_optional(auth, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, revoked, or expired authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is deactivated")
    return user


def require_role(min_role: UserRole):
    """RBAC authorization gatekeeper enforcing minimum privileges."""
    role_weights = {
        UserRole.VIEWER: 1,
        UserRole.OPERATOR: 2,
        UserRole.SECURITY_ANALYST: 3,
        UserRole.ADMIN: 4,
    }

    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        user_weight = role_weights.get(current_user.role, 0)
        req_weight = role_weights.get(min_role, 0)
        if user_weight < req_weight:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires minimum role '{min_role.value}', current user has '{current_user.role.value}'"
            )
        return current_user

    return role_checker


def verify_org_ownership(resource_org_id: str, current_user: User) -> None:
    """IDOR safeguard: ensures authenticated user belongs to the resource's organization."""
    if resource_org_id != current_user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Requested resource was not found."
        )
