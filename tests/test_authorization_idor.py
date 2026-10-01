"""
Tests for RBAC and IDOR Protection (Requirements #13, #14)

Verifies:
- VIEWER cannot execute admin operations
- Organization isolation: User from Org A cannot access resources from Org B
"""

import pytest
from fastapi import HTTPException
from backend.app.api.deps import require_role, verify_org_ownership
from backend.app.models.entities import User, UserRole


def test_rbac_role_hierarchy():
    viewer = User(id="u1", role=UserRole.VIEWER, is_active=True, organization_id="org1")
    operator = User(id="u2", role=UserRole.OPERATOR, is_active=True, organization_id="org1")
    admin = User(id="u3", role=UserRole.ADMIN, is_active=True, organization_id="org1")

    # Viewer checking admin permission
    admin_checker = require_role(UserRole.ADMIN)

    import asyncio
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(admin_checker(viewer))
    assert exc_info.value.status_code == 403

    # Operator checking admin permission
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(admin_checker(operator))
    assert exc_info.value.status_code == 403

    # Admin checking admin permission -> passes
    result = asyncio.run(admin_checker(admin))
    assert result.id == "u3"


def test_idor_cross_organization_access_denied():
    user_org_a = User(id="u1", role=UserRole.ADMIN, is_active=True, organization_id="org-alpha")

    # Resource in same org -> allowed
    verify_org_ownership("org-alpha", user_org_a)

    # Resource in different org -> 404 (prevent resource enumeration)
    with pytest.raises(HTTPException) as exc_info:
        verify_org_ownership("org-beta", user_org_a)
    assert exc_info.value.status_code == 404
