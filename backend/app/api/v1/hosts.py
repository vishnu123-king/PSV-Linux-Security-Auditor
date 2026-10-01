"""
PSV Linux Security Auditor - Hosts Management Router

Hardening Requirements #8, #13, #14, #25, #26:
- Enforce network target validation (block SSRF, cloud metadata, newline injection).
- Strict RBAC: VIEWER can view, OPERATOR can test, ADMIN can onboard/delete.
- IDOR Protection: Scoped strictly to authenticated user's organization.
"""

import time
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.api.deps import get_current_user, require_role, verify_org_ownership
from backend.app.core.database import get_db
from backend.app.engine.ssh import SSHExecutionContext
from backend.app.models.entities import AuditEvent, CredentialReference, Host, Organization, User, UserRole
from backend.app.schemas.schemas import HostCreate, HostResponse, HostTestResult, HostUpdate
from backend.app.security.network_validation import TargetValidationError, validate_network_target

router = APIRouter(prefix="/hosts", tags=["Hosts"])


@router.get("", response_model=List[HostResponse])
async def list_hosts(
    environment: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.VIEWER))
):
    query = select(Host).where(Host.organization_id == current_user.organization_id).order_by(Host.created_at.desc())
    if environment:
        query = query.where(Host.environment == environment)
    result = await db.execute(query)
    hosts = result.scalars().all()
    return [HostResponse.model_validate(h) for h in hosts]


@router.post("", response_model=HostResponse, status_code=status.HTTP_201_CREATED)
async def create_host(
    host_in: HostCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    # 1. Enforce network target validation & SSRF prevention (Requirements #25, #26)
    try:
        clean_hostname = validate_network_target(
            hostname=host_in.hostname,
            port=host_in.port,
            allow_loopback=bool(host_in.tags.get("simulated", False) or host_in.tags.get("test", False))
        )
    except TargetValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    cred_id = host_in.credential_id
    # Create inline credential reference if user provided private_key or password
    if not cred_id and (host_in.private_key or host_in.password):
        auth_type = "ssh_key" if host_in.private_key else "password"
        secret_content = host_in.private_key if host_in.private_key else host_in.password
        cred = CredentialReference(
            name=f"Cred for {host_in.name}",
            auth_type=auth_type,
            username=host_in.username or "root",
            encrypted_secret=secret_content or ""
        )
        db.add(cred)
        await db.flush()
        cred_id = cred.id

    new_host = Host(
        organization_id=current_user.organization_id,
        name=host_in.name,
        hostname=clean_hostname,
        port=host_in.port,
        environment=host_in.environment,
        credential_id=cred_id,
        tags=host_in.tags,
        is_active=True
    )
    db.add(new_host)
    await db.flush()

    audit_log = AuditEvent(
        user_id=current_user.id,
        action="host.created",
        resource_type="host",
        resource_id=new_host.id,
        details={"name": new_host.name, "hostname": clean_hostname, "port": new_host.port}
    )
    db.add(audit_log)
    await db.commit()
    await db.refresh(new_host)

    return HostResponse.model_validate(new_host)


@router.get("/{host_id}", response_model=HostResponse)
async def get_host(
    host_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.VIEWER))
):
    result = await db.execute(select(Host).where(Host.id == host_id))
    host = result.scalar_one_or_none()
    if not host:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")
    verify_org_ownership(host.organization_id, current_user)
    return HostResponse.model_validate(host)


@router.put("/{host_id}", response_model=HostResponse)
async def update_host(
    host_id: str,
    host_in: HostUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    result = await db.execute(select(Host).where(Host.id == host_id))
    host = result.scalar_one_or_none()
    if not host:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")
    verify_org_ownership(host.organization_id, current_user)

    if host_in.name is not None:
        host.name = host_in.name
    if host_in.hostname is not None:
        try:
            host.hostname = validate_network_target(
                hostname=host_in.hostname,
                port=host.port,
                allow_loopback=bool(host.tags.get("simulated", False))
            )
        except TargetValidationError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    if host_in.port is not None:
        host.port = host_in.port
    if host_in.environment is not None:
        host.environment = host_in.environment
    if host_in.tags is not None:
        host.tags = host_in.tags

    audit_log = AuditEvent(
        user_id=current_user.id,
        action="host.updated",
        resource_type="host",
        resource_id=host.id,
        details={"name": host.name}
    )
    db.add(audit_log)
    await db.commit()
    await db.refresh(host)
    return HostResponse.model_validate(host)


@router.delete("/{host_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_host(
    host_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    result = await db.execute(select(Host).where(Host.id == host_id))
    host = result.scalar_one_or_none()
    if not host:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")
    verify_org_ownership(host.organization_id, current_user)

    audit_log = AuditEvent(
        user_id=current_user.id,
        action="host.deleted",
        resource_type="host",
        resource_id=host.id,
        details={"name": host.name, "hostname": host.hostname}
    )
    db.add(audit_log)
    await db.delete(host)
    await db.commit()
    return None


@router.post("/{host_id}/test", response_model=HostTestResult)
async def test_host_connection(
    host_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.OPERATOR))
):
    result = await db.execute(select(Host).where(Host.id == host_id))
    host = result.scalar_one_or_none()
    if not host:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")
    verify_org_ownership(host.organization_id, current_user)

    # If simulated target tag is set, return synthetic test response
    if host.tags.get("simulated") is True:
        return HostTestResult(
            success=True,
            latency_ms=1.45,
            message="Simulated SSH authentication and banner handshake succeeded.",
            banner="SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"
        )

    # Retrieve credential if linked
    private_keys = []
    password = None
    username = "root"

    if host.credential_id:
        cred_res = await db.execute(select(CredentialReference).where(CredentialReference.id == host.credential_id))
        cred = cred_res.scalar_one_or_none()
        if cred:
            username = cred.username
            if cred.auth_type == "ssh_key":
                private_keys.append(cred.encrypted_secret)
            else:
                password = cred.encrypted_secret

    ssh_ctx = SSHExecutionContext(
        hostname=host.hostname,
        port=host.port,
        username=username,
        client_keys=private_keys,
        password=password,
        known_hosts="ignore" if host.tags.get("test") else "known_hosts",
        connect_timeout=10
    )

    start_time = time.monotonic()
    try:
        await ssh_ctx.connect()
        latency = (time.monotonic() - start_time) * 1000.0
        uname_res = await ssh_ctx.run_command("system.uname")
        await ssh_ctx.close()

        banner = uname_res.get("stdout", "").strip() or "SSH-2.0-OpenSSH"
        return HostTestResult(
            success=True,
            latency_ms=round(latency, 2),
            message="SSH authentication and handshake successful.",
            banner=banner
        )
    except Exception as e:
        latency = (time.monotonic() - start_time) * 1000.0
        await ssh_ctx.close()
        return HostTestResult(
            success=False,
            latency_ms=round(latency, 2),
            message=f"SSH connection failed: {str(e)}"
        )
