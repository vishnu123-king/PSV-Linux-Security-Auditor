from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.core.database import get_db
from backend.app.engine.rule_loader import rule_loader
from backend.app.models.entities import Profile
from backend.app.schemas.schemas import ProfileCreate, ProfileResponse

router = APIRouter(prefix="/profiles", tags=["Profiles"])

# Baseline built-in profiles
BUILTIN_PROFILES = [
    {
        "id": "cis-linux-server",
        "name": "CIS Linux Server Benchmark (Level 1)",
        "description": "Standard production hardening profile intended for physical and virtual enterprise Linux servers",
        "is_system_default": True,
        "rule_count": 60
    },
    {
        "id": "cis-linux-workstation",
        "name": "CIS Linux Workstation Benchmark",
        "description": "Hardening profile tailored for engineer laptops and interactive developer workstations",
        "is_system_default": False,
        "rule_count": 45
    },
    {
        "id": "essential-eight-hardened",
        "name": "Essential Eight Server Baseline",
        "description": "Strict isolation profile focusing on application whitelisting, macro controls, and privilege restriction",
        "is_system_default": False,
        "rule_count": 52
    },
    {
        "id": "minimal-audit",
        "name": "Minimal Fast Triage Audit",
        "description": "Rapid audit evaluating only Critical and High severity root accounts, SSH, and firewall checks",
        "is_system_default": False,
        "rule_count": 18
    }
]


@router.get("", response_model=List[ProfileResponse])
async def list_profiles(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Profile))
    db_profiles = result.scalars().all()

    # Merge built-ins with db records
    found_ids = {p.id for p in db_profiles}
    combined = list(db_profiles)

    for bp in BUILTIN_PROFILES:
        if bp["id"] not in found_ids:
            p = Profile(
                id=bp["id"],
                name=bp["name"],
                description=bp["description"],
                is_system_default=bp["is_system_default"]
            )
            db.add(p)
            combined.append(p)

    await db.commit()

    return [
        ProfileResponse(
            id=p.id,
            name=p.name,
            description=p.description,
            is_system_default=p.is_system_default,
            rule_count=60 if "server" in p.id else 45,
            created_at=p.created_at
        )
        for p in combined
    ]


@router.get("/{profile_id}", response_model=ProfileResponse)
async def get_profile(profile_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Profile).where(Profile.id == profile_id))
    profile = result.scalar_one_or_none()
    if not profile:
        for bp in BUILTIN_PROFILES:
            if bp["id"] == profile_id:
                return ProfileResponse(
                    id=bp["id"],
                    name=bp["name"],
                    description=bp["description"],
                    is_system_default=bp["is_system_default"],
                    rule_count=bp["rule_count"],
                    created_at="2026-01-01T00:00:00Z"
                )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Profile '{profile_id}' not found")

    return ProfileResponse(
        id=profile.id,
        name=profile.name,
        description=profile.description,
        is_system_default=profile.is_system_default,
        rule_count=60,
        created_at=profile.created_at
    )
