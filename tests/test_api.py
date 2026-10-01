import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_and_ready_endpoints(client: AsyncClient):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "version" in data


@pytest.mark.asyncio
async def test_rules_api(client: AsyncClient):
    resp = await client.get("/api/v1/rules")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) >= 50
    # Verify rule structure
    rule_ids = {r["id"] for r in rules}
    assert "SSH-001" in rule_ids
    assert "ID-001" in rule_ids
    assert "SUDO-001" in rule_ids


@pytest.mark.asyncio
async def test_host_lifecycle(client: AsyncClient):
    # 1. Create Host
    create_resp = await client.post(
        "/api/v1/hosts",
        json={
            "name": "Integration Test Target",
            "hostname": "127.0.0.1",
            "port": 22,
            "environment": "staging",
            "tags": {"test": True}
        }
    )
    assert create_resp.status_code == 201
    host = create_resp.json()
    host_id = host["id"]

    # 2. Get Host
    get_resp = await client.get(f"/api/v1/hosts/{host_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["name"] == "Integration Test Target"

    # 3. Test Host
    test_resp = await client.post(f"/api/v1/hosts/{host_id}/test")
    assert test_resp.status_code == 200
    assert test_resp.json()["success"] is True
