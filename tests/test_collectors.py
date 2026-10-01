import pytest
from backend.app.collectors.base import CollectorResult, ExecutionContext
from backend.app.collectors.identity import IdentityCollector
from backend.app.collectors.ssh import SSHCollector
from backend.app.collectors.sudo import SudoCollector
from backend.app.collectors.system import SystemCollector
from backend.app.workers.assessment_worker import SimulatedTargetExecutionContext


@pytest.mark.asyncio
async def test_system_collector():
    ctx = SimulatedTargetExecutionContext()
    collector = SystemCollector()
    result = await collector.collect(ctx)

    assert result.success is True
    assert result.collector_name == "system"
    controls = {obs.control: obs.value for obs in result.observations}
    assert controls["system.os_distribution"] == "ubuntu"
    assert controls["system.os_version"] == "24.04"
    assert controls["system.architecture"] == "x86_64"


@pytest.mark.asyncio
async def test_identity_collector():
    ctx = SimulatedTargetExecutionContext()
    collector = IdentityCollector()
    result = await collector.collect(ctx)

    assert result.success is True
    controls = {obs.control: obs.value for obs in result.observations}
    assert controls["identity.single_uid_zero"] is True
    assert controls["identity.pass_max_days"] == 90
    assert controls["identity.pass_min_days"] == 1


@pytest.mark.asyncio
async def test_ssh_collector():
    ctx = SimulatedTargetExecutionContext()
    collector = SSHCollector()
    result = await collector.collect(ctx)

    assert result.success is True
    controls = {obs.control: obs.value for obs in result.observations}
    assert controls["ssh.permit_root_login"] == "yes"
    assert controls["ssh.password_authentication"] is True
    assert controls["ssh.permit_empty_passwords"] is False
    assert controls["ssh.max_auth_tries"] == 6


@pytest.mark.asyncio
async def test_sudo_collector():
    ctx = SimulatedTargetExecutionContext()
    collector = SudoCollector()
    result = await collector.collect(ctx)

    assert result.success is True
    controls = {obs.control: obs.value for obs in result.observations}
    assert controls["sudo.env_reset"] is True
    assert controls["sudo.secure_path"] is True
    assert controls["sudo.has_wildcard_nopasswd"] is True
