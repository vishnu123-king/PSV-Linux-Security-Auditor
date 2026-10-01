from typing import Dict, List, Type
from backend.app.collectors.base import BaseCollector, CollectorResult, ExecutionContext, ObservationData
from backend.app.collectors.system import SystemCollector
from backend.app.collectors.identity import IdentityCollector
from backend.app.collectors.ssh import SSHCollector
from backend.app.collectors.sudo import SudoCollector
from backend.app.collectors.filesystem import FilesystemCollector
from backend.app.collectors.networking import NetworkingCollector
from backend.app.collectors.firewall import FirewallCollector
from backend.app.collectors.services import ServicesCollector
from backend.app.collectors.kernel import KernelCollector
from backend.app.collectors.pam import PAMCollector
from backend.app.collectors.logging import LoggingCollector
from backend.app.collectors.containers import ContainersCollector

ALL_COLLECTOR_CLASSES: List[Type[BaseCollector]] = [
    SystemCollector,
    IdentityCollector,
    SSHCollector,
    SudoCollector,
    FilesystemCollector,
    NetworkingCollector,
    FirewallCollector,
    ServicesCollector,
    KernelCollector,
    PAMCollector,
    LoggingCollector,
    ContainersCollector
]


def get_all_collectors() -> List[BaseCollector]:
    return [cls() for cls in ALL_COLLECTOR_CLASSES]


def get_collector_by_name(name: str) -> BaseCollector:
    for cls in ALL_COLLECTOR_CLASSES:
        if cls.name == name:
            return cls()
    raise ValueError(f"Unknown collector '{name}'")


__all__ = [
    "BaseCollector",
    "CollectorResult",
    "ExecutionContext",
    "ObservationData",
    "SystemCollector",
    "IdentityCollector",
    "SSHCollector",
    "SudoCollector",
    "FilesystemCollector",
    "NetworkingCollector",
    "FirewallCollector",
    "ServicesCollector",
    "KernelCollector",
    "PAMCollector",
    "LoggingCollector",
    "ContainersCollector",
    "ALL_COLLECTOR_CLASSES",
    "get_all_collectors",
    "get_collector_by_name",
]
