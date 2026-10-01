from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from backend.app.collectors.registry import SAFE_COMMAND_REGISTRY, SafeCommand


@dataclass
class ObservationData:
    category: str
    control: str
    value: Any
    source: str
    command_executed: Optional[str] = None
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "control": self.control,
            "value": self.value,
            "source": self.source,
            "command_executed": self.command_executed,
            "collected_at": self.collected_at.isoformat()
        }


@dataclass
class CollectorResult:
    collector_name: str
    success: bool
    observations: List[ObservationData] = field(default_factory=list)
    raw_evidence: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    duration_ms: float = 0.0


class ExecutionContext(ABC):
    """Execution abstraction over SSH connector or local test target."""

    @abstractmethod
    async def read_file(self, path: str, max_bytes: int = 262144) -> Optional[str]:
        """Safely reads file content if it exists. Returns None if file does not exist or unreadable."""
        pass

    @abstractmethod
    async def run_command(self, command_id: str) -> Dict[str, Any]:
        """Runs a safe, registered command by identifier. Returns {'stdout': str, 'stderr': str, 'exit_code': int}."""
        pass

    @abstractmethod
    def get_target_metadata(self) -> Dict[str, Any]:
        """Returns metadata such as hostname, IP, detected OS family."""
        pass


class BaseCollector(ABC):
    """
    Abstract base class for security facts collectors.

    Rule: Collectors gather raw facts only. They do not evaluate or judge security.
    """
    name: str = "base"
    category: str = "general"
    description: str = "Base Security Collector"

    @abstractmethod
    async def collect(self, ctx: ExecutionContext) -> CollectorResult:
        """Collect facts and return raw observations and evidence."""
        pass
