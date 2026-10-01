from pathlib import Path
from typing import Any, Dict, List, Set, Tuple
import yaml
from backend.app.core.config import get_settings


class RuleLoader:
    def __init__(self, rules_dir: str = "./rules") -> None:
        self.rules_dir = Path(rules_dir)
        self._rules_cache: List[Dict[str, Any]] = []
        self._control_collector_map: Dict[str, str] = {}
        self._load_control_mappings()

    def _load_control_mappings(self) -> None:
        """Explicit map of control prefixes to collector names."""
        self._prefix_map = {
            "system.": "system",
            "identity.": "identity",
            "ssh.": "ssh",
            "sudo.": "sudo",
            "filesystem.": "filesystem",
            "network.": "networking",
            "firewall.": "firewall",
            "services.": "services",
            "kernel.": "kernel",
            "pam.": "pam",
            "logging.": "logging",
            "containers.": "containers",
        }

    def get_collector_for_control(self, control: str) -> str:
        for prefix, collector in self._prefix_map.items():
            if control.startswith(prefix):
                return collector
        return "system"

    def load_all_rules(self) -> List[Dict[str, Any]]:
        """Loads and parses all YAML rules from the rules directory."""
        rules = []
        if not self.rules_dir.exists():
            return rules

        for yaml_file in sorted(self.rules_dir.glob("*.yaml")):
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    content = yaml.safe_load(f)
                    if isinstance(content, list):
                        for rule in content:
                            if isinstance(rule, dict) and "id" in rule and "control" in rule:
                                control = rule["control"]
                                self._control_collector_map[control] = self.get_collector_for_control(control)
                                rules.append(rule)
            except Exception as e:
                pass

        self._rules_cache = rules
        return rules

    def get_control_collector_map(self) -> Dict[str, str]:
        if not self._control_collector_map:
            self.load_all_rules()
        return self._control_collector_map


rule_loader = RuleLoader()
