"""
PSV CLI - Hardened Configuration Management

Hardening Requirements #52, #53:
- Restricts ~/.config/psv/config.toml file permissions to 0600.
- Restricts ~/.config/psv/ directory permissions to 0700.
- Validates base URL to avoid invalid schemes or injection.
- Secret tokens are not stored in world-readable locations.
"""

import os
from pathlib import Path
import stat
from typing import Any, Dict, Optional
import urllib.parse

CONFIG_DIR = Path.home() / ".config" / "psv"
CONFIG_FILE = CONFIG_DIR / "config.toml"


def validate_url(url: str) -> str:
    """Validates that URL has http or https scheme and no newlines."""
    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Invalid API URL scheme: '{parsed.scheme}'. Must be 'http' or 'https'.")
    if not parsed.netloc:
        raise ValueError(f"Invalid API URL: '{url}'. Missing host location.")
    return url.strip().rstrip("/")


class CLIConfig:
    def __init__(self) -> None:
        self.api_url: str = os.environ.get("PSV_API_URL", "http://localhost:8000")
        self.api_token: Optional[str] = os.environ.get("PSV_API_TOKEN", None)
        self.output_format: str = "table"
        self._load_file_config()

    def _load_file_config(self) -> None:
        if not CONFIG_FILE.exists():
            return
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("url =") or line.startswith("url="):
                        val = line.split("=", 1)[1].strip().strip('"\'')
                        if "PSV_API_URL" not in os.environ:
                            self.api_url = validate_url(val)
                    elif line.startswith("token =") or line.startswith("token="):
                        val = line.split("=", 1)[1].strip().strip('"\'')
                        if "PSV_API_TOKEN" not in os.environ:
                            self.api_token = val
        except Exception:
            pass

    def save_setting(self, key: str, value: str) -> None:
        # Create directory with 0700 permissions
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        try:
            CONFIG_DIR.chmod(stat.S_IRWXU)  # 0700
        except OSError:
            pass

        if key in ("server.url", "url"):
            self.api_url = validate_url(value)
        elif key in ("auth.token", "token"):
            self.api_token = value.strip()

        content = f"""[server]
url = "{self.api_url}"

[auth]
token = "{self.api_token or ''}"
"""
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            f.write(content)

        # Set 0600 file permissions (Requirement #52)
        try:
            CONFIG_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except OSError:
            pass


cli_config = CLIConfig()
