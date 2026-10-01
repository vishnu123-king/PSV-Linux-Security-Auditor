from typing import Any, Dict, List, Optional
import httpx
from psv.config import cli_config
from psv.errors import APIConnectionError, AuthenticationError, CommandExecutionError


class PSVClient:
    def __init__(self, base_url: Optional[str] = None, token: Optional[str] = None) -> None:
        self.base_url = (base_url or cli_config.api_url).rstrip("/")
        self.token = token or cli_config.api_token

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "PSV-CLI/1.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        timeout: float = 30.0
    ) -> Any:
        url = f"{self.base_url}/api/v1{path}"
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json_data,
                    headers=self._headers()
                )

                if response.status_code == 401:
                    raise AuthenticationError("Authentication failed: invalid or expired API token.")
                elif response.status_code >= 400:
                    detail = response.text
                    try:
                        data = response.json()
                        detail = data.get("detail", data.get("message", response.text))
                    except Exception:
                        pass
                    raise CommandExecutionError(f"API Error ({response.status_code}): {detail}")

                if response.status_code == 204:
                    return None
                return response.json()

        except httpx.ConnectError:
            raise APIConnectionError(
                f"Cannot connect to PSV API at {self.base_url}. Ensure the FastAPI server is running with "
                "'uvicorn backend.app.main:app --host 0.0.0.0 --port 8000'."
            )
        except httpx.TimeoutException:
            raise APIConnectionError(f"Request to {url} timed out.")


psv_client = PSVClient()
