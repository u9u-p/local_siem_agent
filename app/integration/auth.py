import base64
from typing import Protocol

import httpx


class AuthStrategy(Protocol):
    def get_headers(self) -> dict[str, str]: ...
    def refresh(self) -> None: ...


class BasicAuthStrategy:
    def __init__(self, username: str, password: str) -> None:
        self._username = username
        self._password = password

    def get_headers(self) -> dict[str, str]:
        token = base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
        return {"Authorization": f"Basic {token}"}

    def refresh(self) -> None:
        pass  # static credentials, nothing to refresh


class JWTBearerAuthStrategy:
    def __init__(self, client: httpx.Client, username: str, password: str) -> None:
        self._client = client
        self._username = username
        self._password = password
        self._token: str | None = None

    def get_headers(self) -> dict[str, str]:
        if self._token is None:
            self.refresh()
        return {"Authorization": f"Bearer {self._token}"}

    def refresh(self) -> None:
        response = self._client.post("/security/user/authenticate", auth=(self._username, self._password))
        response.raise_for_status()
        self._token = response.json()["data"]["token"]
