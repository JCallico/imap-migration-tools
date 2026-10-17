"""GitHub App authentication: JWT signing with PyJWT and installation tokens minted through ``gh api``.

Installation tokens are held in memory only and refreshed shortly before they expire.
"""

from __future__ import annotations

import os
import stat
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from .gh import Gh, GhError

JWT_LIFETIME_SECONDS = 9 * 60
JWT_CLOCK_SKEW_SECONDS = 60
REFRESH_MARGIN_SECONDS = 5 * 60


class AppAuthError(RuntimeError):
    """Raised when GitHub App credentials are missing, insecure, or rejected."""


def check_private_key_file(path: Path) -> None:
    """Refuse keys that are missing or readable by other users."""
    if not path.is_file():
        raise AppAuthError(f"GitHub App private key not found: {path}")
    if os.name == "posix":
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise AppAuthError(f"GitHub App private key {path} must not be accessible to other users (chmod 600)")


def build_app_jwt(app_id: str, private_key_pem: str, now: float | None = None) -> str:
    """Return a short-lived RS256 JWT identifying the GitHub App."""
    try:
        import jwt
    except ImportError as exc:  # pragma: no cover - dependency guidance
        raise AppAuthError(
            "PyJWT with cryptography is required for GitHub App authentication; "
            "install it with: pip install -r tools/agent_loop/requirements.txt"
        ) from exc
    now = time.time() if now is None else now
    payload = {
        "iat": int(now) - JWT_CLOCK_SKEW_SECONDS,
        "exp": int(now) + JWT_LIFETIME_SECONDS,
        "iss": str(app_id),
    }
    return jwt.encode(payload, private_key_pem, algorithm="RS256")


class AppTokenProvider:
    """Callable returning a valid installation token for use as ``GH_TOKEN``."""

    def __init__(
        self,
        app_id: str,
        installation_id: str,
        private_key_path: Path,
        gh: Gh,
        clock: Callable[[], float] = time.time,
    ):
        self.app_id = str(app_id)
        self.installation_id = str(installation_id)
        self.private_key_path = Path(private_key_path)
        self.gh = gh
        self.clock = clock
        self._token: str | None = None
        self._expires_at = 0.0

    def _jwt(self) -> str:
        check_private_key_file(self.private_key_path)
        return build_app_jwt(self.app_id, self.private_key_path.read_text(encoding="utf-8"), now=self.clock())

    def _app_headers(self) -> list[str]:
        return [f"Authorization: Bearer {self._jwt()}", "Accept: application/vnd.github+json"]

    def app_info(self) -> dict:
        """Return ``GET /app`` for the authenticated App (used to resolve its bot login)."""
        try:
            return self.gh.api("/app", headers=self._app_headers(), authenticated=False) or {}
        except GhError as exc:
            raise AppAuthError(f"GitHub rejected the App JWT: {exc.stderr[:200]}") from exc

    def __call__(self) -> str:
        if self._token is None or self.clock() >= self._expires_at - REFRESH_MARGIN_SECONDS:
            self._mint()
        assert self._token is not None
        return self._token

    def _mint(self) -> None:
        try:
            response = self.gh.api(
                f"/app/installations/{self.installation_id}/access_tokens",
                method="POST",
                headers=self._app_headers(),
                authenticated=False,
            )
        except GhError as exc:
            raise AppAuthError(f"could not create an installation token: {exc.stderr[:200]}") from exc
        if not isinstance(response, dict) or not response.get("token"):
            raise AppAuthError("GitHub returned no installation token")
        self._token = str(response["token"])
        expires = response.get("expires_at")
        try:
            self._expires_at = datetime.fromisoformat(str(expires).replace("Z", "+00:00")).timestamp()
        except ValueError:
            self._expires_at = self.clock() + 50 * 60


def provider_from_config(github_config, gh_runner=None) -> AppTokenProvider | None:
    """Create a token provider when App credentials are configured, otherwise ``None``."""
    values = (github_config.app_id, github_config.installation_id, github_config.private_key_path)
    if not any(values):
        return None
    if not all(values):
        raise AppAuthError(
            "incomplete GitHub App configuration: set app_id, installation_id, and private_key_path "
            "(or AGENT_LOOP_APP_ID, AGENT_LOOP_APP_INSTALLATION_ID, AGENT_LOOP_APP_PRIVATE_KEY_PATH)"
        )
    kwargs = {"runner": gh_runner} if gh_runner is not None else {}
    unauthenticated = Gh(github_config.repo, **kwargs)
    return AppTokenProvider(
        github_config.app_id, github_config.installation_id, github_config.private_key_path, unauthenticated
    )
