"""Auth lifecycle management for target profiles.

Resolves credentials from target profiles without ever storing secrets inline.
Supports: API keys, bearer tokens, OAuth2 client credentials, Azure Entra.
Credential resolution order: explicit env var -> .env file -> interactive prompt (if TTY).
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ResolvedCredentials:
    """Resolved credentials ready for use in requests."""

    headers: dict[str, str]
    query_params: dict[str, str]
    auth_method: str
    expires_at: float | None = None  # Unix timestamp for token expiry

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at


class AuthResolver:
    """Resolves credentials from a target profile's auth config."""

    def __init__(self, auth_config: Any) -> None:
        self.config = auth_config
        self._cached_token: str | None = None
        self._cached_expires: float | None = None

    def resolve(self) -> ResolvedCredentials:
        """Resolve credentials based on auth mode."""
        mode = self.config.mode

        if mode == "none":
            return ResolvedCredentials(headers={}, query_params={}, auth_method="none")

        if mode in ("api_key", "bearer"):
            return self._resolve_api_key()

        if mode == "oauth2_client_credentials":
            return self._resolve_oauth2_client_credentials()

        if mode == "azure_entra":
            return self._resolve_azure_entra()

        if mode == "basic":
            return self._resolve_basic()

        raise ValueError(
            f"Unknown auth mode: {mode}. "
            f"Supported: api_key, bearer, oauth2_client_credentials, azure_entra, basic, none"
        )

    def _resolve_api_key(self) -> ResolvedCredentials:
        """Resolve API key from environment."""
        env_var = self.config.api_key_env
        api_key = os.environ.get(env_var)

        if not api_key:
            raise CredentialError(
                f"API key not found in environment variable '{env_var}'.\n"
                f"Set it with: export {env_var}=your-key-here\n"
                f"Or add it to your .env file."
            )

        headers = {}
        query_params = {}

        if self.config.api_key_placement == "header":
            header_name = self.config.api_key_header
            if self.config.api_key_format == "bearer":
                headers[header_name] = f"Bearer {api_key}"
            else:
                headers[header_name] = api_key
        else:
            query_params["api_key"] = api_key

        return ResolvedCredentials(
            headers=headers,
            query_params=query_params,
            auth_method="api_key",
        )

    def _resolve_oauth2_client_credentials(self) -> ResolvedCredentials:
        """Resolve OAuth2 client credentials and exchange for access token."""
        # Check for cached token
        if self._cached_token and self._cached_expires and time.time() < self._cached_expires:
            return ResolvedCredentials(
                headers={"Authorization": f"Bearer {self._cached_token}"},
                query_params={},
                auth_method="oauth2_client_credentials",
                expires_at=self._cached_expires,
            )

        token_url = self.config.oauth2_token_url
        client_id = os.environ.get(self.config.oauth2_client_id_env or "")
        client_secret = os.environ.get(self.config.oauth2_client_secret_env or "")

        if not all([token_url, client_id, client_secret]):
            missing = []
            if not token_url:
                missing.append("oauth2_token_url in target profile")
            if not client_id:
                missing.append(f"{self.config.oauth2_client_id_env} env var")
            if not client_secret:
                missing.append(f"{self.config.oauth2_client_secret_env} env var")
            raise CredentialError(
                f"OAuth2 client credentials incomplete. Missing: {', '.join(missing)}"
            )

        import requests

        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if self.config.oauth2_scopes:
            data["scope"] = " ".join(self.config.oauth2_scopes)

        try:
            resp = requests.post(token_url, data=data, timeout=30)
            resp.raise_for_status()
            token_data = resp.json()
        except Exception as e:
            raise CredentialError(f"OAuth2 token exchange failed: {e}") from e

        access_token = token_data.get("access_token")
        if not access_token:
            raise CredentialError("OAuth2 response missing access_token")

        expires_in = token_data.get("expires_in", 3600)
        self._cached_token = access_token
        self._cached_expires = time.time() + expires_in - 60  # 60s buffer

        return ResolvedCredentials(
            headers={"Authorization": f"Bearer {access_token}"},
            query_params={},
            auth_method="oauth2_client_credentials",
            expires_at=self._cached_expires,
        )

    def _resolve_azure_entra(self) -> ResolvedCredentials:
        """Resolve Azure Entra (AAD) credentials."""
        method = self.config.azure_method

        if method == "azure_cli":
            return self._resolve_azure_cli()
        elif method == "service_principal":
            return self._resolve_azure_service_principal()
        else:
            raise CredentialError(
                f"Unknown Azure auth method: {method}. "
                f"Supported: azure_cli, service_principal"
            )

    def _resolve_azure_cli(self) -> ResolvedCredentials:
        """Get token via az login (Azure CLI)."""
        import subprocess

        try:
            result = subprocess.run(
                ["az", "account", "get-access-token", "--resource", "https://cognitiveservices.azure.com"],
                capture_output=True, text=True, timeout=30, check=True,
            )
            import json
            token_data = json.loads(result.stdout)
            access_token = token_data["accessToken"]
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            raise CredentialError(
                f"Azure CLI auth failed. Run 'az login' first.\nError: {e}"
            ) from e

        return ResolvedCredentials(
            headers={"Authorization": f"Bearer {access_token}"},
            query_params={},
            auth_method="azure_entra_cli",
        )

    def _resolve_azure_service_principal(self) -> ResolvedCredentials:
        """Get token via service principal client credentials."""
        tenant_id = os.environ.get(self.config.azure_tenant_id_env or "")
        client_id = os.environ.get(self.config.azure_client_id_env or "")
        client_secret = os.environ.get(self.config.azure_client_secret_env or "")

        if not all([tenant_id, client_id, client_secret]):
            raise CredentialError(
                "Azure service principal credentials incomplete. "
                f"Set: {self.config.azure_tenant_id_env}, {self.config.azure_client_id_env}, {self.config.azure_client_secret_env}"
            )

        import requests

        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://cognitiveservices.azure.com/.default",
        }

        try:
            resp = requests.post(token_url, data=data, timeout=30)
            resp.raise_for_status()
            token_data = resp.json()
        except Exception as e:
            raise CredentialError(f"Azure service principal auth failed: {e}") from e

        access_token = token_data.get("access_token")
        if not access_token:
            raise CredentialError("Azure token response missing access_token")

        expires_in = token_data.get("expires_in", 3600)
        return ResolvedCredentials(
            headers={"Authorization": f"Bearer {access_token}"},
            query_params={},
            auth_method="azure_entra_sp",
            expires_at=time.time() + expires_in - 60,
        )

    def _resolve_basic(self) -> ResolvedCredentials:
        """Resolve HTTP Basic auth."""
        import base64

        username = os.environ.get(self.config.api_key_env, "")  # reuse field
        password = os.environ.get("API_PASSWORD", "")

        if not username:
            raise CredentialError("Basic auth username not found in environment")

        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        return ResolvedCredentials(
            headers={"Authorization": f"Basic {encoded}"},
            query_params={},
            auth_method="basic",
        )


class CredentialError(Exception):
    """Error resolving credentials."""
