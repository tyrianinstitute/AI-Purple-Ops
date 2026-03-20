"""Target profile system for AI security assessments.

A target profile is the single source of truth for connecting to and testing
an AI system. It captures endpoint, auth, model config, rate limits, and
session management in one YAML file that can drive any orchestrated tool.

Designed from research across Promptfoo, PyRIT, Inspect AI, and Ghostwriter
config schemas to be a superset that projects into each tool's native format.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class TLSConfig:
    """TLS and mTLS configuration."""

    mode: str = "default"  # default | mtls
    ca_bundle_path: str | None = None
    client_cert_path: str | None = None
    client_key_path: str | None = None
    reject_unauthorized: bool = True


@dataclass
class AuthConfig:
    """Authentication configuration. Secrets reference env vars, never stored inline."""

    mode: str = "api_key"  # api_key | bearer | basic | oauth2_client_credentials | azure_entra | none

    # API key / bearer
    api_key_env: str = "OPENAI_API_KEY"
    api_key_placement: str = "header"  # header | query
    api_key_header: str = "Authorization"
    api_key_format: str = "bearer"  # bearer | raw

    # OAuth2 client credentials
    oauth2_token_url: str | None = None
    oauth2_client_id_env: str | None = None
    oauth2_client_secret_env: str | None = None
    oauth2_scopes: list[str] = field(default_factory=list)

    # Azure Entra
    azure_method: str | None = None  # azure_cli | service_principal | managed_identity
    azure_tenant_id_env: str | None = None
    azure_client_id_env: str | None = None
    azure_client_secret_env: str | None = None

    def resolve_api_key(self) -> str | None:
        """Resolve the API key from environment."""
        if self.mode in ("api_key", "bearer"):
            return os.environ.get(self.api_key_env)
        return None


@dataclass
class ModelConfig:
    """Model configuration."""

    provider: str = "openai"  # openai | azure_openai | anthropic | ollama | mock | custom_http
    name: str = "gpt-4o"
    deployment: str | None = None  # Azure deployment name
    api_version: str | None = None  # Azure API version

    # Request parameters
    temperature: float | None = None
    max_tokens: int | None = None
    seed: int | None = None


@dataclass
class BudgetConfig:
    """Budget and cost controls."""

    max_cost_usd: float | None = None  # Hard cap on API spend
    max_requests: int | None = None  # Hard cap on total requests
    warn_at_usd: float | None = None  # Warn when spend exceeds this
    warn_at_requests: int | None = None  # Warn when request count exceeds this


@dataclass
class KnowledgeConfig:
    """What the operator knows about the target (black/gray/white box)."""

    system_prompt: str | None = None  # If known, enables extraction tests
    tool_schemas: list[dict[str, Any]] | None = None  # If known, enables ASI02 with real schemas
    architecture: str | None = None  # rag | agent | chatbot | pipeline | unknown
    source_access: bool = False  # White-box: access to model weights or code
    known_guardrails: list[str] | None = None  # If known, skip fingerprinting
    notes: str = ""


@dataclass
class RateLimitConfig:
    """Rate limiting and retry configuration."""

    mode: str = "adaptive"  # adaptive | fixed
    max_concurrency: int = 5
    max_requests_per_minute: int | None = None  # Explicit RPM cap
    max_retries: int = 4
    honor_retry_after: bool = True
    retry_on_status: list[int] = field(default_factory=lambda: [429, 502, 503, 504])
    delay_between_requests_ms: int = 0  # Fixed delay between requests


@dataclass
class SessionConfig:
    """Session management for multi-turn testing."""

    server_side_enabled: bool = False
    server_side_parser: str | None = None  # expression to extract session ID
    client_side_enabled: bool = False
    client_side_strategy: str = "uuid"  # uuid | static
    client_side_header: str = "x-session-id"


@dataclass
class TargetProfile:
    """Complete target profile for an AI system under test."""

    name: str
    description: str = ""
    tags: list[str] = field(default_factory=list)

    # Connection
    base_url: str = ""
    endpoint_path: str = ""
    timeout_seconds: int = 60
    headers: dict[str, str] = field(default_factory=dict)

    # Sub-configs
    tls: TLSConfig = field(default_factory=TLSConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    model: ModelConfig = field(default_factory=ModelConfig)
    rate_limits: RateLimitConfig = field(default_factory=RateLimitConfig)
    budget: BudgetConfig = field(default_factory=BudgetConfig)
    session: SessionConfig = field(default_factory=SessionConfig)
    knowledge: KnowledgeConfig = field(default_factory=KnowledgeConfig)

    # Scope boundaries
    scope_notes: str = ""
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: str | Path) -> TargetProfile:
        """Load target profile from YAML file."""
        path = Path(path)
        with path.open() as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise ValueError(f"Invalid target profile: expected dict, got {type(data).__name__}")

        spec = data.get("spec", data)
        conn = spec.get("connection", {})
        auth_data = spec.get("auth", {})
        model_data = spec.get("model", {})
        rate_data = spec.get("rateLimits", spec.get("rate_limits", {}))
        session_data = spec.get("sessions", spec.get("session", {}))
        tls_data = conn.get("tls", {})
        metadata = data.get("metadata", {})

        return cls(
            name=metadata.get("name", path.stem),
            description=metadata.get("description", ""),
            tags=metadata.get("tags", []),
            base_url=conn.get("baseUrl", conn.get("base_url", "")),
            endpoint_path=conn.get("endpointPath", conn.get("endpoint_path", "")),
            timeout_seconds=conn.get("timeoutSeconds", conn.get("timeout_seconds", 60)),
            headers=conn.get("headers", {}),
            tls=TLSConfig(
                mode=tls_data.get("mode", "default"),
                ca_bundle_path=tls_data.get("caBundlePath", tls_data.get("ca_bundle_path")),
                client_cert_path=tls_data.get("clientCertPath", tls_data.get("client_cert_path")),
                client_key_path=tls_data.get("clientKeyPath", tls_data.get("client_key_path")),
                reject_unauthorized=tls_data.get("rejectUnauthorized", True),
            ),
            auth=AuthConfig(
                mode=auth_data.get("mode", "api_key"),
                api_key_env=auth_data.get("apiKey", {}).get("envVar", auth_data.get("api_key_env", "OPENAI_API_KEY")),
                api_key_placement=auth_data.get("apiKey", {}).get("placement", "header"),
                api_key_header=auth_data.get("apiKey", {}).get("headerName", "Authorization"),
                api_key_format=auth_data.get("apiKey", {}).get("format", "bearer"),
                oauth2_token_url=auth_data.get("oauth2ClientCredentials", {}).get("tokenUrl"),
                oauth2_client_id_env=auth_data.get("oauth2ClientCredentials", {}).get("clientIdFrom", {}).get("envVar"),
                oauth2_client_secret_env=auth_data.get("oauth2ClientCredentials", {}).get("clientSecretFrom", {}).get("envVar"),
                oauth2_scopes=auth_data.get("oauth2ClientCredentials", {}).get("scopes", []),
                azure_method=auth_data.get("azureEntra", {}).get("method"),
                azure_tenant_id_env=auth_data.get("azureEntra", {}).get("tenantIdFrom", {}).get("envVar"),
                azure_client_id_env=auth_data.get("azureEntra", {}).get("clientIdFrom", {}).get("envVar"),
                azure_client_secret_env=auth_data.get("azureEntra", {}).get("clientSecretFrom", {}).get("envVar"),
            ),
            model=ModelConfig(
                provider=model_data.get("provider", "openai"),
                name=model_data.get("name", "gpt-4o"),
                deployment=model_data.get("deployment"),
                api_version=model_data.get("apiVersion", model_data.get("api_version")),
                temperature=model_data.get("request", {}).get("temperature"),
                max_tokens=model_data.get("request", {}).get("maxTokens", model_data.get("request", {}).get("max_tokens")),
                seed=model_data.get("request", {}).get("seed"),
            ),
            rate_limits=RateLimitConfig(
                mode=rate_data.get("concurrency", {}).get("mode", "adaptive"),
                max_concurrency=rate_data.get("concurrency", {}).get("fixedMax", rate_data.get("concurrency", {}).get("max", 5)),
                max_requests_per_minute=rate_data.get("concurrency", {}).get("rpm"),
                max_retries=rate_data.get("retries", {}).get("maxAttempts", 4),
                honor_retry_after=rate_data.get("retries", {}).get("honorRetryAfter", True),
                retry_on_status=rate_data.get("retries", {}).get("retryOnStatus", [429, 502, 503, 504]),
                delay_between_requests_ms=rate_data.get("delayMs", rate_data.get("delay_between_requests_ms", 0)),
            ),
            budget=BudgetConfig(
                max_cost_usd=spec.get("budget", {}).get("maxCostUsd", spec.get("budget", {}).get("max_cost_usd")),
                max_requests=spec.get("budget", {}).get("maxRequests", spec.get("budget", {}).get("max_requests")),
                warn_at_usd=spec.get("budget", {}).get("warnAtUsd", spec.get("budget", {}).get("warn_at_usd")),
                warn_at_requests=spec.get("budget", {}).get("warnAtRequests"),
            ),
            knowledge=KnowledgeConfig(
                system_prompt=spec.get("knowledge", {}).get("systemPrompt", spec.get("knowledge", {}).get("system_prompt")),
                tool_schemas=spec.get("knowledge", {}).get("toolSchemas", spec.get("knowledge", {}).get("tool_schemas")),
                architecture=spec.get("knowledge", {}).get("architecture"),
                source_access=spec.get("knowledge", {}).get("sourceAccess", spec.get("knowledge", {}).get("source_access", False)),
                known_guardrails=spec.get("knowledge", {}).get("knownGuardrails", spec.get("knowledge", {}).get("known_guardrails")),
                notes=spec.get("knowledge", {}).get("notes", ""),
            ),
            session=SessionConfig(
                server_side_enabled=session_data.get("serverSide", {}).get("enabled", False),
                server_side_parser=session_data.get("serverSide", {}).get("extract", {}).get("parser"),
                client_side_enabled=session_data.get("clientSide", {}).get("enabled", False),
                client_side_strategy=session_data.get("clientSide", {}).get("idStrategy", "uuid"),
                client_side_header=session_data.get("clientSide", {}).get("headerName", "x-session-id"),
            ),
            scope_notes=spec.get("scope", {}).get("notes", ""),
            in_scope=spec.get("scope", {}).get("inScope", []),
            out_of_scope=spec.get("scope", {}).get("outOfScope", []),
        )

    def to_yaml(self, path: str | Path) -> None:
        """Save target profile to YAML file."""
        data = {
            "apiVersion": "aipop/v1",
            "kind": "TargetProfile",
            "metadata": {
                "name": self.name,
                "description": self.description,
                "tags": self.tags,
            },
            "spec": {
                "connection": {
                    "baseUrl": self.base_url,
                    "endpointPath": self.endpoint_path,
                    "timeoutSeconds": self.timeout_seconds,
                    "headers": self.headers,
                    "tls": {"mode": self.tls.mode},
                },
                "auth": {"mode": self.auth.mode},
                "model": {
                    "provider": self.model.provider,
                    "name": self.model.name,
                },
                "rateLimits": {
                    "concurrency": {"mode": self.rate_limits.mode, "max": self.rate_limits.max_concurrency},
                    "retries": {"maxAttempts": self.rate_limits.max_retries},
                },
            },
        }

        # Add auth details based on mode
        if self.auth.mode == "api_key":
            data["spec"]["auth"]["apiKey"] = {"envVar": self.auth.api_key_env, "format": self.auth.api_key_format}
        elif self.auth.mode == "oauth2_client_credentials":
            data["spec"]["auth"]["oauth2ClientCredentials"] = {
                "tokenUrl": self.auth.oauth2_token_url,
                "clientIdFrom": {"valueFrom": "env", "envVar": self.auth.oauth2_client_id_env},
                "clientSecretFrom": {"valueFrom": "env", "envVar": self.auth.oauth2_client_secret_env},
                "scopes": self.auth.oauth2_scopes,
            }

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    def to_adapter_kwargs(self) -> dict[str, Any]:
        """Convert target profile to adapter constructor kwargs."""
        kwargs: dict[str, Any] = {
            "model": self.model.name,
        }
        api_key = self.auth.resolve_api_key()
        if api_key:
            kwargs["api_key"] = api_key
        if self.model.temperature is not None:
            kwargs["temperature"] = self.model.temperature
        if self.model.seed is not None:
            kwargs["seed"] = self.model.seed
        return kwargs
