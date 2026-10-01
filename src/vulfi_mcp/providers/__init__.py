"""External reverse-engineering providers, reached over MCP under supervision.

:mod:`~vulfi_mcp.providers.config` decides what may be launched and which bytes
may be analysed; :mod:`~vulfi_mcp.providers.client` opens the session, enforces
the adapter's tool allowlist and the pinned schemas, and converts a provider's
stated facts into the contexts :func:`vulfi_mcp.ida_runtime.evaluate_rule`
already knows how to judge. Backend adapters live beside them and own their own
tool maps.

Nothing here publishes a provider's tools, descriptions or raw text to an
agent, and nothing here treats a provider's words as anything but data.
"""

from __future__ import annotations

from vulfi_mcp.providers.client import (
    CapabilityUnavailableError,
    ForbiddenToolError,
    ProviderArgumentError,
    ProviderCallError,
    ProviderError,
    ProviderEvidenceError,
    ProviderIdentityError,
    ProviderResponseError,
    ProviderSession,
    ProviderUnavailableError,
    UNCLASSIFIED_KEYWORDS,
    checked_call,
    provider_session,
    rule_contexts,
    tool_fingerprint,
)
from vulfi_mcp.providers.config import (
    CONFIG_FILENAME,
    FORBIDDEN_TOOLS,
    PROVIDER_BACKENDS,
    PROVIDER_CONFIG_ENV,
    AttestConfig,
    PathMapping,
    ProviderConfig,
    ProviderConfigError,
    ProviderLimits,
    load_provider_config,
)

__all__ = [
    "AttestConfig",
    "CONFIG_FILENAME",
    "CapabilityUnavailableError",
    "FORBIDDEN_TOOLS",
    "ForbiddenToolError",
    "PROVIDER_BACKENDS",
    "PROVIDER_CONFIG_ENV",
    "PathMapping",
    "ProviderArgumentError",
    "ProviderCallError",
    "ProviderConfig",
    "ProviderConfigError",
    "ProviderError",
    "ProviderEvidenceError",
    "ProviderIdentityError",
    "ProviderLimits",
    "ProviderResponseError",
    "ProviderSession",
    "ProviderUnavailableError",
    "UNCLASSIFIED_KEYWORDS",
    "checked_call",
    "load_provider_config",
    "provider_session",
    "rule_contexts",
    "tool_fingerprint",
]
