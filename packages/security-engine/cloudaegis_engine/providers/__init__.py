"""Provider adapters and the provider factory."""

from __future__ import annotations

from typing import Any, Callable

from cloudaegis_engine.providers.base import (
    CloudProvider,
    ConnectionResult,
    ProviderError,
    ServiceAccessError,
)

ProviderFactory = Callable[[dict[str, Any]], CloudProvider]


def _aws(config: dict[str, Any]) -> CloudProvider:
    from cloudaegis_engine.providers.aws import AWSProvider

    return AWSProvider.from_config(config)


def _demo(config: dict[str, Any]) -> CloudProvider:
    from cloudaegis_engine.providers.demo import DemoProvider

    return DemoProvider.from_config(config)


# New providers (Azure, GCP) register a factory here.
PROVIDERS: dict[str, ProviderFactory] = {
    "aws": _aws,
    "demo": _demo,
}


def create_provider(kind: str, config: dict[str, Any]) -> CloudProvider:
    try:
        factory = PROVIDERS[kind]
    except KeyError as exc:
        raise ProviderError(f"Unsupported provider: {kind}") from exc
    return factory(config)


__all__ = [
    "CloudProvider",
    "ConnectionResult",
    "PROVIDERS",
    "ProviderError",
    "ServiceAccessError",
    "create_provider",
]
