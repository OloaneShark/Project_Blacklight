from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ScannerSpec:
    provider: str
    name: str
    scanner_cls: type[Any]


_REGISTRY: dict[str, dict[str, ScannerSpec]] = defaultdict(dict)
_BUILTINS_LOADED = False


def register_scanner(provider: str, name: str, scanner_cls: type[Any]) -> None:
    provider_key = provider.strip().lower()
    name_key = name.strip().lower()
    if not provider_key or not name_key:
        raise ValueError("provider and scanner name are required")
    if name_key in _REGISTRY[provider_key]:
        raise ValueError(f"scanner already registered: {provider_key}.{name_key}")
    _REGISTRY[provider_key][name_key] = ScannerSpec(provider_key, name_key, scanner_cls)


def load_builtin_scanners() -> None:
    global _BUILTINS_LOADED
    if _BUILTINS_LOADED:
        return

    from blacklight_security.scanners.aws import (
        CloudTrailScanner,
        EC2Scanner,
        IAMScanner,
        RDSScanner,
        S3Scanner,
    )

    for name, scanner_cls in {
        "s3": S3Scanner,
        "iam": IAMScanner,
        "cloudtrail": CloudTrailScanner,
        "ec2": EC2Scanner,
        "rds": RDSScanner,
    }.items():
        register_scanner("aws", name, scanner_cls)

    _BUILTINS_LOADED = True


def scanner_names(provider: str) -> list[str]:
    load_builtin_scanners()
    return sorted(_REGISTRY.get(provider.lower(), {}))


def scanner_specs(provider: str, selected: str = "all") -> list[ScannerSpec]:
    load_builtin_scanners()
    provider_key = provider.lower()
    provider_scanners = _REGISTRY.get(provider_key, {})

    if selected == "all":
        return [provider_scanners[name] for name in sorted(provider_scanners)]

    try:
        return [provider_scanners[selected.lower()]]
    except KeyError as exc:
        raise KeyError(f"unknown scanner: {provider_key}.{selected}") from exc
