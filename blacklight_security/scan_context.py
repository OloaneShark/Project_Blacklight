from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Cloud environment metadata attached to a Blacklight scan."""

    provider: str
    region: str | None
    profile: str | None
    identity_status: str
    account_id: str | None = None
    principal_arn: str | None = None
    user_id: str | None = None
    partition: str | None = None
    identity_error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "region": self.region,
            "profile": self.profile,
            "identity": {
                "status": self.identity_status,
                "account_id": self.account_id,
                "principal_arn": self.principal_arn,
                "user_id": self.user_id,
                "partition": self.partition,
                "error": self.identity_error,
            },
        }


def _partition_from_arn(arn: str | None) -> str | None:
    if not arn:
        return None
    parts = arn.split(":", 2)
    if len(parts) >= 2 and parts[0] == "arn":
        return parts[1] or None
    return None


def resolve_scan_context(provider: str, session: Any) -> ScanContext:
    """Resolve best-effort provider identity metadata without changing cloud resources."""

    normalized_provider = provider.strip().lower()
    region = getattr(session, "region_name", None)
    profile = getattr(session, "profile_name", None)

    if normalized_provider != "aws":
        return ScanContext(
            provider=normalized_provider,
            region=region,
            profile=profile,
            identity_status="NOT_APPLICABLE",
        )

    try:
        identity = session.client("sts").get_caller_identity()
    except (BotoCoreError, ClientError) as error:
        return ScanContext(
            provider=normalized_provider,
            region=region,
            profile=profile,
            identity_status="UNAVAILABLE",
            identity_error=f"{type(error).__name__}: {error}",
        )

    principal_arn = identity.get("Arn")
    return ScanContext(
        provider=normalized_provider,
        region=region,
        profile=profile,
        identity_status="RESOLVED",
        account_id=identity.get("Account"),
        principal_arn=principal_arn,
        user_id=identity.get("UserId"),
        partition=_partition_from_arn(principal_arn),
    )
