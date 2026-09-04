from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    PASS = "PASS"
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"


@dataclass(slots=True)
class Finding:
    """A normalized security finding returned by a Blacklight scanner."""

    check_id: str
    provider: str
    service: str
    resource_type: str
    resource_id: str
    severity: Severity
    title: str
    description: str
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data
