from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

@dataclass(frozen=True)
class Finding:
    finding_id: str
    severity: str
    title: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    tags: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory = lambda: datetime.now(timezone.utc).isoformat())

@dataclass(frozen=True)
class CoverageNote:
    area: str
    detail: str