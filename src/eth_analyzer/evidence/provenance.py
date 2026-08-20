from __future__ import annotations
from dataclasses import asdict, dataclass
from typing import Any
from .models import Confidence, StatementType


@dataclass(frozen=True)
class ProvenanceRecord:
    statement: str
    statement_type: StatementType
    evidence_ids: tuple[str, ...]
    confidence: Confidence | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))
        if not self.evidence_ids:
            raise ValueError("provenance requires at least one evidence record")
        if self.statement_type is StatementType.HYPOTHESIS and self.confidence is None:
            raise ValueError("hypothesis provenance requires an explicit confidence")

    def to_json(self) -> dict[str, Any]:
        data = asdict(self)
        data["statement_type"] = self.statement_type.value
        data["confidence"] = self.confidence.value if self.confidence else None
        data["evidence_ids"] = list(self.evidence_ids)
        return data
