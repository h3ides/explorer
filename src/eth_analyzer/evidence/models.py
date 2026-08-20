from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any


class StatementType(str, Enum):
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"
    HYPOTHESIS = "HYPOTHESIS"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


def _freeze(value: Any) -> Any:
    if isinstance(value, MappingProxyType):
        return value
    if isinstance(value, dict):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(v) for v in value)
    if isinstance(value, tuple):
        return tuple(_freeze(v) for v in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, MappingProxyType):
        return {k: _thaw(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [_thaw(v) for v in value]
    return value


def _canonical(value: Any) -> str:
    return json.dumps(_thaw(value), sort_keys=True, separators=(",", ":"), default=str)


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    rpc_method: str
    raw_request: dict[str, Any]
    request_params: list[Any]
    raw_response: dict[str, Any]
    chain_id: str | None = None
    block: str | int | None = None
    transaction_hash: str | None = None
    timestamp: str | int | None = None
    collection_timestamp: float = field(default_factory=time.time)
    provider_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "raw_request", _freeze(self.raw_request))
        object.__setattr__(self, "request_params", _freeze(self.request_params))
        object.__setattr__(self, "raw_response", _freeze(self.raw_response))

    @classmethod
    def from_rpc_result(
        cls,
        result,
        *,
        chain_id: str | None = None,
        block: str | int | None = None,
        transaction_hash: str | None = None,
        timestamp: str | int | None = None,
        provider_id: str | None = None,
    ) -> "EvidenceRecord":
        base = {
            "rpc_method": result.method,
            "raw_request": result.request,
            "request_params": result.params,
            "raw_response": result.response,
            "chain_id": chain_id,
            "block": block,
            "transaction_hash": transaction_hash,
            "timestamp": timestamp,
            "provider_id": provider_id,
        }
        digest = hashlib.sha256(_canonical(base).encode("utf-8")).hexdigest()
        return cls(evidence_id=digest, collection_timestamp=time.time(), **base)

    def to_json(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "rpc_method": self.rpc_method,
            "raw_request": _thaw(self.raw_request),
            "request_params": _thaw(self.request_params),
            "raw_response": _thaw(self.raw_response),
            "chain_id": self.chain_id,
            "block": self.block,
            "transaction_hash": self.transaction_hash,
            "timestamp": self.timestamp,
            "collection_timestamp": self.collection_timestamp,
            "provider_id": self.provider_id,
        }


@dataclass(frozen=True)
class NormalizedObservation:
    observation_id: str
    statement: str
    value: Any
    statement_type: StatementType
    evidence_ids: tuple[str, ...]
    confidence: Confidence | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))
        if self.statement_type is StatementType.HYPOTHESIS and self.confidence is None:
            raise ValueError("hypothesis observations require an explicit confidence")

    def to_json(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "statement": self.statement,
            "value": self.value,
            "statement_type": self.statement_type.value,
            "evidence_ids": list(self.evidence_ids),
            "confidence": self.confidence.value if self.confidence else None,
        }
