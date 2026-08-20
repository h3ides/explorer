from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from .models import EvidenceRecord, NormalizedObservation
from .provenance import ProvenanceRecord


class EvidenceBundle:
    def __init__(self) -> None:
        self.evidence: dict[str, EvidenceRecord] = {}
        self.observations: list[NormalizedObservation] = []
        self.provenance: list[ProvenanceRecord] = []

    def add_evidence(self, record: EvidenceRecord) -> EvidenceRecord:
        existing = self.evidence.get(record.evidence_id)
        if existing is not None and existing != record:
            raise ValueError(f"conflicting evidence record id: {record.evidence_id}")
        self.evidence[record.evidence_id] = record
        return record

    def add_observation(self, obs: NormalizedObservation, prov: ProvenanceRecord) -> None:
        missing = set(obs.evidence_ids) - set(self.evidence)
        if missing:
            raise ValueError(f"observation references missing evidence: {sorted(missing)}")
        if obs.statement != prov.statement or obs.statement_type != prov.statement_type or obs.evidence_ids != prov.evidence_ids:
            raise ValueError("provenance must match the normalized observation it supports")
        self.observations.append(obs)
        self.provenance.append(prov)

    def to_json(self) -> dict[str, Any]:
        return {
            "evidence": [e.to_json() for e in self.evidence.values()],
            "observations": [o.to_json() for o in self.observations],
            "provenance": [p.to_json() for p in self.provenance],
        }

    def write(self, path: str | Path) -> None:
        p = Path(path)
        p.mkdir(parents=True, exist_ok=True)
        data = self.to_json()
        (p / "metadata.json").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        for name in ("code", "balance", "provenance"):
            (p / f"{name}.json").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
