from __future__ import annotations
import re
from eth_analyzer.evidence import EvidenceBundle, EvidenceRecord, NormalizedObservation, ProvenanceRecord, StatementType, Confidence

ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
HEX_QUANTITY_RE = re.compile(r"^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$")
BLOCK_TAGS = {"latest", "earliest", "pending", "safe", "finalized"}


def validate_address(address: str) -> str:
    if not isinstance(address, str) or not ADDRESS_RE.fullmatch(address):
        raise ValueError(f"invalid Ethereum address: {address}")
    return address.lower()


def validate_block_identifier(block: str | int) -> str | int:
    if isinstance(block, int):
        if block < 0:
            raise ValueError("block number cannot be negative")
        return hex(block)
    if not isinstance(block, str):
        raise ValueError(f"invalid block identifier: {block}")
    if block in BLOCK_TAGS or HEX_QUANTITY_RE.fullmatch(block):
        return block
    raise ValueError(f"invalid block identifier: {block}")


def bytecode_length(bytecode: str | None) -> int:
    if bytecode in (None, "0x"):
        return 0
    if not isinstance(bytecode, str) or not bytecode.startswith("0x") or len(bytecode) % 2 != 0:
        raise ValueError(f"invalid bytecode response: {bytecode}")
    return len(bytecode[2:]) // 2


def collect_contract(eth, address: str, *, block: str | int = "latest", storage_slots: list[str] | None = None) -> EvidenceBundle:
    address = validate_address(address)
    block = validate_block_identifier(block)
    bundle = EvidenceBundle()
    chain = eth.chain_id()
    chain_id = chain.result
    for res, stmt, value, kind, confidence in [
        (chain, "chain_id", chain.result, StatementType.OBSERVED, None),
        (eth.block_number(), "current_block", None, StatementType.OBSERVED, None),
        (eth.get_code(address, block), "bytecode_length", None, StatementType.DERIVED, Confidence.HIGH),
        (eth.get_balance(address, block), "balance", None, StatementType.OBSERVED, None),
    ]:
        normalized = bytecode_length(res.result) if stmt == "bytecode_length" else (value if value is not None else res.result)
        ev = bundle.add_evidence(EvidenceRecord.from_rpc_result(res, chain_id=chain_id, block=block, provider_id=eth.client.provider_id))
        obs = NormalizedObservation(f"{ev.evidence_id}:{stmt}", stmt, normalized, kind, (ev.evidence_id,), confidence)
        bundle.add_observation(obs, ProvenanceRecord(stmt, kind, obs.evidence_ids, confidence))
    for slot in storage_slots or []:
        if not isinstance(slot, str) or not slot.startswith("0x"):
            raise ValueError(f"invalid storage slot: {slot}")
        res = eth.get_storage_at(address, slot, block)
        ev = bundle.add_evidence(EvidenceRecord.from_rpc_result(res, chain_id=chain_id, block=block, provider_id=eth.client.provider_id))
        obs = NormalizedObservation(f"{ev.evidence_id}:storage", f"storage[{slot}]", res.result, StatementType.OBSERVED, (ev.evidence_id,))
        bundle.add_observation(obs, ProvenanceRecord(obs.statement, obs.statement_type, obs.evidence_ids))
    return bundle
