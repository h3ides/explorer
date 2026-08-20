from __future__ import annotations
from typing import Any
from eth_analyzer.contract import validate_address, validate_block_identifier


def simulate_call(eth, *, to: str, data: str, value: str | None = None, block: str | int = "latest") -> Any:
    """Run eth_call simulation only; this helper never broadcasts transactions."""
    if not isinstance(data, str) or not data.startswith("0x"):
        raise ValueError("eth_call data must be 0x-prefixed hex")
    tx = {"to": validate_address(to), "data": data}
    if value is not None:
        if not isinstance(value, str) or not value.startswith("0x"):
            raise ValueError("eth_call value must be a 0x-prefixed quantity")
        tx["value"] = value
    return eth.call(tx, validate_block_identifier(block))
