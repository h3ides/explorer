from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .rpc import EthRpc


TREASURY = "0x4d603a9ca01907173929eab78e59ef82b943aa0e"
IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

SELECTORS = {
    "getNativeOwner": "0x66b46a7a",
    "getInstalledPlugins": "0x3a0cac56",
    "getEntryPoint": "0x44ab613f",
    "PLUGIN_MANAGER": "0x16feeab7",
    "ENTRY_POINT": "0x94430fa5",
    "getNonce": "0xd087d288",
    "getDeposit": "0xc399ec88",
}


@dataclass(frozen=True)
class TreasurySnapshot:
    address: str
    block: str
    results: dict[str, Any]


def _address_from_word(value: str) -> str | None:
    if not isinstance(value, str) or not value.startswith("0x"):
        return None
    word = value[2:]
    if len(word) < 40:
        return None
    return "0x" + word[-40:]


def _decode_address_array(value: str) -> list[str]:
    if not isinstance(value, str) or not value.startswith("0x"):
        return []
    raw = value[2:]
    if len(raw) < 128:
        return []
    try:
        offset = int(raw[:64], 16) * 2
        length = int(raw[offset:offset + 64], 16)
        start = offset + 64
        return ["0x" + raw[start + i * 64 + 24:start + (i + 1) * 64] for i in range(length)]
    except (ValueError, IndexError):
        return []


def collect_treasury(eth: EthRpc, address: str = TREASURY, block: str = "latest") -> TreasurySnapshot:
    results: dict[str, Any] = {}
    storage = eth.get_storage_at(address, IMPLEMENTATION_SLOT, block)
    results["eip1967_implementation_slot"] = storage.result
    for name, selector in SELECTORS.items():
        call = eth.call({"to": address, "data": selector}, block)
        value = call.result
        entry: dict[str, Any] = {"raw": value}
        if name == "getNativeOwner" or name in {"getEntryPoint", "PLUGIN_MANAGER", "ENTRY_POINT"}:
            entry["address"] = _address_from_word(value)
        elif name == "getInstalledPlugins":
            entry["addresses"] = _decode_address_array(value)
        elif name in {"getNonce", "getDeposit"} and isinstance(value, str) and value.startswith("0x"):
            try:
                entry["uint256"] = int(value, 16)
            except ValueError:
                pass
        results[name] = entry
    return TreasurySnapshot(address=address, block=block, results=results)


def write_snapshot(snapshot: TreasurySnapshot, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"address": snapshot.address, "block": snapshot.block, "results": snapshot.results}, fh, indent=2)
        fh.write("\n")
