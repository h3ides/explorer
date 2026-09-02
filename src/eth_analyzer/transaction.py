from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .rpc import EthRpc


KNOWN_SELECTORS = {
    "execute": "0xb61d27f6",
    "executeBatch": "0x34fcd5be",
    "executeFromPlugin": "0x94ed11e7",
    "executeFromPluginExternal": "0x38997b11",
    "validateUserOp": "0x3a871cdd",
    "transfer": "0xa9059cbb",
    "approve": "0x095ea7b3",
    "transferFrom": "0x23b872dd",
}
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628a6f9b5a7f5f5d" 


@dataclass(frozen=True)
class TransactionSnapshot:
    tx_hash: str
    transaction: dict[str, Any] | None
    receipt: dict[str, Any] | None
    decoded: dict[str, Any]


def _word(raw: str, index: int) -> str:
    start = index * 64
    end = start + 64
    if start < 0 or end > len(raw):
        raise ValueError("ABI word out of bounds")
    return raw[start:end]


def _address_word(word: str) -> str:
    return "0x" + word[-40:]


def _uint_word(word: str) -> int:
    return int(word, 16)


def _bytes_at(raw: str, byte_offset: int) -> str:
    offset = byte_offset * 2
    length = int(raw[offset:offset + 64], 16)
    start = offset + 64
    return "0x" + raw[start:start + length * 2]


def _decode_inner_call(data: str) -> dict[str, Any]:
    if not isinstance(data, str) or not data.startswith("0x") or len(data) < 10:
        return {"raw": data}
    selector = data[:10].lower()
    raw = data[10:]
    result: dict[str, Any] = {
        "selector": selector,
        "method": next((name for name, value in KNOWN_SELECTORS.items() if value == selector), None),
        "raw": data,
    }
    try:
        if selector == KNOWN_SELECTORS["transfer"]:
            result["arguments"] = {"to": _address_word(_word(raw, 0)), "amount": _uint_word(_word(raw, 1))}
        elif selector == KNOWN_SELECTORS["approve"]:
            result["arguments"] = {"spender": _address_word(_word(raw, 0)), "amount": _uint_word(_word(raw, 1))}
        elif selector == KNOWN_SELECTORS["transferFrom"]:
            result["arguments"] = {
                "from": _address_word(_word(raw, 0)),
                "to": _address_word(_word(raw, 1)),
                "amount": _uint_word(_word(raw, 2)),
            }
        elif selector == KNOWN_SELECTORS["execute"]:
            target = _address_word(_word(raw, 0))
            value = _uint_word(_word(raw, 1))
            data_offset = _uint_word(_word(raw, 2))
            inner = _bytes_at(raw, data_offset)
            result["arguments"] = {"target": target, "value": value, "data": _decode_inner_call(inner)}
        elif selector == KNOWN_SELECTORS["executeFromPlugin"]:
            data_offset = _uint_word(_word(raw, 0))
            inner = _bytes_at(raw, data_offset)
            result["arguments"] = {"data": _decode_inner_call(inner)}
        elif selector == KNOWN_SELECTORS["executeFromPluginExternal"]:
            target = _address_word(_word(raw, 0))
            value = _uint_word(_word(raw, 1))
            data_offset = _uint_word(_word(raw, 2))
            inner = _bytes_at(raw, data_offset)
            result["arguments"] = {"target": target, "value": value, "data": _decode_inner_call(inner)}
        elif selector == KNOWN_SELECTORS["executeBatch"]:
            offset = _uint_word(_word(raw, 0))
            base = offset * 2
            length = int(raw[base:base + 64], 16)
            calls: list[dict[str, Any]] = []
            head_start = base + 64
            for i in range(length):
                tuple_offset = int(raw[head_start + i * 64:head_start + (i + 1) * 64], 16)
                item = head_start + tuple_offset * 2
                target = _address_word(raw[item:item + 64])
                value = _uint_word(raw[item + 64:item + 128])
                data_rel = int(raw[item + 128:item + 192], 16)
                data_start = item + data_rel * 2
                data_len = int(raw[data_start:data_start + 64], 16)
                inner = "0x" + raw[data_start + 64:data_start + 64 + data_len * 2]
                calls.append({"target": target, "value": value, "data": _decode_inner_call(inner)})
            result["arguments"] = {"calls": calls}
        elif selector == KNOWN_SELECTORS["validateUserOp"]:
            result["arguments"] = {"rawArguments": "0x" + raw}
    except (ValueError, IndexError) as exc:
        result["decodeError"] = str(exc)
    return result


def _decode_logs(logs: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    decoded = []
    for log in logs or []:
        topics = log.get("topics") or []
        entry = {
            "address": log.get("address"),
            "topics": topics,
            "data": log.get("data"),
            "logIndex": log.get("logIndex"),
        }
        if topics and topics[0].lower() == TRANSFER_TOPIC:
            entry["event"] = "Transfer"
            if len(topics) >= 3:
                entry["from"] = _address_word(topics[1][2:])
                entry["to"] = _address_word(topics[2][2:])
            if isinstance(log.get("data"), str) and log["data"].startswith("0x"):
                try:
                    entry["amount"] = int(log["data"], 16)
                except ValueError:
                    pass
        decoded.append(entry)
    return decoded


def collect_transaction(eth: EthRpc, tx_hash: str) -> TransactionSnapshot:
    tx = eth.get_transaction_by_hash(tx_hash).result
    receipt = eth.get_transaction_receipt(tx_hash).result
    decoded: dict[str, Any] = {}
    if tx:
        decoded["topLevel"] = _decode_inner_call(tx.get("input", "0x"))
    decoded["logs"] = _decode_logs(receipt.get("logs") if receipt else None)
    if receipt:
        decoded["status"] = receipt.get("status")
        decoded["gasUsed"] = receipt.get("gasUsed")
        decoded["blockNumber"] = receipt.get("blockNumber")
    return TransactionSnapshot(tx_hash=tx_hash, transaction=tx, receipt=receipt, decoded=decoded)


def write_transaction(snapshot: TransactionSnapshot, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({
            "txHash": snapshot.tx_hash,
            "transaction": snapshot.transaction,
            "receipt": snapshot.receipt,
            "decoded": snapshot.decoded,
        }, fh, indent=2)
        fh.write("\n")
