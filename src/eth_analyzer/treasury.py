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

EXECUTION_CONFIG_SELECTOR = "0x8d112184"
EXECUTION_HOOKS_SELECTOR = "0x642f9dd4"
PRE_VALIDATION_HOOKS_SELECTOR = "0xceaf1309"

EXECUTION_TARGETS = {
    "execute": "0xb61d27f6",
    "executeBatch": "0x34fcd5be",
    "executeFromPlugin": "0x94ed11e7",
    "executeFromPluginExternal": "0x38997b11",
    "validateUserOp": "0x3a871cdd",
    "installPlugin": "0xf85730f4",
    "uninstallPlugin": "0xc1a221f3",
    "upgradeTo": "0x3659cfe6",
    "upgradeToAndCall": "0x4f1ef286",
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


def _word(raw: str, index: int) -> str:
    start = index * 64
    end = start + 64
    if start < 0 or end > len(raw):
        raise ValueError("ABI word out of bounds")
    return raw[start:end]


def _function_reference(raw: str, word_index: int) -> dict[str, Any]:
    return {
        "plugin": "0x" + _word(raw, word_index)[24:],
        "functionId": int(_word(raw, word_index + 1), 16),
    }


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


def _decode_execution_config(value: str) -> dict[str, Any]:
    raw = value[2:] if isinstance(value, str) and value.startswith("0x") else ""
    try:
        if len(raw) < 320:
            raise ValueError("short ExecutionFunctionConfig")
        return {
            "plugin": "0x" + _word(raw, 0)[24:],
            "userOpValidationFunction": _function_reference(raw, 1),
            "runtimeValidationFunction": _function_reference(raw, 3),
        }
    except (ValueError, IndexError) as exc:
        return {"decodeError": str(exc), "raw": value}


def _decode_execution_hooks(value: str) -> list[dict[str, Any]]:
    raw = value[2:] if isinstance(value, str) and value.startswith("0x") else ""
    try:
        offset = int(_word(raw, 0), 16) * 2
        length = int(raw[offset:offset + 64], 16)
        base = offset + 64
        hooks = []
        for i in range(length):
            item = base + i * 256
            hooks.append({
                "preExecHook": _function_reference(raw, item // 64),
                "postExecHook": _function_reference(raw, item // 64 + 2),
            })
        return hooks
    except (ValueError, IndexError) as exc:
        return [{"decodeError": str(exc), "raw": value}]


def _decode_pre_validation_hooks(value: str) -> dict[str, Any]:
    raw = value[2:] if isinstance(value, str) and value.startswith("0x") else ""
    try:
        first_offset = int(_word(raw, 0), 16) * 2
        second_offset = int(_word(raw, 1), 16) * 2

        def decode_refs(offset: int) -> list[dict[str, Any]]:
            length = int(raw[offset:offset + 64], 16)
            base = offset + 64
            return [_function_reference(raw, (base // 64) + i * 2) for i in range(length)]

        return {
            "preUserOpValidationHooks": decode_refs(first_offset),
            "preRuntimeValidationHooks": decode_refs(second_offset),
        }
    except (ValueError, IndexError) as exc:
        return {"decodeError": str(exc), "raw": value}


def _selector_call(eth: EthRpc, address: str, selector: str, argument: str, block: str) -> dict[str, Any]:
    data = selector + argument[2:] if argument.startswith("0x") else selector + argument
    call = eth.call({"to": address, "data": data}, block)
    return {"raw": call.result}


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

    execution_config: dict[str, Any] = {}
    execution_hooks: dict[str, Any] = {}
    pre_validation_hooks: dict[str, Any] = {}
    for name, target_selector in EXECUTION_TARGETS.items():
        padded = target_selector[2:].ljust(64, "0")
        try:
            execution_config[name] = _selector_call(eth, address, EXECUTION_CONFIG_SELECTOR, padded, block)
            execution_config[name]["decoded"] = _decode_execution_config(execution_config[name]["raw"])
        except Exception as exc:
            execution_config[name] = {"error": str(exc)}
        try:
            execution_hooks[name] = _selector_call(eth, address, EXECUTION_HOOKS_SELECTOR, padded, block)
            execution_hooks[name]["decoded"] = _decode_execution_hooks(execution_hooks[name]["raw"])
        except Exception as exc:
            execution_hooks[name] = {"error": str(exc)}
        try:
            pre_validation_hooks[name] = _selector_call(eth, address, PRE_VALIDATION_HOOKS_SELECTOR, padded, block)
            pre_validation_hooks[name]["decoded"] = _decode_pre_validation_hooks(pre_validation_hooks[name]["raw"])
        except Exception as exc:
            pre_validation_hooks[name] = {"error": str(exc)}

    results["executionFunctionConfigs"] = execution_config
    results["executionHooks"] = execution_hooks
    results["preValidationHooks"] = pre_validation_hooks
    return TreasurySnapshot(address=address, block=block, results=results)


def write_snapshot(snapshot: TreasurySnapshot, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"address": snapshot.address, "block": snapshot.block, "results": snapshot.results}, fh, indent=2)
        fh.write("\n")
