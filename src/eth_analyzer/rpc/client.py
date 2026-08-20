from __future__ import annotations

import json
import itertools
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Any


class RpcError(RuntimeError):
    def __init__(self, message: str, *, response: dict[str, Any] | None = None):
        super().__init__(message)
        self.response = response


@dataclass(frozen=True)
class RpcResult:
    method: str
    params: list[Any]
    request: dict[str, Any]
    response: dict[str, Any]
    result: Any


class JsonRpcClient:
    """Small JSON-RPC 2.0 HTTP client with no write-method helpers."""

    _ids = itertools.count(1)
    allowed_methods = frozenset({
        "eth_chainId", "eth_blockNumber", "eth_getCode", "eth_getBalance",
        "eth_getStorageAt", "eth_call", "eth_getLogs", "eth_getTransactionByHash",
        "eth_getTransactionReceipt", "eth_getBlockByNumber",
    })

    def __init__(self, rpc_url: str, *, timeout: float = 10.0, provider_id: str | None = None):
        self.rpc_url = rpc_url
        self.timeout = timeout
        self.provider_id = provider_id or rpc_url

    def build_request(self, method: str, params: list[Any] | None = None) -> dict[str, Any]:
        if method not in self.allowed_methods:
            raise ValueError(f"RPC method is not exposed by this read-only client: {method}")
        return {"jsonrpc": "2.0", "id": next(self._ids), "method": method, "params": params or []}

    def call(self, method: str, params: list[Any] | None = None) -> RpcResult:
        request = self.build_request(method, params)
        data = json.dumps(request).encode("utf-8")
        http_request = urllib.request.Request(
            self.rpc_url, data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(http_request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.URLError as exc:
            raise RpcError(f"JSON-RPC transport error: {exc}") from exc
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RpcError("JSON-RPC response was not valid JSON") from exc
        if not isinstance(payload, dict):
            raise RpcError("JSON-RPC response must be an object")
        if "error" in payload:
            err = payload["error"]
            msg = err.get("message", "unknown RPC error") if isinstance(err, dict) else str(err)
            raise RpcError(f"JSON-RPC error from {method}: {msg}", response=payload)
        if "result" not in payload:
            raise RpcError(f"JSON-RPC response missing result for {method}", response=payload)
        return RpcResult(method=method, params=request["params"], request=request, response=payload, result=payload["result"])
