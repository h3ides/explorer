from __future__ import annotations
from typing import Any
from .client import JsonRpcClient, RpcResult

class EthRpc:
    def __init__(self, client: JsonRpcClient): self.client = client
    def chain_id(self) -> RpcResult: return self.client.call("eth_chainId")
    def block_number(self) -> RpcResult: return self.client.call("eth_blockNumber")
    def get_code(self, address: str, block: str = "latest") -> RpcResult: return self.client.call("eth_getCode", [address, block])
    def get_balance(self, address: str, block: str = "latest") -> RpcResult: return self.client.call("eth_getBalance", [address, block])
    def get_storage_at(self, address: str, slot: str, block: str = "latest") -> RpcResult: return self.client.call("eth_getStorageAt", [address, slot, block])
    def call(self, tx: dict[str, Any], block: str = "latest") -> RpcResult: return self.client.call("eth_call", [tx, block])
    def get_logs(self, params: dict[str, Any]) -> RpcResult: return self.client.call("eth_getLogs", [params])
    def get_transaction_by_hash(self, tx_hash: str) -> RpcResult: return self.client.call("eth_getTransactionByHash", [tx_hash])
    def get_transaction_receipt(self, tx_hash: str) -> RpcResult: return self.client.call("eth_getTransactionReceipt", [tx_hash])
    def get_block_by_number(self, block: str, full: bool = False) -> RpcResult: return self.client.call("eth_getBlockByNumber", [block, full])
