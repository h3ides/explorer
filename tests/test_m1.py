from __future__ import annotations
import json, threading
from dataclasses import FrozenInstanceError
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock
from urllib.error import URLError

import pytest

from eth_analyzer.rpc import JsonRpcClient, EthRpc, RpcError
from eth_analyzer.contract import validate_address, validate_block_identifier, collect_contract, bytecode_length
from eth_analyzer.evidence import EvidenceRecord, EvidenceBundle, NormalizedObservation, ProvenanceRecord, StatementType, Confidence
from eth_analyzer.execution import simulate_call
from eth_analyzer.history.logs import get_logs
from eth_analyzer.history.transactions import get_transaction, get_receipt
from eth_analyzer.cli import main

ADDR = "0x0000000000000000000000000000000000000000"
MIXED_ADDR = "0x00000000000000000000000000000000000000aA"
TX = "0x" + "1" * 64

class MockRpc:
    def __init__(self, responses):
        self.responses = responses; self.requests = []
        parent = self
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                parent.requests.append(body)
                result = parent.responses.get(body["method"], "0x0")
                payload = result if isinstance(result, dict) and ("error" in result or "result" in result) else {"jsonrpc":"2.0","id":body["id"],"result":result}
                self.send_response(200); self.end_headers(); self.wfile.write(json.dumps(payload).encode())
            def log_message(self, *args): pass
        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
    def __enter__(self):
        self.thread.start(); return f"http://127.0.0.1:{self.server.server_port}"
    def __exit__(self, *exc): self.server.shutdown(); self.thread.join()

def responses(code="0x6000", tx=None, receipt=None, logs=None):
    return {
        "eth_chainId": "0x1", "eth_blockNumber": "0x10", "eth_getCode": code,
        "eth_getBalance": "0x2", "eth_getStorageAt": "0x" + "0"*64,
        "eth_call": "0x1234", "eth_getLogs": logs if logs is not None else [{"blockNumber":"0x1","blockHash":"0xabc","transactionHash":TX,"transactionIndex":"0x0","logIndex":"0x0","address":ADDR,"topics":[],"data":"0x","removed":False}],
        "eth_getTransactionByHash": tx, "eth_getTransactionReceipt": receipt,
        "eth_getBlockByNumber": {"number":"0x10"},
    }

def test_request_construction_ids_and_dedicated_write_method_denylist():
    c = JsonRpcClient("http://example.invalid")
    one = c.build_request("eth_getCode", [ADDR, "latest"])
    two = c.build_request("eth_getBalance", [ADDR, "pending"])
    assert one["jsonrpc"] == "2.0" and one["method"] == "eth_getCode" and one["params"] == [ADDR, "latest"]
    assert two["id"] == one["id"] + 1
    denied = ["eth_sendRawTransaction", "eth_sendTransaction", "personal_sign", "wallet_switchEthereumChain"]
    for method in denied:
        with pytest.raises(ValueError): c.build_request(method, [])
    for attr in ["send_transaction", "send_raw_transaction", "sign", "wallet", "personal", "private_key"]:
        assert not hasattr(c, attr)

def test_rpc_methods_block_tags_nulls_and_raw_responses():
    log = {"blockNumber":"0x1","blockHash":"0xabc","transactionHash":TX,"transactionIndex":"0x0","logIndex":"0x0","address":ADDR,"topics":["0xaaa"],"data":"0x","removed":False}
    with MockRpc(responses(tx=None, receipt=None, logs=[log])) as url:
        eth = EthRpc(JsonRpcClient(url, provider_id="mock"))
        assert eth.chain_id().result == "0x1"
        assert eth.block_number().result == "0x10"
        assert eth.get_code(ADDR, "pending").response["result"] == "0x6000"
        assert eth.get_balance(ADDR, "0x10").result == "0x2"
        assert eth.get_storage_at(ADDR, "0x0", "latest").result.startswith("0x")
        call = simulate_call(eth, to=MIXED_ADDR, data="0xabcdef", value="0x0", block=16)
        assert call.result == "0x1234"
        assert eth.client.provider_id == "mock"
        assert get_logs(eth, address=MIXED_ADDR, from_block=1, to_block="latest").result[0] == log
        assert get_transaction(eth, TX).result is None
        assert get_receipt(eth, TX).result is None
        assert eth.get_block_by_number("latest").result["number"] == "0x10"

def test_rpc_error_transport_and_malformed_handling():
    with MockRpc({"eth_chainId": {"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"revert"}}}) as url:
        with pytest.raises(RpcError) as exc:
            EthRpc(JsonRpcClient(url)).chain_id()
        assert exc.value.response["error"]["message"] == "revert"
    with mock.patch("urllib.request.urlopen", side_effect=URLError("timeout")):
        with pytest.raises(RpcError, match="transport"):
            JsonRpcClient("http://example.invalid", timeout=0.01).call("eth_chainId")
    class BadResponse:
        def __enter__(self): return self
        def __exit__(self, *exc): pass
        def read(self): return b"not json"
    with mock.patch("urllib.request.urlopen", return_value=BadResponse()):
        with pytest.raises(RpcError, match="valid JSON"):
            JsonRpcClient("http://example.invalid").call("eth_chainId")
    class MissingResultResponse:
        def __enter__(self): return self
        def __exit__(self, *exc): pass
        def read(self): return b'{"jsonrpc":"2.0","id":1}'
    with mock.patch("urllib.request.urlopen", return_value=MissingResultResponse()):
        with pytest.raises(RpcError, match="missing result"):
            JsonRpcClient("http://example.invalid").call("eth_chainId")

def test_address_block_validation_empty_code_and_no_storage_bruteforce():
    assert validate_address(MIXED_ADDR) == MIXED_ADDR.lower()
    with pytest.raises(ValueError): validate_address("0x123")
    assert validate_block_identifier("latest") == "latest"
    assert validate_block_identifier(15) == "0xf"
    assert validate_block_identifier("0x10") == "0x10"
    with pytest.raises(ValueError): validate_block_identifier("10")
    assert bytecode_length("0x") == 0
    with MockRpc(responses(code="0x")) as url:
        eth = EthRpc(JsonRpcClient(url))
        bundle = collect_contract(eth, ADDR)
    assert any(o.statement == "bytecode_length" and o.value == 0 for o in bundle.observations)

def test_evidence_immutability_raw_request_response_and_deterministic_ids():
    with MockRpc(responses()) as url:
        result = EthRpc(JsonRpcClient(url, provider_id="mock")).get_code(ADDR, "latest")
    ev1 = EvidenceRecord.from_rpc_result(result, chain_id="0x1", block="latest", timestamp="0x5", provider_id="mock")
    ev2 = EvidenceRecord.from_rpc_result(result, chain_id="0x1", block="latest", timestamp="0x5", provider_id="mock")
    assert ev1.evidence_id == ev2.evidence_id
    assert ev1.raw_request["method"] == "eth_getCode"
    assert ev1.raw_response["result"] == "0x6000"
    assert ev1.timestamp == "0x5" and ev1.collection_timestamp != ev1.timestamp
    with pytest.raises(FrozenInstanceError): ev1.rpc_method = "changed"
    with pytest.raises(TypeError): ev1.raw_response["result"] = "0x"
    assert ev1.to_json()["raw_response"]["result"] == "0x6000"

def test_provenance_multiple_sources_and_invalid_missing_cases():
    with MockRpc(responses()) as url:
        eth = EthRpc(JsonRpcClient(url))
        a = EvidenceRecord.from_rpc_result(eth.get_code(ADDR), chain_id="0x1", block="latest")
        b = EvidenceRecord.from_rpc_result(eth.get_balance(ADDR), chain_id="0x1", block="latest")
    bundle = EvidenceBundle(); bundle.add_evidence(a); bundle.add_evidence(b)
    obs = NormalizedObservation("derived", "code_and_balance_seen", True, StatementType.DERIVED, (a.evidence_id, b.evidence_id), Confidence.HIGH)
    prov = ProvenanceRecord(obs.statement, StatementType.DERIVED, obs.evidence_ids, Confidence.HIGH)
    bundle.add_observation(obs, prov)
    with pytest.raises(ValueError): bundle.add_observation(NormalizedObservation("missing", "missing", True, StatementType.OBSERVED, ("nope",)), ProvenanceRecord("missing", StatementType.OBSERVED, ("nope",)))
    with pytest.raises(ValueError): bundle.add_observation(obs, ProvenanceRecord("different", StatementType.DERIVED, obs.evidence_ids, Confidence.HIGH))
    with pytest.raises(ValueError): ProvenanceRecord("unsupported", StatementType.HYPOTHESIS, (a.evidence_id,))
    assert bundle.provenance[0].statement_type is StatementType.DERIVED

def test_cli_output_valid_json_and_no_partial_on_failure(tmp_path):
    with MockRpc(responses()) as url:
        assert main(["analyze", ADDR, "--rpc-url", url, "--block", "latest", "--output", str(tmp_path)]) == 0
    out = tmp_path / "0x1" / ADDR
    assert (out / "metadata.json").exists()
    data = json.loads((out / "metadata.json").read_text())
    assert data["evidence"] and data["evidence"][0]["raw_request"] and data["evidence"][0]["raw_response"]
    bad_out = tmp_path / "bad"
    with MockRpc({"eth_chainId": {"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"boom"}}}) as url:
        with pytest.raises(RpcError): main(["analyze", ADDR, "--rpc-url", url, "--output", str(bad_out)])
    assert not bad_out.exists()

def test_eth_call_validation_and_revert_response_preserved():
    with MockRpc({"eth_call": {"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted","data":"0x08c379a"}}}) as url:
        with pytest.raises(RpcError) as exc:
            simulate_call(EthRpc(JsonRpcClient(url)), to=ADDR, data="0x")
        assert exc.value.response["error"]["data"] == "0x08c379a"
    with MockRpc(responses()) as url:
        eth = EthRpc(JsonRpcClient(url))
        with pytest.raises(ValueError): simulate_call(eth, to=ADDR, data="abcdef")
        with pytest.raises(ValueError): simulate_call(eth, to=ADDR, data="0x", value="1")
