# explorer

Read-only Ethereum JSON-RPC smart-contract analysis framework.

## Project charter

Build a read-only Ethereum JSON-RPC smart-contract analysis framework. The framework reconstructs contract evidence from the chain without sending state-changing transactions, exploiting contracts, recovering assets, interacting with target assets, or beginning from vulnerability fingerprints or known exploit signatures.

The architecture is evidence-first:

`RPC evidence -> normalized evidence -> provenance -> later analysis`

Milestone 1 implements only the read-only RPC evidence engine.

## Installation

```bash
python -m pip install -e .
```

## Configuration

Provide an Ethereum JSON-RPC URL with `--rpc-url` or `ETH_ANALYZER_RPC_URL`.

## CLI usage

```bash
eth-analyzer analyze 0x0000000000000000000000000000000000000000 --rpc-url http://localhost:8545 --output analysis
```

The CLI writes a JSON evidence bundle under `analysis/<chain_id>/<contract_address>/` containing metadata, code, balance, and provenance records.

## Milestone 1 architecture

- `eth_analyzer.rpc`: provider-agnostic JSON-RPC 2.0 HTTP POST client exposing only read/simulation methods.
- `eth_analyzer.evidence`: immutable evidence records, JSON bundle storage, and provenance links.
- `eth_analyzer.contract`: address validation and explicit contract code, balance, and storage collection.
- `eth_analyzer.execution`: read-only `eth_call` simulation helper.
- `eth_analyzer.history`: explicit log and transaction/receipt lookup helpers.

## Evidence model

Every RPC observation is stored as immutable evidence with the RPC method, request parameters, raw response, chain ID, relevant block or transaction hash, collection timestamp, and optional provider identifier. Normalized observations are stored separately and cite one or more evidence IDs through provenance.

## Read-only guarantees

The RPC API intentionally exposes only:

- `eth_chainId`
- `eth_blockNumber`
- `eth_getCode`
- `eth_getBalance`
- `eth_getStorageAt`
- `eth_call`
- `eth_getLogs`
- `eth_getTransactionByHash`
- `eth_getTransactionReceipt`
- `eth_getBlockByNumber`

It contains no private-key support, signing, wallet APIs, `eth_sendTransaction`, or `eth_sendRawTransaction` helpers.

## Testing

```bash
python -m pytest
python -m compileall src
python -m eth_analyzer --help
```

The unit tests use mocked RPC responses and do not require a live Ethereum endpoint.

## Not implemented yet

Milestone 1 does not implement exploitation, asset recovery, vulnerability detection, abandoned-contract discovery, automated transaction sending, historical discovery, authority reconstruction, semantic event decoding, tracing, or persistent database storage.
