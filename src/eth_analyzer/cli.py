from __future__ import annotations
import argparse
import os
from pathlib import Path
from .contract import collect_contract, validate_address, validate_block_identifier
from .rpc import JsonRpcClient, EthRpc


def build_parser():
    p = argparse.ArgumentParser(prog="eth-analyzer")
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("analyze")
    a.add_argument("contract_address")
    a.add_argument("--rpc-url", default=os.environ.get("ETH_ANALYZER_RPC_URL"))
    a.add_argument("--block", default="latest")
    a.add_argument("--output", default="analysis")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        if not args.rpc_url:
            raise SystemExit("--rpc-url or ETH_ANALYZER_RPC_URL is required")
        address = validate_address(args.contract_address)
        block = validate_block_identifier(args.block)
        eth = EthRpc(JsonRpcClient(args.rpc_url))
        bundle = collect_contract(eth, address, block=block)
        chain_id = next((o.value for o in bundle.observations if o.statement == "chain_id"), "unknown")
        out = Path(args.output) / str(chain_id).replace("/", "_") / address
        bundle.write(out)
        print(out)
    return 0
