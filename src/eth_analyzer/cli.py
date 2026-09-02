from __future__ import annotations
import argparse
import os
from pathlib import Path
from .contract import collect_contract, validate_address, validate_block_identifier
from .rpc import JsonRpcClient, EthRpc
from .treasury import TREASURY, collect_treasury, write_snapshot
from .transaction import collect_transaction, write_transaction


def build_parser():
    p = argparse.ArgumentParser(prog="eth-analyzer")
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("analyze")
    a.add_argument("contract_address")
    a.add_argument("--rpc-url", default=os.environ.get("ETH_ANALYZER_RPC_URL"))
    a.add_argument("--block", default="latest")
    a.add_argument("--output", default="analysis")
    t = sub.add_parser("treasury")
    t.add_argument("--address", default=TREASURY)
    t.add_argument("--rpc-url", default=os.environ.get("ETH_ANALYZER_RPC_URL"))
    t.add_argument("--block", default="latest")
    t.add_argument("--output", default="treasury.json")
    x = sub.add_parser("transaction")
    x.add_argument("tx_hash")
    x.add_argument("--rpc-url", default=os.environ.get("ETH_ANALYZER_RPC_URL"))
    x.add_argument("--output", default="transaction.json")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.rpc_url:
        raise SystemExit("--rpc-url or ETH_ANALYZER_RPC_URL is required")
    eth = EthRpc(JsonRpcClient(args.rpc_url))
    if args.command == "analyze":
        address = validate_address(args.contract_address)
        block = validate_block_identifier(args.block)
        bundle = collect_contract(eth, address, block=block)
        chain_id = next((o.value for o in bundle.observations if o.statement == "chain_id"), "unknown")
        out = Path(args.output) / str(chain_id).replace("/", "_") / address
        bundle.write(out)
        print(out)
    elif args.command == "treasury":
        address = validate_address(args.address)
        block = validate_block_identifier(args.block)
        snapshot = collect_treasury(eth, address, block=block)
        write_snapshot(snapshot, args.output)
        print(args.output)
    elif args.command == "transaction":
        snapshot = collect_transaction(eth, args.tx_hash)
        write_transaction(snapshot, args.output)
        print(args.output)
    return 0
