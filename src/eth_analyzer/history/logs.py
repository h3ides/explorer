from eth_analyzer.contract import validate_address, validate_block_identifier


def get_logs(eth, *, address: str, from_block: str | int, to_block: str | int):
    return eth.get_logs({
        "address": validate_address(address),
        "fromBlock": validate_block_identifier(from_block),
        "toBlock": validate_block_identifier(to_block),
    })
