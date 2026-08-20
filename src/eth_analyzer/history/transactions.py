def get_transaction(eth, tx_hash: str): return eth.get_transaction_by_hash(tx_hash)
def get_receipt(eth, tx_hash: str): return eth.get_transaction_receipt(tx_hash)
