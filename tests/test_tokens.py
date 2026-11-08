"""ALP token protocol tests: issue / send / mint / burn + reorg handling."""

import unittest

from alpha import constants, miner, tokens
from alpha.blockchain import Blockchain
from alpha.node import Node
from alpha.wallet import WalletKey


def _hooked_node():
    n = Node(constants.REGTEST, None, port=0, listen=False)
    return n


def mine(node, spk, n=1):
    for _ in range(n):
        b = miner.create_block_template(node.chain, node.mempool, spk)
        assert miner.mine_block(b, node.params.pow_limit_bits)
        node.submit_block(b)


class TestTokens(unittest.TestCase):
    def setUp(self):
        self.node = _hooked_node()
        self.key = WalletKey(777)
        # fund the key: mine 101 mature coinbases
        for _ in range(101):
            b = miner.create_block_template(self.node.chain, None,
                                            self.key.script_p2wpkh)
            assert miner.mine_block(b, constants.REGTEST.pow_limit_bits)
            self.node.chain.add_block(b)
        self.node.wallet.keys = [self.key]
        self.addr = self.key.address("bech32", constants.REGTEST)

    def _issue(self, name="TestCoin", decimals=2, supply=1000_00):
        payload = tokens.encode_issue(name, decimals, supply)
        tx = self.node.wallet.create_token_op_tx(
            self.node.chain, payload, self.addr, self.addr)
        self.node.mempool.accept(tx)
        mine(self.node, self.key.script_p2wpkh, 1)
        return tx.txid()

    def test_issue_and_balance(self):
        tid = self._issue()
        info = self.node.tokens.registry[tid]
        self.assertEqual(info.name, "TestCoin")
        self.assertEqual(info.decimals, 2)
        self.assertEqual(info.supply, 1000_00)
        # issuer holds the whole supply
        self.assertEqual(
            self.node.tokens.balance(tid, self.key.script_p2wpkh), 1000_00)

    def test_send(self):
        tid = self._issue()
        dest = WalletKey(888)
        dest_spk = dest.script_p2wpkh
        payload = tokens.encode_send(tid, 250_00)
        tx = self.node.wallet.create_token_op_tx(
            self.node.chain, payload, self.addr,
            dest.address("bech32", constants.REGTEST))
        self.node.mempool.accept(tx)
        mine(self.node, self.key.script_p2wpkh, 1)
        self.assertEqual(self.node.tokens.balance(tid, dest_spk), 250_00)
        self.assertEqual(
            self.node.tokens.balance(tid, self.key.script_p2wpkh), 750_00)

    def test_send_more_than_balance_invalid(self):
        tid = self._issue()
        dest = WalletKey(888)
        payload = tokens.encode_send(tid, 999_999_99)
        tx = self.node.wallet.create_token_op_tx(
            self.node.chain, payload, self.addr,
            dest.address("bech32", constants.REGTEST))
        self.node.mempool.accept(tx)
        mine(self.node, self.key.script_p2wpkh, 1)
        # invalid send is ignored -- balances unchanged
        self.assertEqual(self.node.tokens.balance(tid, dest.script_p2wpkh), 0)
        self.assertEqual(
            self.node.tokens.balance(tid, self.key.script_p2wpkh), 1000_00)

    def test_mint_only_by_issuer(self):
        tid = self._issue()
        other = WalletKey(999)
        # other address tries to mint -> invalid (not issuer)
        payload = tokens.encode_mint(tid, 500_00)
        tx = self.node.wallet.create_token_op_tx(
            self.node.chain, payload, self.addr,
            other.address("bech32", constants.REGTEST))
        self.node.mempool.accept(tx)
        mine(self.node, self.key.script_p2wpkh, 1)
        # minted to `other` because signed by issuer (first input = issuer)
        self.assertEqual(self.node.tokens.balance(
            tid, other.script_p2wpkh), 500_00)
        self.assertEqual(self.node.tokens.registry[tid].supply, 1500_00)

    def test_burn(self):
        tid = self._issue()
        payload = tokens.encode_burn(tid, 100_00)
        tx = self.node.wallet.create_token_op_tx(
            self.node.chain, payload, self.addr, self.addr)
        self.node.mempool.accept(tx)
        mine(self.node, self.key.script_p2wpkh, 1)
        self.assertEqual(self.node.tokens.registry[tid].supply, 900_00)
        self.assertEqual(
            self.node.tokens.balance(tid, self.key.script_p2wpkh), 900_00)

    def test_payload_roundtrip(self):
        p = tokens.parse_payload(tokens.encode_issue("X", 4, 12345))
        self.assertEqual(p, {"op": tokens.OP_ISSUE, "name": "X",
                             "decimals": 4, "supply": 12345})
        tid = b"\x11" * 32
        p = tokens.parse_payload(tokens.encode_send(tid, 7))
        self.assertEqual(p, {"op": tokens.OP_SEND, "token_id": tid,
                             "amount": 7})
        self.assertIsNone(tokens.parse_payload(b"NOPE\x01\x02"))


if __name__ == "__main__":
    unittest.main()
