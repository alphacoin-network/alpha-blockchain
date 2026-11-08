"""End-to-end tests on the regtest network: mining, spending (legacy +
segwit), mempool acceptance, difficulty retargeting, and reorgs.
"""

import os
import tempfile
import unittest

from alpha import constants, miner, script
from alpha.block import Block, BlockHeader
from alpha.blockchain import Blockchain, ChainError
from alpha.mempool import Mempool, MempoolError
from alpha.node import Node
from alpha.transaction import OutPoint, Transaction, TxIn, TxOut
from alpha.utils import hash_to_hex, now
from alpha.wallet import Wallet, WalletKey


def fresh_chain():
    return Blockchain(constants.REGTEST)


def mine_to(chain, key, n=1):
    """Mine n blocks paying `key`'s bech32 script."""
    blocks = []
    for _ in range(n):
        block = miner.create_block_template(chain, None,
                                            key.script_p2wpkh)
        assert miner.mine_block(block, chain.params.pow_limit_bits), "PoW failed"
        chain.add_block(block)
        blocks.append(block)
    return blocks


class TestMining(unittest.TestCase):
    def test_mine_and_supply(self):
        chain = fresh_chain()
        key = WalletKey(1234)
        blocks = mine_to(chain, key, 5)
        self.assertEqual(chain.height, 5)
        # 5 blocks * 50 coins to our script
        self.assertEqual(chain.total_supply(), 5 * 50 * constants.COIN)
        # coinbase matures after 100 blocks -> not yet spendable-locked logic
        self.assertEqual(len(chain.utxo), 5)

    def test_pow_check(self):
        chain = fresh_chain()
        key = WalletKey(5)
        blocks = mine_to(chain, key, 1)
        block = blocks[0]
        self.assertTrue(block.header.check_pow(chain.params.pow_limit_bits))
        self.assertIn(block.hash(), chain.index)
        # tip = our block
        self.assertEqual(chain.tip.hash, block.hash())


class TestSpending(unittest.TestCase):
    def setUp(self):
        self.chain = fresh_chain()
        self.miner_key = WalletKey(42)
        mine_to(self.chain, self.miner_key, 110)  # mature 10 coinbases
        self.mempool = Mempool(self.chain)
        self.wallet = Wallet(constants.REGTEST)
        self.wallet.keys = [self.miner_key]

    def _spendable(self, chain, key):
        for (txid, n), coin in chain.utxo.items():
            if coin.txout.script_pubkey in key.scripts() and not coin.is_coinbase:
                return (txid, n, coin)
        # mature coinbases
        for (txid, n), coin in chain.utxo.items():
            if (coin.txout.script_pubkey in key.scripts()
                    and coin.is_coinbase
                    and chain.height - coin.height >= 100):
                return (txid, n, coin)
        return None

    def test_p2wpkh_spend(self):
        """Spend a bech32 (P2WPKH) coinbase output to a new wallet key."""
        dest = WalletKey(99)
        utxo = self._spendable(self.chain, self.miner_key)
        self.assertIsNotNone(utxo)
        txid, n, coin = utxo

        tx = Transaction(
            version=2,
            vin=[TxIn(prevout=OutPoint(txid, n))],
            vout=[TxOut(coin.txout.value - 1000,
                        script.script_p2wpkh(dest.pubkey_hash))],
            locktime=0)
        Wallet.sign(self.wallet, tx, [coin.txout.script_pubkey],
                    [coin.txout.value], [self.miner_key])
        fee = self.mempool.accept(tx)
        self.assertEqual(fee, 1000)

        # mine it into a block
        block = miner.create_block_template(self.chain, self.mempool,
                                            self.miner_key.script_p2wpkh)
        self.assertTrue(miner.mine_block(block, constants.REGTEST.pow_limit_bits))
        self.chain.add_block(block)
        self.mempool.remove_for_block(block)

        # dest now owns the output
        self.assertIsNotNone(
            self.chain.get_utxo(tx.txid(), 0))
        self.assertEqual(len(self.mempool), 0)

    def test_p2pkh_legacy_spend(self):
        """Pay to a legacy P2PKH address then spend it."""
        dest = WalletKey(77)
        utxo = self._spendable(self.chain, self.miner_key)
        txid, n, coin = utxo

        tx = Transaction(
            version=2,
            vin=[TxIn(prevout=OutPoint(txid, n))],
            vout=[TxOut(coin.txout.value - 1000,
                        script.script_p2pkh(dest.pubkey_hash))],
            locktime=0)
        Wallet.sign(self.wallet, tx, [coin.txout.script_pubkey],
                    [coin.txout.value], [self.miner_key])
        self.mempool.accept(tx)
        block = miner.create_block_template(self.chain, self.mempool,
                                            self.miner_key.script_p2wpkh)
        self.assertTrue(miner.mine_block(block, constants.REGTEST.pow_limit_bits))
        self.chain.add_block(block)
        self.mempool.remove_for_block(block)  # confirm it

        # now dest spends the P2PKH output (legacy sighash path)
        w2 = Wallet(constants.REGTEST)
        w2.keys = [dest]
        new_key = WalletKey(88)
        out_coin = self.chain.get_utxo(tx.txid(), 0)
        tx2 = Transaction(
            version=2,
            vin=[TxIn(prevout=OutPoint(tx.txid(), 0))],
            vout=[TxOut(out_coin.txout.value - 1000,
                        script.script_p2pkh(new_key.pubkey_hash))],
            locktime=0)
        w2.sign(tx2, [out_coin.txout.script_pubkey],
                [out_coin.txout.value], [dest])
        self.mempool.accept(tx2)

    def test_bad_signature_rejected(self):
        dest = WalletKey(99)
        utxo = self._spendable(self.chain, self.miner_key)
        txid, n, coin = utxo
        tx = Transaction(
            version=2,
            vin=[TxIn(prevout=OutPoint(txid, n))],
            vout=[TxOut(coin.txout.value - 1000,
                        script.script_p2wpkh(dest.pubkey_hash))],
            locktime=0)
        # sign with the WRONG key
        wrong = Wallet(constants.REGTEST)
        wrong.keys = [WalletKey(7)]
        with self.assertRaises(ValueError):
            wrong.sign(tx, [coin.txout.script_pubkey], [coin.txout.value],
                       [WalletKey(7)])
        # and a signature made for a different message must fail
        sighash = tx.signature_hash_v0(
            script.script_p2pkh(self.miner_key.pubkey_hash), 0,
            coin.txout.value, 1)
        import alpha.crypto as crypto
        sig = crypto.ecdsa_sign_der(sighash, self.miner_key.priv) + b"\x01"
        tx.vin[0].witness = [sig, self.miner_key.pubkey]
        tx.vin[0].script_sig = b""
        # corrupt output -> sighash changes -> mempool reject
        tx.vout[0].value -= 500
        with self.assertRaises(MempoolError):
            self.mempool.accept(tx)

    def test_double_spend_rejected(self):
        utxo = self._spendable(self.chain, self.miner_key)
        txid, n, coin = utxo
        d1, d2 = WalletKey(1), WalletKey(2)
        for dest in (d1, d2):
            tx = Transaction(
                version=2,
                vin=[TxIn(prevout=OutPoint(txid, n))],
                vout=[TxOut(coin.txout.value - 1000,
                            script.script_p2wpkh(dest.pubkey_hash))],
                locktime=0)
            Wallet.sign(self.wallet, tx, [coin.txout.script_pubkey],
                        [coin.txout.value], [self.miner_key])
            if dest is d1:
                self.mempool.accept(tx)
            else:
                with self.assertRaises(MempoolError):
                    self.mempool.accept(tx)


class TestReorg(unittest.TestCase):
    def test_reorg_longer_chain_wins(self):
        chain = fresh_chain()
        k1, k2 = WalletKey(11), WalletKey(22)
        # mine 3 blocks to k1
        for _ in range(3):
            b = miner.create_block_template(chain, None, k1.script_p2wpkh)
            assert miner.mine_block(b, constants.REGTEST.pow_limit_bits)
            chain.add_block(b)
        tip3 = chain.tip.hash

        # build a competing branch from height 2: fork block at height 3
        parent = chain.get_block_index(2)
        alt_blocks = []
        prev = chain.get_block(parent.hash)
        for i in range(3):  # alt chain longer by work
            # craft block at height 3+i on the alt branch
            pass
        # easier: build fresh headers manually on top of parent
        alt_parent_entry = parent
        prev_block = chain.get_block(parent.hash)
        prev_hash = parent.hash
        for i in range(3):
            cb = miner.create_coinbase(
                parent.height + 1 + i, constants.REGTEST,
                k2.script_p2wpkh, 0, b"alt" + bytes([i]))
            blk = Block(BlockHeader(
                version=1, prev_hash=prev_hash, merkle=cb.txid(),
                timestamp=chain.get_block(prev_hash).header.timestamp + 1
                if chain.get_block(prev_hash) else now() + i + 1,
                bits=constants.REGTEST.pow_limit_bits, nonce=0),
                [cb])
            # fix timestamp to be > parent mtp
            blk.header.timestamp = max(
                now(),
                (chain.index[prev_hash].median_time_past() + 1))
            assert miner.mine_block(blk, constants.REGTEST.pow_limit_bits)
            chain.add_block(blk)
            prev_hash = blk.hash()
        self.assertEqual(chain.tip.hash, prev_hash)
        # blocks 1-2 are shared (still k1's); the reorganized h3-5 are k2's
        k1_utxos = [c for c in chain.utxo.values()
                    if c.txout.script_pubkey == k1.script_p2wpkh]
        k2_utxos = [c for c in chain.utxo.values()
                    if c.txout.script_pubkey == k2.script_p2wpkh]
        self.assertEqual(len(k1_utxos), 2)   # heights 1,2 survive the reorg
        self.assertEqual(len(k2_utxos), 3)   # alt heights 3,4,5


class TestNode(unittest.TestCase):
    def test_node_end_to_end(self):
        with tempfile.TemporaryDirectory() as td:
            node = Node(constants.REGTEST, os.path.join(td, "n1"),
                        port=0, listen=False)
            addr = node.wallet.new_address("bech32")
            spk = script.script_for_address(addr, constants.REGTEST)
            for _ in range(101):
                node.generate_block(spk)
            self.assertEqual(node.chain.height, 101)
            self.assertGreater(node.wallet.balance(node.chain), 0)
            # send coins to another address
            dest = WalletKey(555).address("bech32", constants.REGTEST)
            tx = node.wallet.send_to_address(
                node.chain, node.mempool, dest, 10 * constants.COIN)
            self.assertEqual(len(node.mempool), 1)
            node.generate_block(spk)
            self.assertEqual(len(node.mempool), 0)
            # dest's output exists
            coin = node.chain.get_utxo(tx.txid(), 0)
            self.assertIsNotNone(coin)
            self.assertEqual(coin.txout.value, 10 * constants.COIN)
            node.stop()

    def test_persistence(self):
        with tempfile.TemporaryDirectory() as td:
            n1 = Node(constants.REGTEST, td, port=0, listen=False)
            spk = n1.wallet.keys[0].script_p2wpkh if n1.wallet.keys else None
            n1.wallet.new_address()
            spk = n1.wallet.keys[0].script_p2wpkh
            n1.generate_block(spk)
            h = n1.chain.tip.hash
            n1.stop()

            n2 = Node(constants.REGTEST, td, port=0, listen=False)
            self.assertEqual(n2.chain.height, 1)
            self.assertEqual(n2.chain.tip.hash, h)
            self.assertEqual(len(n2.wallet.keys), 1)
            n2.stop()


if __name__ == "__main__":
    unittest.main()
