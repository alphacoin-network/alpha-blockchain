"""Consensus-rule tests: halving boundary, P2SH multisig, P2PK, difficulty
retarget math, and supply invariants on regtest.
"""

import unittest

from alpha import constants, crypto, miner, script
from alpha.blockchain import Blockchain
from alpha.mempool import Mempool
from alpha.transaction import OutPoint, Transaction, TxIn, TxOut
from alpha.utils import hash160
from alpha.wallet import WalletKey


def chain():
    return Blockchain(constants.REGTEST)


def mine(chain, key, n=1):
    for _ in range(n):
        b = miner.create_block_template(chain, None, key.script_p2wpkh)
        assert miner.mine_block(b, chain.params.pow_limit_bits)
        chain.add_block(b)


class TestHalving(unittest.TestCase):
    def test_subsidy_schedule(self):
        c = chain()
        self.assertEqual(c.subsidy(0), 50 * constants.COIN)
        # regtest halves every 150 blocks (like Bitcoin Core regtest)
        self.assertEqual(c.subsidy(149), 50 * constants.COIN)
        self.assertEqual(c.subsidy(150), 25 * constants.COIN)
        self.assertEqual(c.subsidy(300), 1_250_000_000)  # 12.5 coins
        self.assertEqual(c.subsidy(150 * 32), 1)             # 1 alphasat
        self.assertEqual(c.subsidy(150 * 33), 0)

    def test_mainnet_schedule(self):
        c = Blockchain(constants.MAINNET)
        self.assertEqual(c.subsidy(0), 50 * constants.COIN)
        self.assertEqual(c.subsidy(209_999), 50 * constants.COIN)
        self.assertEqual(c.subsidy(210_000), 25 * constants.COIN)
        self.assertEqual(c.subsidy(420_000), 1_250_000_000)
        self.assertEqual(c.subsidy(630_000), 625_000_000)


class TestDifficulty(unittest.TestCase):
    def test_retarget_math(self):
        """Blocks arriving 2x too fast -> difficulty target ~halves at the
        2016-block boundary (Bitcoin's exact retarget rule)."""
        from alpha.block import Block, BlockHeader
        from alpha import utils
        c = chain()
        key = WalletKey(3)
        spacing = c.params.pow_target_spacing // 2   # 5-minute blocks
        for i in range(2016):
            entry = c.tip
            cb = miner.create_coinbase(i + 1, c.params, key.script_p2wpkh, 0)
            b = Block(BlockHeader(
                version=1, prev_hash=entry.hash, merkle=cb.txid(),
                timestamp=entry.header.timestamp + spacing,
                bits=c.next_work_required(entry), nonce=0), [cb])
            assert miner.mine_block(b, c.params.pow_limit_bits)
            c.add_block(b)
        # block 2016 carried the retargeted difficulty
        new_target = utils.compact_to_target(c.tip.header.bits)
        limit = utils.compact_to_target(c.params.pow_limit_bits)
        ratio = limit / new_target
        self.assertGreater(ratio, 1.8)
        self.assertLess(ratio, 2.2)


class TestScripts(unittest.TestCase):
    def setUp(self):
        self.chain = chain()
        self.key = WalletKey(50)
        mine(self.chain, self.key, 105)
        self.mempool = Mempool(self.chain)

    def _coin(self):
        for (txid, n), c in self.chain.utxo.items():
            if (c.txout.script_pubkey == self.key.script_p2wpkh
                    and self.chain.height - c.height >= 100):
                return txid, n, c
        raise AssertionError("no mature coin")

    def _pay(self, spk, value):
        txid, n, c = self._coin()
        tx = Transaction(version=2,
                         vin=[TxIn(prevout=OutPoint(txid, n))],
                         vout=[TxOut(value, spk),
                               TxOut(c.txout.value - value - 500,
                                     self.key.script_p2wpkh)],
                         locktime=0)
        code = script.script_p2pkh(self.key.pubkey_hash)
        sighash = tx.signature_hash_v0(code, 0, c.txout.value, 1)
        sig = crypto.ecdsa_sign_der(sighash, self.key.priv) + b"\x01"
        tx.vin[0].witness = [sig, self.key.pubkey]
        self.mempool.accept(tx)
        return tx

    def test_p2sh_multisig_2of3(self):
        """2-of-3 P2SH multisig: fund, then spend with two signatures."""
        keys = [WalletKey(i) for i in (101, 102, 103)]
        redeem = script.script_multisig(2, [k.pubkey for k in keys])
        spk = script.script_p2sh(hash160(redeem))
        fund = self._pay(spk, 20 * constants.COIN)
        mine(self.chain, self.key, 1)
        self.mempool.remove_for_block(self.chain.get_block(
            self.chain.tip.hash))

        spend = Transaction(
            version=2,
            vin=[TxIn(prevout=OutPoint(fund.txid(), 0))],
            vout=[TxOut(20 * constants.COIN - 1000,
                        self.key.script_p2wpkh)],
            locktime=0)
        sighash = spend.signature_hash(redeem, 0, 1)
        sig1 = crypto.ecdsa_sign_der(sighash, keys[0].priv) + b"\x01"
        sig2 = crypto.ecdsa_sign_der(sighash, keys[1].priv) + b"\x01"
        # P2SH multisig scriptSig: OP_0 <sig1> <sig2> <redeem>
        spend.vin[0].script_sig = (
            script.push_data(b"") + script.push_data(sig1)
            + script.push_data(sig2) + script.push_data(redeem))
        fee = self.mempool.accept(spend)
        self.assertEqual(fee, 1000)

    def test_p2sh_multisig_wrong_sigs_rejected(self):
        keys = [WalletKey(i) for i in (201, 202, 203)]
        redeem = script.script_multisig(2, [k.pubkey for k in keys])
        spk = script.script_p2sh(hash160(redeem))
        fund = self._pay(spk, 20 * constants.COIN)
        mine(self.chain, self.key, 1)
        self.mempool.remove_for_block(
            self.chain.get_block(self.chain.tip.hash))

        spend = Transaction(
            version=2,
            vin=[TxIn(prevout=OutPoint(fund.txid(), 0))],
            vout=[TxOut(20 * constants.COIN - 1000,
                        self.key.script_p2wpkh)],
            locktime=0)
        sighash = spend.signature_hash(redeem, 0, 1)
        # only ONE valid signature for a 2-of-3
        sig1 = crypto.ecdsa_sign_der(sighash, keys[0].priv) + b"\x01"
        spend.vin[0].script_sig = (
            script.push_data(b"") + script.push_data(sig1)
            + script.push_data(b"") + script.push_data(redeem))
        from alpha.mempool import MempoolError
        with self.assertRaises(MempoolError):
            self.mempool.accept(spend)


class TestSupplyInvariant(unittest.TestCase):
    def test_cannot_create_money(self):
        """A block paying more than subsidy+fees must be rejected."""
        c = chain()
        key = WalletKey(9)
        b = miner.create_block_template(c, None, key.script_p2wpkh)
        # inflate the coinbase reward by 1 alphasat
        b.txs[0].vout[0].value += 1
        b.compute_merkle()
        assert miner.mine_block(b, c.params.pow_limit_bits)
        from alpha.blockchain import ChainError
        with self.assertRaises(ChainError):
            c.add_block(b)

    def test_nonexistent_input_rejected(self):
        c = chain()
        mempool = Mempool(c)
        tx = Transaction(
            version=2,
            vin=[TxIn(prevout=OutPoint(b"\x11" * 32, 0))],
            vout=[TxOut(1000, b"\x6a")],
            locktime=0)
        from alpha.mempool import MempoolError
        with self.assertRaises(MempoolError):
            mempool.accept(tx)


if __name__ == "__main__":
    unittest.main()
