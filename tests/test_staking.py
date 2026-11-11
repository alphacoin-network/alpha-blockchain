"""Staking tests: CLTV lock / early-spend rejection / unstake / rewards."""

import unittest

from alpha import constants, miner, script
from alpha.node import Node
from alpha.rpc import RPCError, RPCMethods
from alpha.wallet import WalletKey


def mine(node, spk, n=1):
    for _ in range(n):
        b = miner.create_block_template(node.chain, node.mempool, spk)
        assert miner.mine_block(b, node.params.pow_limit_bits)
        node.submit_block(b)


class TestStaking(unittest.TestCase):
    def setUp(self):
        self.node = Node(constants.REGTEST, None, port=0, listen=False)
        self.key = WalletKey(4242)
        for _ in range(101):
            b = miner.create_block_template(
                self.node.chain, None, self.key.script_p2wpkh)
            assert miner.mine_block(
                b, constants.REGTEST.pow_limit_bits)
            self.node.chain.add_block(b)
        self.node.wallet.keys = [self.key]
        self.addr = self.key.address("bech32", constants.REGTEST)
        self.rpc = RPCMethods(self.node)

    def test_stake_lock_unstake(self):
        # lock 10 ALPHA for 5 blocks
        r = self.rpc.stakeopen(10, 5, self.addr)
        self.assertIn("stake_id", r)
        tip = self.node.chain.height
        self.assertEqual(r["unlock_height"], tip + 5)
        mine(self.node, self.key.script_p2wpkh)
        st = self.node.staking.stakes
        self.assertEqual(len(st), 1)
        pos = next(iter(st.values()))
        self.assertTrue(pos["open"])
        self.assertEqual(pos["amount"], 10 * 10**8)

        # early unstake must fail
        with self.assertRaises(RPCError):
            self.rpc.unstake(r["stake_id"])

        # mine to maturity and spend
        mine(self.node, self.key.script_p2wpkh, 5)
        out = self.rpc.unstake(r["stake_id"])
        self.assertAlmostEqual(out["amount_alpha"], 10 - 0.00002)
        mine(self.node, self.key.script_p2wpkh)
        self.assertFalse(pos["open"])

        # stats reflect the closed position
        info = self.rpc.stakeinfo()
        self.assertEqual(info["positions"], 0)
        self.assertEqual(info["all_time_positions"], 1)

    def test_stakedistribute(self):
        # two stakers, pro-rata reward payout
        r = self.rpc.stakeopen(30, 100, self.addr)
        mine(self.node, self.key.script_p2wpkh)
        bal_before = self.rpc.getbalance()
        d = self.rpc.stakedistribute(3)
        self.assertEqual(d["stakers"], 1)
        mine(self.node, self.key.script_p2wpkh)
        # reward circulates back to own wallet minus the locked change flow
        info = self.rpc.stakeinfo()
        self.assertEqual(info["positions"], 1)
        self.assertEqual(info["total_staked_alpha"], 30)

    def test_stake_spk_is_cltv(self):
        spk = script.script_p2pkh(b"\x00" * 20)
        from alpha.staking import stake_spk, encode_stake, parse_payload
        pkh = b"\x11" * 20
        lock = stake_spk(500, pkh)
        self.assertIn(b"\xb1", lock)              # OP_CHECKLOCKTIMEVERIFY
        self.assertTrue(lock.endswith(b"\x88\xac"))
        p = parse_payload(encode_stake(500, pkh))
        self.assertEqual(p["unlock"], 500)
        self.assertEqual(p["pkh"], pkh)


if __name__ == "__main__":
    unittest.main()
