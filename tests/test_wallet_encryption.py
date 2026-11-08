"""Wallet encryption tests (Bitcoin-style: AES-256-CBC + passphrase)."""

import os
import tempfile
import unittest

from alpha import aes, constants, miner
from alpha.wallet import Wallet, WalletKey, WalletLocked


class TestAES(unittest.TestCase):
    def test_fips197(self):
        key = bytes.fromhex(
            "603deb1015ca71be2b73aef0857d7781"
            "1f352c073b6108d72d9810a30914dff4")
        pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        rks = aes._expand_key(key)
        ct = aes.encrypt_block(pt, rks)
        self.assertEqual(ct.hex(),
                         "f3eed1bdb5d2a03c064b5a7e3db181f8")
        self.assertEqual(aes.decrypt_block(ct, rks), pt)


class TestEncryption(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.w = Wallet(constants.REGTEST,
                        os.path.join(self.td.name, "w.json"))
        self.key = self.w.new_key()
        self.addr = self.key.address("bech32", constants.REGTEST)

    def tearDown(self):
        self.td.cleanup()

    def test_encrypt_lock_unlock(self):
        self.w.encrypt("pw")
        self.assertTrue(self.w.is_encrypted())
        self.assertTrue(self.w.is_locked())
        with self.assertRaises(WalletLocked):
            self.w.new_key()
        with self.assertRaises(ValueError):
            self.w.unlock("bad")
        self.w.unlock("pw", 300)
        self.assertFalse(self.w.is_locked())
        self.w.lock()
        self.assertTrue(self.w.is_locked())

    def test_disk_has_no_plaintext(self):
        self.w.encrypt("pw")
        raw = open(self.w.path).read()
        self.assertIn('"encrypted": true', raw)
        self.assertNotIn("keys\":[\"", raw)  # no plaintext WIFs

    def test_reload_still_encrypted(self):
        self.w.encrypt("pw")
        w2 = Wallet(constants.REGTEST, self.w.path)
        self.assertTrue(w2.is_encrypted())
        self.assertTrue(w2.is_locked())
        w2.unlock("pw", 60)
        self.assertIn(self.addr, w2.addresses())
        self.assertTrue(w2.export_wif(self.addr).startswith(("9", "c")))

    def test_change_passphrase(self):
        self.w.encrypt("old")
        self.w.unlock("old", 60)
        self.w.change_passphrase("old", "new")
        with self.assertRaises(ValueError):
            self.w.unlock("old")
        self.w.unlock("new", 60)
        self.assertFalse(self.w.is_locked())

    def test_balance_visible_while_locked(self):
        # addresses list derivable from stored pubkeys even when locked
        self.w.encrypt("pw")
        self.assertIn(self.addr, self.w.addresses())


if __name__ == "__main__":
    unittest.main()
