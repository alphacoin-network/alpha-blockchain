"""Known-answer tests using real Bitcoin vectors.

If our primitives reproduce Bitcoin's genesis block hash, Satoshi's
address, and well-known key/address vectors, the wire formats are
byte-for-byte compatible.
"""

import unittest

from alpha import base58, constants, crypto, script, utils
from alpha.block import Block, BlockHeader, merkle_root
from alpha.blockchain import make_genesis_block
from alpha.transaction import OutPoint, Transaction, TxIn, TxOut
from alpha.utils import hash160, hex_to_hash, sha256d
from alpha.wallet import wif_decode, wif_encode, WalletKey


# The real Bitcoin genesis block: hash
BTC_GENESIS_HASH = (
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
BTC_GENESIS_MERKLE = (
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
SATOSHI_PUBKEY = bytes.fromhex(
    "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6"
    "49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")
SATOSHI_ADDRESS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


class TestBitcoinVectors(unittest.TestCase):
    def test_genesis_block_reproduction(self):
        """Rebuild Bitcoin's genesis block and check its hash."""
        msg = (b"The Times 03/Jan/2009 Chancellor on brink of second "
               b"bailout for banks")
        script_sig = (b"\x04" + (0x1D00FFFF).to_bytes(4, "little")
                      + b"\x01\x04" + script.push_data(msg))
        coinbase = Transaction(
            version=1,
            vin=[TxIn(prevout=OutPoint(b"\x00" * 32, 0xFFFFFFFF),
                      script_sig=script_sig, sequence=0xFFFFFFFF)],
            vout=[TxOut(50 * constants.COIN, script.script_p2pk(SATOSHI_PUBKEY))],
            locktime=0)
        self.assertEqual(coinbase.txid()[::-1].hex(), BTC_GENESIS_MERKLE)

        header = BlockHeader(version=1, prev_hash=b"\x00" * 32,
                             merkle=coinbase.txid(), timestamp=1231006505,
                             bits=0x1D00FFFF, nonce=2083236893)
        block = Block(header, [coinbase])
        self.assertEqual(block.hash_hex(), BTC_GENESIS_HASH)
        self.assertTrue(header.check_pow(0x1D00FFFF))

    def test_satoshi_address(self):
        spk = script.script_p2pkh(hash160(SATOSHI_PUBKEY))
        addr = script.extract_destination(spk, constants.MAINNET)
        self.assertEqual(addr, SATOSHI_ADDRESS)

    def test_privkey1_address(self):
        """privkey=1, compressed pubkey -> 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"""
        key = WalletKey(1, compressed=True)
        self.assertEqual(
            key.address("legacy", constants.MAINNET),
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")

    def test_wif_roundtrip(self):
        # known WIF for privkey=1 compressed (Bitcoin mainnet)
        wif = wif_encode(1, constants.MAINNET, compressed=True)
        self.assertEqual(wif, "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")
        priv, comp = wif_decode(wif, constants.MAINNET)
        self.assertEqual((priv, comp), (1, True))

    def test_base58_check(self):
        payload = bytes([0x00]) + hash160(SATOSHI_PUBKEY)
        self.assertEqual(base58.b58encode_check(payload), SATOSHI_ADDRESS)
        self.assertEqual(base58.b58decode_check(SATOSHI_ADDRESS), payload)

    def test_bech32_known_vector(self):
        """BIP173 test vector: P2WPKH for a fixed witness program."""
        prog = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
        addr = __import__("alpha.bech32", fromlist=["x"]) \
            .encode_segwit_address("bc", 0, prog)
        self.assertEqual(addr, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")

    def test_merkle_root(self):
        # single element -> itself; pairs hashed together
        h = sha256d(b"x")
        self.assertEqual(merkle_root([h]), h)
        a, b = sha256d(b"a"), sha256d(b"b")
        self.assertEqual(merkle_root([a, b]), sha256d(a + b))
        # odd count duplicates the last
        c = sha256d(b"c")
        self.assertEqual(
            merkle_root([a, b, c]),
            sha256d(sha256d(a + b) + sha256d(c + c)))

    def test_bits_target_roundtrip(self):
        for bits in (0x1D00FFFF, 0x207FFFFF, 0x1C0FFFFF):
            target = utils.compact_to_target(bits)
            self.assertEqual(utils.target_to_compact(target), bits)

    def test_subsidy_total_supply(self):
        """Total issuance == Bitcoin's: 20,999,999.9769 coins."""
        total = 0
        for h in range(33):
            subs = constants.INITIAL_SUBSIDY >> h
            total += constants.HALVING_INTERVAL * subs
        self.assertEqual(total, 2_099_999_997_690_000)  # in alphasats
        self.assertLess(total, constants.MAX_MONEY)

    def test_ecdsa_sign_verify(self):
        msg = sha256d(b"hello alpha")
        sig_der = crypto.ecdsa_sign_der(msg, 7)
        self.assertTrue(crypto.is_valid_der(sig_der))
        self.assertTrue(crypto.ecdsa_verify(
            msg, sig_der, crypto.pubkey_from_privkey(7)))
        self.assertFalse(crypto.ecdsa_verify(
            sha256d(b"other"), sig_der, crypto.pubkey_from_privkey(7)))

    def test_secp256k1_G(self):
        p = crypto.point_mul(1)
        self.assertEqual(p, crypto.G)
        self.assertIsNone(crypto.point_mul(crypto.ORDER_N))
        self.assertEqual(crypto.serialize_pubkey(crypto.G),
                         bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07"
                                       "029bfcdb2dce28d959f2815b16f81798"))

    def test_script_num_codec(self):
        for v in (0, 1, -1, 127, 128, -128, 255, 256, -256, 32767, -32768,
                  2**31 - 1, -(2**31) + 1, 2**32):
            enc = utils.encode_script_num(v)
            self.assertEqual(utils.decode_script_num(enc, max_size=5), v)


if __name__ == "__main__":
    unittest.main()
