"""BIP32 hierarchical deterministic (HD) keys -- same as Bitcoin's.

Master key from a seed, hardened/normal child derivation, xprv/xpub
serialization, and standard path derivation (m/44'/0'/0'/...).
"""

import hashlib
import hmac
import struct

from . import crypto
from .base58 import b58decode_check, b58encode_check

HARDENED = 0x80000000

_XPRV_VERSIONS = {0x0488B21E, 0x04358394}
_XPUB_VERSIONS = {0x0488ADE4, 0x043587CF}


class HDKey:
    __slots__ = ("priv", "pub", "chain", "depth", "fingerprint", "child")

    def __init__(self, priv, pub, chain, depth=0, fingerprint=b"\x00"*4,
                 child=0):
        self.priv = priv          # int or None (watch-only)
        self.pub = pub            # 33-byte compressed pubkey
        self.chain = chain
        self.depth = depth
        self.fingerprint = fingerprint
        self.child = child

    # -- construction -----------------------------------------------------------
    @staticmethod
    def from_seed(seed: bytes) -> "HDKey":
        i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        priv = int.from_bytes(i[:32], "big")
        if not crypto.valid_privkey(priv):
            raise ValueError("bad seed")
        return HDKey(priv, crypto.serialize_pubkey(
            crypto.pubkey_from_privkey(priv)), i[32:])

    @staticmethod
    def parse(xkey: str) -> "HDKey":
        raw = b58decode_check(xkey)
        if len(raw) != 78:
            raise ValueError("bad xkey length")
        ver = struct.unpack(">I", raw[:4])[0]
        depth = raw[4]
        fp = raw[5:9]
        child = struct.unpack(">I", raw[9:13])[0]
        chain = raw[13:45]
        data = raw[45:]
        if ver in _XPRV_VERSIONS:
            if data[0] != 0:
                raise ValueError("bad xprv payload")
            priv = int.from_bytes(data[1:], "big")
            pub = crypto.serialize_pubkey(crypto.pubkey_from_privkey(priv))
        elif ver in _XPUB_VERSIONS:
            priv = None
            pub = data
        else:
            raise ValueError("unknown xkey version")
        return HDKey(priv, pub, chain, depth, fp, child)

    # -- serialization ------------------------------------------------------------
    def _serialize(self, version: int, data: bytes) -> str:
        payload = (struct.pack(">I", version) + bytes([self.depth])
                   + self.fingerprint + struct.pack(">I", self.child)
                   + self.chain + data)
        return b58encode_check(payload)

    def xprv(self, mainnet: bool = True) -> str:
        if self.priv is None:
            raise ValueError("watch-only key has no private part")
        return self._serialize(
            0x0488B21E if mainnet else 0x04358394,
            b"\x00" + self.priv.to_bytes(32, "big"))

    def xpub(self, mainnet: bool = True) -> str:
        return self._serialize(
            0x0488ADE4 if mainnet else 0x043587CF, self.pub)

    def neutered(self) -> "HDKey":
        return HDKey(None, self.pub, self.chain, self.depth,
                     self.fingerprint, self.child)

    # -- derivation -----------------------------------------------------------------
    def _fingerprint(self) -> bytes:
        from .utils import hash160
        return hash160(self.pub)[:4]

    def ckd(self, index: int) -> "HDKey":
        hardened = index & HARDENED
        if hardened and self.priv is None:
            raise ValueError("cannot derive hardened from xpub")
        if hardened:
            data = b"\x00" + self.priv.to_bytes(32, "big") \
                + struct.pack(">I", index)
        else:
            data = self.pub + struct.pack(">I", index)
        i = hmac.new(self.chain, data, hashlib.sha512).digest()
        il, ir = i[:32], i[32:]
        tweak = int.from_bytes(il, "big")
        if tweak >= crypto.ORDER_N:
            return self.ckd(index + 1)  # BIP32 skip rule
        if self.priv is not None:
            priv = (tweak + self.priv) % crypto.ORDER_N
            if priv == 0:
                return self.ckd(index + 1)
            pub = crypto.serialize_pubkey(crypto.pubkey_from_privkey(priv))
        else:
            priv = None
            point = crypto.point_add(crypto.point_mul(tweak),
                                     crypto.parse_pubkey(self.pub))
            pub = crypto.serialize_pubkey(point)
        return HDKey(priv, pub, ir, self.depth + 1, self._fingerprint(),
                     index)

    def derive(self, path: str) -> "HDKey":
        """Path like m/44'/0'/0'/0/5 (hardened marked ' or h)."""
        node = self
        for comp in path.replace("m/", "").split("/"):
            if not comp:
                continue
            hardened = comp.endswith(("'", "h", "H"))
            idx = int(comp.rstrip("'hH"))
            if hardened:
                idx |= HARDENED
            node = node.ckd(idx)
        return node


def seed_from_mnemonic(words: str, passphrase: str = "") -> bytes:
    """BIP39 mnemonic -> 64-byte seed (PBKDF2-HMAC-SHA512, 2048 rounds)."""
    return hashlib.pbkdf2_hmac(
        "sha512", words.encode("utf-8"),
        b"mnemonic" + passphrase.encode("utf-8"), 2048)
