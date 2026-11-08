"""Bloom filters (BIP37) + compact block filters (BIP158 GCS).

Also provides SipHash-2-4 for BIP152 short transaction IDs.
"""

import math
import struct


# ---------------------------------------------------------------------------
# MurmurHash3 x86_32 (BIP37 uses it for bloom hashing)
# ---------------------------------------------------------------------------
def murmur3(data: bytes, seed: int = 0) -> int:
    c1, c2 = 0xcc9e2d51, 0x1b873593
    h = seed & 0xFFFFFFFF
    n = len(data) & ~3
    for i in range(0, n, 4):
        k = int.from_bytes(data[i:i + 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xe6546b64) & 0xFFFFFFFF
    k = 0
    tail = data[n:]
    for i, b in enumerate(tail):
        k |= b << (8 * i)
    if tail:
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85ebca6b) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xc2b2ae35) & 0xFFFFFFFF
    h ^= h >> 16
    return h


class BloomFilter:
    """BIP37 bloom filter."""

    MAX_SIZE = 36000
    MAX_FUNCS = 50
    TWEAK = 0xFBA4C795

    def __init__(self, n_elements: int, fp_rate: float,
                 tweak: int = TWEAK):
        size = max(1, int(-n_elements * math.log(fp_rate)
                          / (math.log(2) ** 2) / 8))
        self.data = bytearray(min(size, self.MAX_SIZE))
        self.n_funcs = min(self.MAX_FUNCS, int(
            len(self.data) * 8 / max(n_elements, 1) * math.log(2)) or 1)
        self.tweak = tweak

    def _hashes(self, item: bytes):
        nbits = len(self.data) * 8
        for i in range(self.n_funcs):
            seed = (i * self.TWEAK + self.tweak) & 0xFFFFFFFF
            yield murmur3(item, seed) % nbits

    def insert(self, item: bytes) -> None:
        for h in self._hashes(item):
            self.data[h >> 3] |= 1 << (h & 7)

    def contains(self, item: bytes) -> bool:
        return all(self.data[h >> 3] & (1 << (h & 7))
                   for h in self._hashes(item))


# ---------------------------------------------------------------------------
# SipHash-2-4 -- BIP152 short transaction IDs
# ---------------------------------------------------------------------------
def _rotl(x: int, b: int) -> int:
    return ((x << b) | (x >> (64 - b))) & 0xFFFFFFFFFFFFFFFF


def siphash(k0: int, k1: int, data: bytes) -> int:
    v0 = 0x736f6d6570736575 ^ k0
    v1 = 0x646f72616e646f6d ^ k1
    v2 = 0x6c7967656e657261 ^ k0
    v3 = 0x7465646279746573 ^ k1

    def rnd():
        nonlocal v0, v1, v2, v3
        v0 = (v0 + v1) & 0xFFFFFFFFFFFFFFFF
        v1 = _rotl(v1, 13); v1 ^= v0; v0 = _rotl(v0, 32)
        v2 = (v2 + v3) & 0xFFFFFFFFFFFFFFFF
        v3 = _rotl(v3, 16); v3 ^= v2
        v0 = (v0 + v3) & 0xFFFFFFFFFFFFFFFF
        v3 = _rotl(v3, 21); v3 ^= v0
        v2 = (v2 + v1) & 0xFFFFFFFFFFFFFFFF
        v1 = _rotl(v1, 17); v1 ^= v2; v2 = _rotl(v2, 32)

    n = len(data)
    for i in range(0, n & ~7, 8):
        m = int.from_bytes(data[i:i + 8], "little")
        v3 ^= m
        rnd(); rnd()
        v0 ^= m
    last = (n & 0xFF) << 56
    for i, b in enumerate(data[n & ~7:]):
        last |= b << (8 * i)
    v3 ^= last
    rnd(); rnd()
    v0 ^= last
    v2 ^= 0xFF
    for _ in range(4):
        rnd()
    return v0 ^ v1 ^ v2 ^ v3


def short_txid(txid: bytes, salt: int) -> bytes:
    """BIP152 6-byte short txid."""
    return siphash(salt, salt, txid).to_bytes(8, "little")[:6]


# ---------------------------------------------------------------------------
# GCS Golomb-Rice filters (BIP158)
# ---------------------------------------------------------------------------
def gcs_match(key: int, items: list, filter_data: bytes,
              n_items: int, p: int = 19, m: int = 784931) -> bool:
    """Does the GCS filter possibly contain any of `items`?

    `n_items` = number of elements the filter was built with (BIP158 stores
    it alongside the filter; the caller supplies it).
    """
    if not items or not filter_data or n_items <= 0:
        return False
    f = m * n_items
    # decode all stored deltas
    bits = []
    for byte in filter_data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    vals = []
    i = last = 0
    while i < len(bits):
        q = 0
        while i < len(bits) and bits[i] == 1:
            q += 1
            i += 1
        i += 1                      # the terminating 0
        if i + p > len(bits):
            break
        r = 0
        for j in range(p):
            r |= bits[i + j] << (p - 1 - j)
        i += p
        last += (q << p) + r
        vals.append(last)
    stored = set(vals)
    return any(siphash(key, key, it) % f in stored for it in items)


def build_gcs_filter(key: int, items: list, p: int = 19,
                     m: int = 784931) -> bytes:
    """BIP158 'basic' compact filter over block scripts."""
    # F = m * N where N = number of items
    n = len(items)
    if n == 0:
        return b""
    f = m * n
    vals = sorted(siphash(key, key, it) % f for it in items)

    # Golomb-Rice encode sorted deltas
    bits = []
    last = 0
    for v in vals:
        delta = v - last
        last = v
        q, r = divmod(delta, 1 << p)
        bits += [1] * q + [0]
        for i in range(p - 1, -1, -1):
            bits.append((r >> i) & 1)
    out = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i + 8]
        b = 0
        for j, bit in enumerate(chunk):
            b |= bit << (7 - j)
        out.append(b)
    return bytes(out)


def block_filter(block, key: int) -> tuple:
    """BIP158 basic filter for a block: hashes all output scriptPubKeys.

    Returns (filter_bytes, n_items)."""
    items = [o.script_pubkey for tx in block.txs for o in tx.vout
             if len(o.script_pubkey) > 0]
    return build_gcs_filter(key, items), len(items)
