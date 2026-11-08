"""Pure-Python AES-256 (CBC) used for wallet encryption.

Bitcoin Core encrypts wallets with AES-256-CBC under a key derived from the
passphrase via EVP_BytesToKey (SHA-512, 25,000 rounds). We mirror that.
"""

import hashlib

# ---------------------------------------------------------------------------
# AES primitives (tables generated from the GF(2^8) spec -- no lookup files)
# ---------------------------------------------------------------------------
def _xtime(a):
    return ((a << 1) ^ (0x1B if a & 0x80 else 0)) & 0xFF


def _gf_mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _gf_pow(a, e):
    r = 1
    while e:
        if e & 1:
            r = _gf_mul(r, a)
        a = _gf_mul(a, a)
        e >>= 1
    return r


def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


_SBOX = [0] * 256
_INV_SBOX = [0] * 256
for _i in range(256):
    _inv = 0 if _i == 0 else _gf_pow(_i, 254)
    _s = _inv ^ _rotl8(_inv, 1) ^ _rotl8(_inv, 2) ^ _rotl8(_inv, 3) \
        ^ _rotl8(_inv, 4) ^ 0x63
    _SBOX[_i] = _s
    _INV_SBOX[_s] = _i

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
         0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]


def _expand_key(key: bytes):
    """AES-256 key expansion -> 15 round keys of 16 bytes."""
    w = list(key)
    i = 8
    while len(w) < 240:
        t = w[-4:]
        if i % 8 == 0:
            t = [_SBOX[t[1]] ^ _RCON[i // 8 - 1],
                 _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
        elif i % 8 == 4:
            t = [_SBOX[b] for b in t]
        w += [w[len(w) - 32] ^ t[0], w[len(w) - 31] ^ t[1],
              w[len(w) - 30] ^ t[2], w[len(w) - 29] ^ t[3]]
        i += 1
    return [bytes(w[r * 16:(r + 1) * 16]) for r in range(15)]


def _shift(s, row, n):
    for _ in range(n):
        s[row], s[row + 4], s[row + 8], s[row + 12] = \
            s[row + 4], s[row + 8], s[row + 12], s[row]


def _ishift(s, row, n):
    for _ in range(n):
        s[row], s[row + 4], s[row + 8], s[row + 12] = \
            s[row + 12], s[row], s[row + 4], s[row + 8]


def _mix(s):
    for c in range(4):
        i = c * 4
        a = s[i:i + 4]
        s[i] = _gf_mul(a[0], 2) ^ _gf_mul(a[1], 3) ^ a[2] ^ a[3]
        s[i + 1] = a[0] ^ _gf_mul(a[1], 2) ^ _gf_mul(a[2], 3) ^ a[3]
        s[i + 2] = a[0] ^ a[1] ^ _gf_mul(a[2], 2) ^ _gf_mul(a[3], 3)
        s[i + 3] = _gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ _gf_mul(a[3], 2)


def _imix(s):
    for c in range(4):
        i = c * 4
        a = s[i:i + 4]
        s[i] = (_gf_mul(a[0], 14) ^ _gf_mul(a[1], 11)
                ^ _gf_mul(a[2], 13) ^ _gf_mul(a[3], 9))
        s[i + 1] = (_gf_mul(a[0], 9) ^ _gf_mul(a[1], 14)
                    ^ _gf_mul(a[2], 11) ^ _gf_mul(a[3], 13))
        s[i + 2] = (_gf_mul(a[0], 13) ^ _gf_mul(a[1], 9)
                    ^ _gf_mul(a[2], 14) ^ _gf_mul(a[3], 11))
        s[i + 3] = (_gf_mul(a[0], 11) ^ _gf_mul(a[1], 13)
                    ^ _gf_mul(a[2], 9) ^ _gf_mul(a[3], 14))


def encrypt_block(block: bytes, rkeys) -> bytes:
    s = [b ^ k for b, k in zip(block, rkeys[0])]
    for rnd in range(1, 14):
        s = [_SBOX[b] for b in s]
        _shift(s, 1, 1)
        _shift(s, 2, 2)
        _shift(s, 3, 3)
        _mix(s)
        s = [b ^ k for b, k in zip(s, rkeys[rnd])]
    s = [_SBOX[b] for b in s]
    _shift(s, 1, 1)
    _shift(s, 2, 2)
    _shift(s, 3, 3)
    return bytes(b ^ k for b, k in zip(s, rkeys[14]))


def decrypt_block(block: bytes, rkeys) -> bytes:
    s = [b ^ k for b, k in zip(block, rkeys[14])]
    for rnd in range(13, 0, -1):
        _ishift(s, 1, 1)
        _ishift(s, 2, 2)
        _ishift(s, 3, 3)
        s = [_INV_SBOX[b] for b in s]
        s = [b ^ k for b, k in zip(s, rkeys[rnd])]
        _imix(s)
    _ishift(s, 1, 1)
    _ishift(s, 2, 2)
    _ishift(s, 3, 3)
    s = [_INV_SBOX[b] for b in s]
    return bytes(b ^ k for b, k in zip(s, rkeys[0]))


def cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CBC on a multiple of 16 bytes (no padding)."""
    if len(data) % 16 or len(key) != 32 or len(iv) != 16:
        raise ValueError("bad CBC parameters")
    rkeys = _expand_key(key)
    out, prev = b"", iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = encrypt_block(blk, rkeys)
        out += prev
    return out


def cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    rkeys = _expand_key(key)
    out, prev = b"", iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(decrypt_block(blk, rkeys), prev))
        prev = blk
    return out


# ---------------------------------------------------------------------------
# Key derivation -- OpenSSL EVP_BytesToKey(SHA-512, AES-256-CBC) equivalent
# ---------------------------------------------------------------------------
def derive_key_iv(passphrase: bytes, salt: bytes, rounds: int = 25000):
    """Returns (32-byte key, 16-byte iv) exactly like bitcoind's derivation."""
    d = hashlib.sha512(passphrase + salt).digest()
    for _ in range(rounds - 1):
        d = hashlib.sha512(d).digest()
    return d[:32], d[32:48]
