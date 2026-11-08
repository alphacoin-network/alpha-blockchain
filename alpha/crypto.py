"""Elliptic-curve crypto on secp256k1 -- the same curve Bitcoin uses.

Pure Python, no dependencies:
  * ECDSA signing with deterministic nonces (RFC 6979, like libsecp256k1)
  * Low-S normalization (BIP62)
  * DER signature encode/decode incl. strict-DER checks (BIP66)
  * Public key serialization (compressed & uncompressed)
"""

import hmac
import secrets
from hashlib import sha256

from .utils import sha256d

# ---------------------------------------------------------------------------
# secp256k1 domain parameters (identical to Bitcoin)
# ---------------------------------------------------------------------------
FIELD_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
ORDER_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
CURVE_A = 0
CURVE_B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)

# Point at infinity is represented as None.


def is_on_curve(p) -> bool:
    if p is None:
        return True
    x, y = p
    return (y * y - (x * x * x + CURVE_B)) % FIELD_P == 0


def point_neg(p):
    if p is None:
        return None
    return (p[0], (-p[1]) % FIELD_P)


def point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2:
        if (y1 + y2) % FIELD_P == 0:
            return None
        # doubling
        lam = (3 * x1 * x1) * pow(2 * y1, FIELD_P - 2, FIELD_P) % FIELD_P
    else:
        lam = (y2 - y1) * pow((x2 - x1) % FIELD_P, FIELD_P - 2, FIELD_P) % FIELD_P
    x3 = (lam * lam - x1 - x2) % FIELD_P
    y3 = (lam * (x1 - x3) - y1) % FIELD_P
    return (x3, y3)


def point_mul(k: int, p=G):
    if p is None or k % ORDER_N == 0:
        return None
    k %= ORDER_N
    result = None
    addend = p
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------
def generate_privkey() -> int:
    return secrets.randbelow(ORDER_N - 1) + 1


def valid_privkey(d: int) -> bool:
    return 1 <= d < ORDER_N


def pubkey_from_privkey(d: int):
    if not valid_privkey(d):
        raise ValueError("invalid private key")
    return point_mul(d, G)


def serialize_pubkey(p, compressed: bool = True) -> bytes:
    if p is None:
        raise ValueError("cannot serialize point at infinity")
    x, y = p
    if compressed:
        return bytes([0x02 | (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def parse_pubkey(data: bytes):
    if len(data) == 33 and data[0] in (0x02, 0x03):
        x = int.from_bytes(data[1:], "big")
        if x >= FIELD_P:
            raise ValueError("x coordinate out of range")
        # y = sqrt(x^3 + 7); FIELD_P % 4 == 3 so a simple pow works
        y = pow((x * x * x + CURVE_B) % FIELD_P, (FIELD_P + 1) // 4, FIELD_P)
        if (y & 1) != (data[0] & 1):
            y = FIELD_P - y
        p = (x, y)
    elif len(data) == 65 and data[0] == 0x04:
        x = int.from_bytes(data[1:33], "big")
        y = int.from_bytes(data[33:65], "big")
        p = (x, y)
    elif len(data) == 33 and data[0] in (0x06, 0x07):  # old hybrid, reject
        raise ValueError("hybrid pubkeys unsupported")
    else:
        raise ValueError("bad public key encoding")
    if not is_on_curve(p):
        raise ValueError("public key not on curve")
    return p


def is_valid_pubkey(data: bytes) -> bool:
    try:
        parse_pubkey(data)
        return True
    except ValueError:
        return False


def is_compressed_pubkey(data: bytes) -> bool:
    return len(data) == 33 and data[0] in (0x02, 0x03)


# ---------------------------------------------------------------------------
# RFC 6979 deterministic nonce generation (HMAC-SHA256)
# ---------------------------------------------------------------------------
def _rfc6979_nonce(priv: int, msg32: bytes, extra_entropy: bytes = b"") -> int:
    x = priv.to_bytes(32, "big")
    h1 = msg32  # already a 32-byte hash
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h1 + extra_entropy, sha256).digest()
    v = hmac.new(k, v, sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h1 + extra_entropy, sha256).digest()
    v = hmac.new(k, v, sha256).digest()
    while True:
        v = hmac.new(k, v, sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < ORDER_N:
            return candidate
        k = hmac.new(k, v + b"\x00", sha256).digest()
        v = hmac.new(k, v, sha256).digest()


# ---------------------------------------------------------------------------
# DER signatures
# ---------------------------------------------------------------------------
def der_encode_sig(r: int, s: int) -> bytes:
    def enc_int(v: int) -> bytes:
        b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b

    rb = enc_int(r)
    sb = enc_int(s)
    body = b"\x02" + bytes([len(rb)]) + rb + b"\x02" + bytes([len(sb)]) + sb
    return b"\x30" + bytes([len(body)]) + body


def der_decode_sig(sig: bytes, strict: bool = True):
    """Decode a DER (r, s) pair.

    With strict=True this enforces BIP66 strict-DER (the same checks Bitcoin
    applies on mainnet since block 363,724).
    """
    if len(sig) < 8 or len(sig) > 72:
        raise ValueError("bad DER length")
    if sig[0] != 0x30:
        raise ValueError("bad DER prefix")
    if sig[1] != len(sig) - 2:
        raise ValueError("bad DER total length")
    if sig[2] != 0x02:
        raise ValueError("missing R integer")
    len_r = sig[3]
    if len_r == 0 or 5 + len_r >= len(sig):
        raise ValueError("bad R length")
    r = int.from_bytes(sig[4:4 + len_r], "big")
    pos = 4 + len_r
    if sig[pos] != 0x02:
        raise ValueError("missing S integer")
    len_s = sig[pos + 1]
    if len_s == 0 or pos + 2 + len_s != len(sig):
        raise ValueError("bad S length")
    s = int.from_bytes(sig[pos + 2:pos + 2 + len_s], "big")
    if strict:
        if len_r > 1 and sig[4] == 0x00 and not (sig[5] & 0x80):
            raise ValueError("R has unnecessary padding")
        if len_r > 1 and sig[4] & 0x80:
            raise ValueError("R is negative")
        if len_s > 1 and sig[pos + 2] == 0x00 and not (sig[pos + 3] & 0x80):
            raise ValueError("S has unnecessary padding")
        if sig[pos + 2] & 0x80:
            raise ValueError("S is negative")
    if not (1 <= r < ORDER_N and 1 <= s < ORDER_N):
        raise ValueError("signature values out of range")
    return r, s


def is_valid_der(sig: bytes) -> bool:
    try:
        der_decode_sig(sig, strict=True)
        return True
    except (ValueError, IndexError):
        return False


# ---------------------------------------------------------------------------
# ECDSA
# ---------------------------------------------------------------------------
def ecdsa_sign(msg32: bytes, priv: int, extra_entropy: bytes = b""):
    """Deterministically sign a 32-byte hash. Returns (r, s) with low-S."""
    if len(msg32) != 32:
        raise ValueError("must sign a 32-byte hash")
    z = int.from_bytes(msg32, "big")
    attempt = 0
    while True:
        k = _rfc6979_nonce(priv, msg32, extra_entropy if attempt == 0 else
                           extra_entropy + attempt.to_bytes(4, "big"))
        x, _ = point_mul(k, G)
        r = x % ORDER_N
        if r == 0:
            attempt += 1
            continue
        s = (pow(k, ORDER_N - 2, ORDER_N) * (z + r * priv)) % ORDER_N
        if s == 0:
            attempt += 1
            continue
        if s > ORDER_N // 2:  # BIP62: normalize to low-S
            s = ORDER_N - s
        return r, s


def ecdsa_sign_der(msg32: bytes, priv: int, extra_entropy: bytes = b"") -> bytes:
    r, s = ecdsa_sign(msg32, priv, extra_entropy)
    return der_encode_sig(r, s)


def ecdsa_recover(msg32: bytes, r: int, s: int, recid: int):
    """Recover the public key point from a signature + recovery id (0..3).

    Same math Bitcoin uses for `signmessage`/`verifymessage` compact sigs.
    """
    if not (0 <= recid <= 3 and 1 <= r < ORDER_N and 1 <= s < ORDER_N):
        return None
    x = r + (recid >> 1) * ORDER_N
    if x >= FIELD_P:
        return None
    y = pow((x * x * x + CURVE_B) % FIELD_P, (FIELD_P + 1) // 4, FIELD_P)
    if (y & 1) != (recid & 1):
        y = FIELD_P - y
    R = (x, y)
    if not is_on_curve(R) or point_mul(ORDER_N, R) is not None:
        return None
    e = int.from_bytes(msg32, "big") % ORDER_N
    r_inv = pow(r, ORDER_N - 2, ORDER_N)
    # Q = r^-1 * (s*R - e*G)
    return point_mul(r_inv, point_add(
        point_mul(s, R), point_neg(point_mul(e, G))))


def ecdsa_verify(msg32: bytes, sig, pubkey) -> bool:
    """Verify (r, s) or DER-encoded signature against a point or pubkey bytes."""
    if len(msg32) != 32:
        return False
    try:
        if isinstance(sig, (bytes, bytearray)):
            r, s = der_decode_sig(bytes(sig), strict=False)
        else:
            r, s = sig
        if not (1 <= r < ORDER_N and 1 <= s < ORDER_N):
            return False
        if isinstance(pubkey, (bytes, bytearray)):
            q = parse_pubkey(bytes(pubkey))
        else:
            q = pubkey
        z = int.from_bytes(msg32, "big")
        w = pow(s, ORDER_N - 2, ORDER_N)
        u1 = (z * w) % ORDER_N
        u2 = (r * w) % ORDER_N
        p = point_add(point_mul(u1, G), point_mul(u2, q))
        if p is None:
            return False
        return p[0] % ORDER_N == r
    except (ValueError, IndexError, ZeroDivisionError):
        return False


# ---------------------------------------------------------------------------
# Convenience: private key <-> hex
# ---------------------------------------------------------------------------
def privkey_to_bytes(d: int) -> bytes:
    return d.to_bytes(32, "big")


def privkey_from_bytes(b: bytes) -> int:
    if len(b) != 32:
        raise ValueError("private key must be 32 bytes")
    d = int.from_bytes(b, "big")
    if not valid_privkey(d):
        raise ValueError("private key out of range")
    return d
