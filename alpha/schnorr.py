"""BIP340 Schnorr signatures on secp256k1 (Taproot's signature scheme)."""

import hashlib
import secrets as _secrets

from . import crypto


def _tagged(tag: str, msg: bytes) -> bytes:
    th = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th + th + msg).digest()


def _lift_x(x: int):
    if x >= crypto.FIELD_P:
        return None
    y = pow((x * x * x + crypto.CURVE_B) % crypto.FIELD_P,
            (crypto.FIELD_P + 1) // 4, crypto.FIELD_P)
    if y & 1:
        y = crypto.FIELD_P - y
    return (x, y)


def xonly_pubkey(priv: int) -> bytes:
    p = crypto.point_mul(priv)
    return p[0].to_bytes(32, "big")


def schnorr_sign(msg32: bytes, priv: int, aux: bytes = b"") -> bytes:
    """BIP340 sign -> 64-byte signature."""
    if len(msg32) != 32:
        raise ValueError("need 32-byte msg")
    p = crypto.point_mul(priv)
    if p[1] & 1:                          # even-y normalization
        priv = crypto.ORDER_N - priv
    px = p[0].to_bytes(32, "big")
    t = bytes(a ^ b for a, b in
              zip(priv.to_bytes(32, "big"), _tagged("BIP0340/aux", aux)))
    k = int.from_bytes(
        _tagged("BIP0340/nonce", t + px + msg32), "big") % crypto.ORDER_N
    if k == 0:
        raise ValueError("bad nonce")
    r = crypto.point_mul(k)
    if r[1] & 1:
        k = crypto.ORDER_N - k
    e = int.from_bytes(_tagged("BIP0340/challenge",
                               r[0].to_bytes(32, "big") + px + msg32),
                       "big") % crypto.ORDER_N
    s = (k + e * priv) % crypto.ORDER_N
    return r[0].to_bytes(32, "big") + s.to_bytes(32, "big")


def schnorr_verify(msg32: bytes, pubkey_x: bytes, sig: bytes) -> bool:
    """BIP340 verify. pubkey_x is the 32-byte x-only pubkey."""
    if len(msg32) != 32 or len(pubkey_x) != 32 or len(sig) != 64:
        return False
    try:
        p = _lift_x(int.from_bytes(pubkey_x, "big"))
        if p is None:
            return False
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        if r >= crypto.FIELD_P or s >= crypto.ORDER_N:
            return False
        e = int.from_bytes(
            _tagged("BIP0340/challenge", sig[:32] + pubkey_x + msg32),
            "big") % crypto.ORDER_N
        rp = crypto.point_add(crypto.point_mul(s),
                              crypto.point_neg(crypto.point_mul(e, p)))
        return rp is not None and rp[0] == r and not (rp[1] & 1)
    except (ValueError, IndexError):
        return False


def generate_keypair():
    d = _secrets.randbelow(crypto.ORDER_N - 1) + 1
    return d, xonly_pubkey(d)


# ---------------------------------------------------------------------------
# BIP341 taproot tweaking
# ---------------------------------------------------------------------------
def taproot_tweak(priv: int, merkle_root: bytes = b"") -> int:
    """Q = P + hash(P||root)*G -> tweaked secret key (key-path only: root=b'')."""
    p = crypto.point_mul(priv)
    if p[1] & 1:
        priv = crypto.ORDER_N - priv
    tweak = int.from_bytes(
        _tagged("TapTweak", p[0].to_bytes(32, "big") + merkle_root),
        "big") % crypto.ORDER_N
    q = (priv + tweak) % crypto.ORDER_N
    if q == 0:
        raise ValueError("bad tweak")
    return q


def taproot_pubkey(priv: int, merkle_root: bytes = b"") -> bytes:
    """x-only tweaked output key."""
    return xonly_pubkey(taproot_tweak(priv, merkle_root))
