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


# ---------------------------------------------------------------------------
# BIP341 script-path: tapleaf/branch hashing + merkle tree + control block
# ---------------------------------------------------------------------------
def tapleaf_hash(script_bytes: bytes, version: int = 0xC0) -> bytes:
    """TapLeaf = hash(version || compactsize(len) || script)."""
    from .utils import ser_compact_size
    return _tagged("TapLeaf",
                   bytes([version]) + ser_compact_size(len(script_bytes))
                   + script_bytes)


def tapbranch(a: bytes, b: bytes) -> bytes:
    """TapBranch = hash(min(a,b) || max(a,b)) -- sorted pair."""
    return _tagged("TapBranch", min(a, b) + max(a, b))


def taproot_merkle_root(leaves: list) -> bytes:
    """Combine leaf hashes into the merkle root (empty -> b'')."""
    if not leaves:
        return b""
    nodes = list(leaves)
    while len(nodes) > 1:
        nodes = [tapbranch(nodes[i], nodes[i + 1])
                 for i in range(0, len(nodes) - 1, 2)]
        if len(leaves) % 2 and len(nodes) > 1:
            pass                    # odd leaf pairs already handled by pairing
        # odd one carries up unchanged
        if len(leaves) & 1:
            nodes.append(leaves[-1])
        leaves = nodes
    return nodes[0]


def control_block(internal_pubx: bytes, leaf_hash: bytes,
                  proof: list, leaf_version: int = 0xC0,
                  parity: int = 0) -> bytes:
    """control_byte || internal_pub || merkle path."""
    return (bytes([leaf_version | (parity & 1)]) + internal_pubx
            + b"".join(proof))


def verify_script_path(control: bytes, output_key_x: bytes,
                       script_bytes: bytes) -> tuple:
    """Validate a BIP341 control block against the output key.

    Returns (script, leaf_version) if valid, else raises ValueError.
    """
    if len(control) < 33 or (len(control) - 33) % 32:
        raise ValueError("bad control block size")
    cb = control[0]
    leaf_version = cb & 0xFE
    parity = cb & 1
    internal_x = control[1:33]
    path = [control[33 + 32 * i:33 + 32 * (i + 1)]
            for i in range((len(control) - 33) // 32)]
    # recompute merkle root from leaf -> root
    h = tapleaf_hash(script_bytes, leaf_version)
    for p in path:
        h = tapbranch(h, p)
    # Q = P + hash(P||root)*G, check x and parity
    tweak = int.from_bytes(
        _tagged("TapTweak", internal_x + h), "big") % crypto.ORDER_N
    p_point = _lift_x(int.from_bytes(internal_x, "big"))
    q = crypto.point_add(p_point, crypto.point_mul(tweak))
    if q[0].to_bytes(32, "big") != output_key_x or (q[1] & 1) != parity:
        raise ValueError("control block does not match output key")
    return leaf_version
