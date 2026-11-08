"""Bitcoin-style output descriptors (BIP380): parse + expand to scripts.

Supports: pkh(KEY), wpkh(KEY), tr(KEY), sh(EXP), multi(N,KEY,...),
sortedmulti(...), addr(ADDR), raw(HEXSCRIPT).
"""

from . import script as _script
from .base58 import b58decode_check
from .bech32 import decode_segwit_address
from .crypto import parse_pubkey, serialize_pubkey
from .utils import hash160
from .bip32 import HDKey
from .wallet import _p2tr_program_from_pubkey
from . import schnorr


def _expand_key(kexpr: str):
    """Returns (key_bytes, is_hd) -- pubkey bytes or (hd_node, True)."""
    kexpr = kexpr.strip()
    if kexpr.startswith(("xpub", "tpub", "xprv", "tprv")):
        return HDKey.parse(kexpr), True
    if len(kexpr) in (66, 130):
        return bytes.fromhex(kexpr), False
    raise ValueError(f"cannot parse key '{kexpr}'")


def _script_of(desc: str, params) -> bytes:
    """Descriptor string -> scriptPubKey."""
    desc = desc.strip()
    if desc.startswith("pkh(") and desc.endswith(")"):
        pub, _ = _expand_key(desc[4:-1])
        return _script.script_p2pkh(hash160(pub))
    if desc.startswith("wpkh(") and desc.endswith(")"):
        pub, _ = _expand_key(desc[5:-1])
        return _script.script_p2wpkh(hash160(pub))
    if desc.startswith("pk(") and desc.endswith(")"):
        pub, _ = _expand_key(desc[3:-1])
        return _script.script_p2pk(pub)
    if desc.startswith("tr(") and desc.endswith(")"):
        inner = desc[3:-1]
        pub, _ = _expand_key(inner.split(",")[0])
        return b"\x51\x20" + _p2tr_program_from_pubkey(pub)
    if desc.startswith("multi(") and desc.endswith(")"):
        return _multi(desc[6:-1], sorted_=False)
    if desc.startswith("sortedmulti(") and desc.endswith(")"):
        return _multi(desc[12:-1], sorted_=True)
    if desc.startswith("sh(") and desc.endswith(")"):
        inner = _script_of(desc[3:-1], params)
        return _script.script_p2sh(hash160(inner))
    if desc.startswith("wsh(") and desc.endswith(")"):
        inner = _script_of(desc[4:-1], params)
        return _script.script_p2wsh(inner)
    if desc.startswith("addr(") and desc.endswith(")"):
        return _script.script_for_address(desc[5:-1], params)
    if desc.startswith("raw(") and desc.endswith(")"):
        return bytes.fromhex(desc[4:-1])
    raise ValueError(f"unsupported descriptor '{desc}'")


def _multi(inner: str, sorted_: bool) -> bytes:
    parts = [p.strip() for p in inner.split(",")]
    n = int(parts[0])
    pubs = [pk for pk, _ in (_expand_key(p) for p in parts[1:])]
    if sorted_:
        pubs.sort()
    return _script.script_multisig(n, pubs)


def expand(descriptor: str, params) -> bytes:
    """Full descriptor string (with optional #checksum) -> scriptPubKey."""
    descriptor = descriptor.split("#")[0].strip()
    return _script_of(descriptor, params)


def descriptor_type(descriptor: str) -> str:
    return descriptor.strip().split("(")[0]
