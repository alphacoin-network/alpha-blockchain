"""Bech32 / Bech32m address encoding for segwit outputs (BIP173/BIP350).

Identical to Bitcoin; only the human-readable part differs per network.
"""

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
CHARSET_IDX = {c: i for i, c in enumerate(CHARSET)}

BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3


def _polymod(values) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def _hrp_expand(hrp: str):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _verify_checksum(hrp: str, data) -> int | None:
    const = _polymod(_hrp_expand(hrp) + data)
    if const == BECH32_CONST:
        return BECH32_CONST
    if const == BECH32M_CONST:
        return BECH32M_CONST
    return None


def _create_checksum(hrp: str, data, spec: int):
    const = BECH32M_CONST if spec == BECH32M_CONST else BECH32_CONST
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp: str, data, spec: int = BECH32_CONST) -> str:
    combined = data + _create_checksum(hrp, data, spec)
    return hrp + "1" + "".join(CHARSET[d] for d in combined)


def bech32_decode(addr: str):
    """Returns (hrp, data5, spec_const) or raises ValueError."""
    if addr.lower() != addr and addr.upper() != addr:
        raise ValueError("mixed-case bech32 string")
    addr = addr.lower()
    if len(addr) > 90:
        raise ValueError("bech32 string too long")
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr):
        raise ValueError("bad bech32 separator position")
    hrp = addr[:pos]
    data = []
    for c in addr[pos + 1:]:
        if c not in CHARSET_IDX:
            raise ValueError(f"bad bech32 character {c!r}")
        data.append(CHARSET_IDX[c])
    spec = _verify_checksum(hrp, data)
    if spec is None:
        raise ValueError("bad bech32 checksum")
    return hrp, data[:-6], spec


def convertbits(data, frombits: int, tobits: int, pad: bool = True):
    """General power-of-2 base conversion (BIP173 reference)."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or value >> frombits:
            raise ValueError("invalid value range")
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("invalid padding")
    return ret


def encode_segwit_address(hrp: str, witver: int, witprog: bytes) -> str:
    """Encode a witness program as a segwit address."""
    if not 0 <= witver <= 16:
        raise ValueError("bad witness version")
    if not 2 <= len(witprog) <= 40:
        raise ValueError("bad witness program length")
    if witver == 0 and len(witprog) not in (20, 32):
        raise ValueError("bad v0 witness program length")
    spec = BECH32_CONST if witver == 0 else BECH32M_CONST
    data = [witver] + convertbits(witprog, 8, 5)
    return bech32_encode(hrp, data, spec)


def decode_segwit_address(hrp_expected: str, addr: str):
    """Returns (witver, witprog_bytes) or raises ValueError."""
    hrp, data, spec = bech32_decode(addr)
    if hrp != hrp_expected:
        raise ValueError(f"wrong hrp (expected {hrp_expected})")
    if not data:
        raise ValueError("empty data section")
    witver = data[0]
    if witver > 16:
        raise ValueError("bad witness version")
    witprog = bytes(convertbits(data[1:], 5, 8, False))
    if not 2 <= len(witprog) <= 40:
        raise ValueError("bad witness program length")
    if witver == 0 and len(witprog) not in (20, 32):
        raise ValueError("bad v0 witness program length")
    if witver == 0 and spec != BECH32_CONST:
        raise ValueError("v0 address must use bech32")
    if witver != 0 and spec != BECH32M_CONST:
        raise ValueError("v1+ address must use bech32m")
    return witver, witprog
