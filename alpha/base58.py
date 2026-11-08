"""Base58 and Base58Check encoding -- identical to Bitcoin.

Base58Check: version byte(s) + payload + 4-byte sha256d checksum.
"""

from .utils import sha256d

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ALPHABET_IDX = {c: i for i, c in enumerate(ALPHABET)}


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = ALPHABET[r] + out
    # preserve leading zero bytes as '1'
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + (out or "")


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        if ch not in ALPHABET_IDX:
            raise ValueError(f"invalid base58 character {ch!r}")
        n = n * 58 + ALPHABET_IDX[ch]
    body = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big") if n else b""
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + body


def b58encode_check(payload: bytes) -> str:
    """Encode version+payload with a 4-byte checksum."""
    return b58encode(payload + sha256d(payload)[:4])


def b58decode_check(s: str) -> bytes:
    """Decode and verify the checksum. Returns version+payload."""
    raw = b58decode(s)
    if len(raw) < 5:
        raise ValueError("base58check string too short")
    payload, checksum = raw[:-4], raw[-4:]
    if sha256d(payload)[:4] != checksum:
        raise ValueError("bad base58check checksum")
    return payload
