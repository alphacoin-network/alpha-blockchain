"""Serialization helpers, hashing, and compact-difficulty ("bits") math.

Wire formats are byte-for-byte identical to Bitcoin's.
"""

import hashlib
import struct
import time


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256d(data: bytes) -> bytes:
    """Bitcoin's standard double-SHA256."""
    return sha256(sha256(data))


def ripemd160(data: bytes) -> bytes:
    try:
        return hashlib.new("ripemd160", data).digest()
    except (ValueError, TypeError):  # OpenSSL build without ripemd160
        return _ripemd160(data)


def hash160(data: bytes) -> bytes:
    """SHA256 then RIPEMD160 -- the hash used for P2PKH/P2SH addresses."""
    return ripemd160(sha256(data))


# ---------------------------------------------------------------------------
# Pure-Python RIPEMD-160 fallback (reference implementation of the spec)
# ---------------------------------------------------------------------------
_R1 = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]
_R2 = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]
_S1 = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]
_S2 = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]


def _rol(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _f(j: int, x: int, y: int, z: int) -> int:
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & z)
    if j < 48:
        return (x | ~y) ^ z
    if j < 64:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


_K1 = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_K2 = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]


def _ripemd160(msg: bytes) -> bytes:
    ml = len(msg) * 8
    msg += b"\x80"
    while len(msg) % 64 != 56:
        msg += b"\x00"
    msg += struct.pack("<Q", ml)

    h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    for off in range(0, len(msg), 64):
        x = list(struct.unpack("<16I", msg[off:off + 64]))
        a1, b1, c1, d1, e1 = h0, h1, h2, h3, h4
        a2, b2, c2, d2, e2 = h0, h1, h2, h3, h4
        for j in range(80):
            t = (_rol((a1 + _f(j, b1, c1, d1) + x[_R1[j]] + _K1[j // 16]) & 0xFFFFFFFF,
                      _S1[j]) + e1) & 0xFFFFFFFF
            a1, e1, d1, c1, b1 = e1, d1, _rol(c1, 10), b1, t
            t = (_rol((a2 + _f(79 - j, b2, c2, d2) + x[_R2[j]] + _K2[j // 16]) & 0xFFFFFFFF,
                      _S2[j]) + e2) & 0xFFFFFFFF
            a2, e2, d2, c2, b2 = e2, d2, _rol(c2, 10), b2, t
        t = (h1 + c1 + d2) & 0xFFFFFFFF
        h1 = (h2 + d1 + e2) & 0xFFFFFFFF
        h2 = (h3 + e1 + a2) & 0xFFFFFFFF
        h3 = (h4 + a1 + b2) & 0xFFFFFFFF
        h4 = (h0 + b1 + c2) & 0xFFFFFFFF
        h0 = t
    return struct.pack("<5I", h0, h1, h2, h3, h4)


# ---------------------------------------------------------------------------
# Hashes as displayed hex (Bitcoin displays hashes big-endian/reversed)
# ---------------------------------------------------------------------------
def hash_to_hex(h: bytes) -> str:
    return h[::-1].hex()


def hex_to_hash(s: str) -> bytes:
    b = bytes.fromhex(s)
    if len(b) != 32:
        raise ValueError("hash must be 32 bytes")
    return b[::-1]


# ---------------------------------------------------------------------------
# Compact-size integers (Bitcoin "varint")
# ---------------------------------------------------------------------------
def ser_compact_size(n: int) -> bytes:
    if n < 0:
        raise ValueError("negative compact size")
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def deser_compact_size(data: bytes, offset: int = 0):
    n = data[offset]
    if n < 253:
        return n, offset + 1
    if n == 253:
        return struct.unpack_from("<H", data, offset + 1)[0], offset + 3
    if n == 254:
        return struct.unpack_from("<I", data, offset + 1)[0], offset + 5
    return struct.unpack_from("<Q", data, offset + 1)[0], offset + 9


def ser_varstr(b: bytes) -> bytes:
    return ser_compact_size(len(b)) + b


# ---------------------------------------------------------------------------
# Byte-stream reader
# ---------------------------------------------------------------------------
class BytesReader:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("read past end of stream")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def read_u8(self) -> int:
        return self.read(1)[0]

    def read_u16(self) -> int:
        return struct.unpack("<H", self.read(2))[0]

    def read_u32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def read_u64(self) -> int:
        return struct.unpack("<Q", self.read(8))[0]

    def read_i32(self) -> int:
        return struct.unpack("<i", self.read(4))[0]

    def read_i64(self) -> int:
        return struct.unpack("<q", self.read(8))[0]

    def read_varint(self) -> int:
        n, self.pos = deser_compact_size(self.data, self.pos)
        return n

    def read_varbytes(self, max_len: int = 0x02000000) -> bytes:
        n = self.read_varint()
        if n > max_len:
            raise ValueError("varbytes too large")
        return self.read(n)

    def eof(self) -> bool:
        return self.pos >= len(self.data)


# ---------------------------------------------------------------------------
# Compact difficulty encoding ("nBits") -- identical to Bitcoin's SetCompact
# ---------------------------------------------------------------------------
def compact_to_target(bits: int) -> int:
    size = bits >> 24
    word = bits & 0x007FFFFF
    if size <= 3:
        return word >> (8 * (3 - size))
    return word << (8 * (size - 3))


def compact_is_valid(bits: int) -> bool:
    """Check the compact form isn't negative/overflowing (Bitcoin semantics)."""
    word = bits & 0x007FFFFF
    if bits & 0x00800000:  # negative
        return False
    size = bits >> 24
    if word != 0 and (size > 34 or (word > 0xFF and size > 33) or
                      (word > 0xFFFF and size > 32)):
        return False
    return True


def target_to_compact(target: int) -> int:
    if target <= 0:
        return 0
    size = (target.bit_length() + 7) // 8
    if size <= 3:
        compact = target << (8 * (3 - size))
    else:
        compact = target >> (8 * (size - 3))
    if compact & 0x00800000:  # sign bit would be set; grow by one byte
        compact >>= 8
        size += 1
    return (size << 24) | (compact & 0x007FFFFF)


def work_from_bits(bits: int) -> int:
    """Chainwork contribution of one block (Bitcoin's exact formula).

    work = (~uint256(0) / (target + 1)) + 1  =  (2^256 - 1 - target)/(target+1) + 1
    """
    target = compact_to_target(bits)
    if target <= 0:
        return 0
    return ((1 << 256) - 1 - target) // (target + 1) + 1


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------
def now() -> int:
    return int(time.time())


def median(values) -> int:
    s = sorted(values)
    n = len(s)
    if n == 0:
        return 0
    return s[n // 2]


def read_le_int(data: bytes) -> int:
    """Decode a little-endian magnitude with sign bit (script numbers)."""
    return decode_script_num(data)


def decode_script_num(data: bytes, max_size: int = 4, require_minimal: bool = False) -> int:
    """Bitcoin CScriptNum decoding: little-endian, sign bit on the last byte."""
    if len(data) > max_size:
        raise ValueError("script number overflow")
    if require_minimal and data:
        if (data[-1] & 0x7F) == 0 and (
            len(data) <= 1 or (data[-2] & 0x80) == 0
        ):
            raise ValueError("non-minimally encoded script number")
    if not data:
        return 0
    v = int.from_bytes(data, "little")
    if data[-1] & 0x80:
        v &= ~(0x80 << (8 * (len(data) - 1)))
        return -v
    return v


def encode_script_num(v: int) -> bytes:
    """Inverse of decode_script_num."""
    if v == 0:
        return b""
    neg = v < 0
    v = abs(v)
    out = bytearray()
    while v:
        out.append(v & 0xFF)
        v >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if neg else 0)
    elif neg:
        out[-1] |= 0x80
    return bytes(out)
