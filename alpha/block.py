"""Blocks and block headers -- byte-identical to Bitcoin.

80-byte header: version(4) | prev_hash(32) | merkle_root(32) | time(4)
              | nbits(4) | nonce(4)
"""

import struct
from dataclasses import dataclass

from .transaction import Transaction
from .utils import (
    BytesReader, compact_is_valid, compact_to_target, hash_to_hex,
    ser_compact_size, sha256d,
)


def merkle_root(hashes: list) -> bytes:
    """Bitcoin's merkle tree: if odd, the last element is duplicated."""
    if not hashes:
        return b"\x00" * 32
    level = list(hashes)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1])
                 for i in range(0, len(level), 2)]
    return level[0]


def witness_merkle_root(block: "Block") -> bytes:
    """BIP141: wtxid of the coinbase is zero."""
    hashes = [b"\x00" * 32] + [tx.wtxid() for tx in block.txs[1:]]
    return merkle_root(hashes)


def witness_commitment(block: "Block", reserved: bytes) -> bytes:
    """BIP141 commitment = sha256d(witness_root | nonce)."""
    return sha256d(witness_merkle_root(block) + reserved)


def get_witness_reserved_value(block: "Block"):
    """Extract the witness reserved value from the coinbase witness."""
    if block.txs and block.txs[0].vin and block.txs[0].vin[0].witness:
        w = block.txs[0].vin[0].witness
        if len(w) == 1 and len(w[0]) == 32:
            return w[0]
    return None


@dataclass
class BlockHeader:
    version: int = 1
    prev_hash: bytes = b"\x00" * 32     # 32 bytes, wire order
    merkle: bytes = b"\x00" * 32        # 32 bytes, wire order
    timestamp: int = 0
    bits: int = 0x1D00FFFF
    nonce: int = 0

    def serialize(self) -> bytes:
        return (struct.pack("<i", self.version)
                + self.prev_hash
                + self.merkle
                + struct.pack("<III", self.timestamp, self.bits, self.nonce))

    @staticmethod
    def parse(r: BytesReader) -> "BlockHeader":
        return BlockHeader(
            r.read_i32(), r.read(32), r.read(32),
            r.read_u32(), r.read_u32(), r.read_u32())

    @staticmethod
    def deserialize(data: bytes) -> "BlockHeader":
        return BlockHeader.parse(BytesReader(data))

    def hash(self) -> bytes:
        return sha256d(self.serialize())

    def hash_hex(self) -> str:
        return hash_to_hex(self.hash())

    def target(self) -> int:
        return compact_to_target(self.bits)

    def check_pow(self, pow_limit_bits: int) -> bool:
        """Bitcoin CheckProofOfWork semantics."""
        if not compact_is_valid(self.bits):
            return False
        target = compact_to_target(self.bits)
        if target <= 0 or target > compact_to_target(pow_limit_bits):
            return False
        return int.from_bytes(self.hash(), "little") <= target


class Block:
    __slots__ = ("header", "txs", "_hash")

    def __init__(self, header: BlockHeader | None = None, txs=None):
        self.header = header or BlockHeader()
        self.txs = list(txs) if txs else []
        self._hash = None

    def hash(self) -> bytes:
        if self._hash is None:
            self._hash = self.header.hash()
        return self._hash

    def hash_hex(self) -> str:
        return hash_to_hex(self.hash())

    def serialize(self, include_witness: bool = True) -> bytes:
        out = self.header.serialize()
        out += ser_compact_size(len(self.txs))
        out += b"".join(tx.serialize(include_witness) for tx in self.txs)
        return out

    @staticmethod
    def deserialize(data: bytes) -> "Block":
        r = BytesReader(data)
        block = Block.from_reader(r)
        if not r.eof():
            raise ValueError("trailing block data")
        return block

    @staticmethod
    def from_reader(r: BytesReader) -> "Block":
        header = BlockHeader.parse(r)
        n = r.read_varint()
        txs = [Transaction.from_reader(r) for _ in range(n)]
        return Block(header, txs)

    def merkle_root(self) -> bytes:
        return merkle_root([tx.txid() for tx in self.txs])

    def compute_merkle(self) -> None:
        self.header.merkle = self.merkle_root()

    def has_witness(self) -> bool:
        return any(tx.has_witness() for tx in self.txs)

    def base_size(self) -> int:
        return len(self.serialize(include_witness=False))

    def total_size(self) -> int:
        return len(self.serialize(include_witness=True))

    def weight(self) -> int:
        return self.base_size() * 3 + self.total_size()

    def check_merkle(self) -> bool:
        return self.merkle_root() == self.header.merkle

    def __repr__(self):
        return f"<Block {self.hash_hex()[:16]}... {len(self.txs)} txs>"


def _tx_serialized_len(data: bytes) -> int:
    """Length of the first serialized transaction in `data`."""
    r = BytesReader(data)
    Transaction.from_reader(r)
    return r.pos
