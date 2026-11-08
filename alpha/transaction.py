"""Transactions and the UTXO model -- byte-identical to Bitcoin.

Includes:
  * Legacy serialization + segwit (BIP144) marker/flag serialization
  * Legacy SIGHASH algorithm (ALL/NONE/SINGLE/ANYONECANPAY, including the
    famous SIGHASH_SINGLE returns-1 quirk, which is consensus on Bitcoin)
  * BIP143 v0 witness signature hashing
  * Weight / virtual-size accounting (BIP141)
"""

import struct
from dataclasses import dataclass, field

from .utils import (
    BytesReader, hash_to_hex, ser_compact_size, ser_varstr, sha256d,
)

# Signature hash types (identical to Bitcoin)
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80
SIGHASH_MASK = 0x1F

SEQUENCE_FINAL = 0xFFFFFFFF
COINBASE_PREV_HASH = b"\x00" * 32
COINBASE_PREV_VOUT = 0xFFFFFFFF

# The uint256 "1" returned by the legacy SIGHASH_SINGLE bug when the input
# index exceeds the number of outputs. This is consensus behavior in Bitcoin.
_SIGHASH_SINGLE_BUG = b"\x01" + b"\x00" * 31

BLANK_OUTPUT_VALUE = 0xFFFFFFFFFFFFFFFF  # int64 -1, used by SIGHASH_SINGLE


@dataclass
class OutPoint:
    """A reference to a specific output of a previous transaction."""
    txid: bytes = COINBASE_PREV_HASH   # 32 bytes, wire order
    vout: int = 0

    def serialize(self) -> bytes:
        return self.txid + struct.pack("<I", self.vout)

    @staticmethod
    def parse(r: BytesReader) -> "OutPoint":
        return OutPoint(r.read(32), r.read_u32())

    def is_null(self) -> bool:
        return self.txid == COINBASE_PREV_HASH and self.vout == COINBASE_PREV_VOUT

    def key(self):
        return (self.txid, self.vout)

    def __hash__(self):
        return hash(self.key())

    def __eq__(self, other):
        return isinstance(other, OutPoint) and self.key() == other.key()


@dataclass
class TxIn:
    prevout: OutPoint = field(default_factory=OutPoint)
    script_sig: bytes = b""
    sequence: int = SEQUENCE_FINAL
    witness: list = field(default_factory=list)   # list of bytes (BIP141)

    def serialize(self) -> bytes:
        return (self.prevout.serialize()
                + ser_varstr(self.script_sig)
                + struct.pack("<I", self.sequence))

    @staticmethod
    def parse(r: BytesReader) -> "TxIn":
        return TxIn(OutPoint.parse(r), r.read_varbytes(), r.read_u32())

    def is_coinbase(self) -> bool:
        return self.prevout.is_null()

    def signals_rbf(self) -> bool:
        return self.sequence < 0xFFFFFFFE


@dataclass
class TxOut:
    value: int = 0                    # in alphasats (int64 range on the wire)
    script_pubkey: bytes = b""

    def serialize(self) -> bytes:
        return struct.pack("<q", self.value) + ser_varstr(self.script_pubkey)

    @staticmethod
    def parse(r: BytesReader) -> "TxOut":
        return TxOut(r.read_i64(), r.read_varbytes())


class Transaction:
    """A Bitcoin-format transaction (with optional segwit witness data)."""

    __slots__ = ("version", "vin", "vout", "locktime")

    def __init__(self, version=2, vin=None, vout=None, locktime=0):
        self.version = version
        self.vin = list(vin) if vin else []
        self.vout = list(vout) if vout else []
        self.locktime = locktime

    # -- serialization ------------------------------------------------------
    def has_witness(self) -> bool:
        return any(txin.witness for txin in self.vin)

    def serialize(self, include_witness: bool = True) -> bytes:
        out = struct.pack("<i", self.version)
        use_witness = include_witness and self.has_witness()
        if use_witness:
            out += b"\x00\x01"  # marker + flag
        out += ser_compact_size(len(self.vin))
        out += b"".join(txin.serialize() for txin in self.vin)
        out += ser_compact_size(len(self.vout))
        out += b"".join(txo.serialize() for txo in self.vout)
        if use_witness:
            for txin in self.vin:
                out += ser_compact_size(len(txin.witness))
                for item in txin.witness:
                    out += ser_varstr(item)
        out += struct.pack("<I", self.locktime)
        return out

    @staticmethod
    def from_reader(r: BytesReader) -> "Transaction":
        """Parse one transaction from a stream (may be followed by more data)."""
        tx = Transaction()
        tx.version = r.read_i32()
        flags = 0
        vin_count = r.read_varint()
        if vin_count == 0:  # segwit marker
            flags = r.read_u8()
            vin_count = r.read_varint()
        for _ in range(vin_count):
            tx.vin.append(TxIn.parse(r))
        vout_count = r.read_varint()
        for _ in range(vout_count):
            tx.vout.append(TxOut.parse(r))
        if flags & 1:
            for txin in tx.vin:
                n = r.read_varint()
                txin.witness = [r.read_varbytes() for _ in range(n)]
            if not tx.has_witness():
                raise ValueError("superfluous witness record")
            flags ^= 1
        if flags:
            raise ValueError("unknown transaction optional data")
        tx.locktime = r.read_u32()
        return tx

    @staticmethod
    def deserialize(data: bytes) -> "Transaction":
        r = BytesReader(data)
        tx = Transaction.from_reader(r)
        if not r.eof():
            raise ValueError("trailing transaction data")
        return tx

    def copy(self) -> "Transaction":
        return Transaction.deserialize(self.serialize())

    # -- identifiers ---------------------------------------------------------
    def txid(self) -> bytes:
        """32-byte txid in wire order (display = txid[::-1].hex())."""
        return sha256d(self.serialize(include_witness=False))

    def wtxid(self) -> bytes:
        if self.has_witness():
            return sha256d(self.serialize(include_witness=True))
        return self.txid()

    def txid_hex(self) -> str:
        return hash_to_hex(self.txid())

    def is_coinbase(self) -> bool:
        return len(self.vin) == 1 and self.vin[0].is_coinbase()

    # -- sizes ----------------------------------------------------------------
    def base_size(self) -> int:
        return len(self.serialize(include_witness=False))

    def total_size(self) -> int:
        return len(self.serialize(include_witness=True))

    def weight(self) -> int:
        # BIP141: weight = base*3 + total  (== base*4 + witness bytes)
        return self.base_size() * 3 + self.total_size()

    def vsize(self) -> int:
        return (self.weight() + 3) // 4

    def total_output_value(self) -> int:
        return sum(txo.value for txo in self.vout)

    # -- legacy signature hashing (pre-segwit, consensus since 2009) ---------
    def signature_hash(self, script_code: bytes, n_in: int, hash_type: int) -> bytes:
        """Bitcoin's legacy SignatureHash, incl. the SIGHASH_SINGLE bug."""
        base_type = hash_type & SIGHASH_MASK
        if base_type == SIGHASH_SINGLE and n_in >= len(self.vout):
            return _SIGHASH_SINGLE_BUG

        tx = self.copy()
        # Remove OP_CODESEPARATOR (0xab) from the executed subscript
        script_code = script_code.replace(b"\xab", b"")

        for txin in tx.vin:
            txin.script_sig = b""
            txin.witness = []
        tx.vin[n_in].script_sig = script_code

        if base_type == SIGHASH_NONE:
            tx.vout = []
            for i, txin in enumerate(tx.vin):
                if i != n_in:
                    txin.sequence = 0
        elif base_type == SIGHASH_SINGLE:
            new_vout = [TxOut(BLANK_OUTPUT_VALUE, b"")] * n_in
            new_vout.append(tx.vout[n_in])
            tx.vout = new_vout
            for i, txin in enumerate(tx.vin):
                if i != n_in:
                    txin.sequence = 0

        if hash_type & SIGHASH_ANYONECANPAY:
            tx.vin = [tx.vin[n_in]]

        preimage = tx.serialize(include_witness=False) + struct.pack("<I", hash_type)
        return sha256d(preimage)

    # -- BIP143 signature hashing for segwit v0 -------------------------------
    def signature_hash_v0(self, script_code: bytes, n_in: int, value: int,
                          hash_type: int) -> bytes:
        base_type = hash_type & SIGHASH_MASK
        anyone = bool(hash_type & SIGHASH_ANYONECANPAY)

        zero = b"\x00" * 32
        if not anyone:
            hash_prevouts = sha256d(b"".join(t.prevout.serialize() for t in self.vin))
        else:
            hash_prevouts = zero

        if not anyone and base_type not in (SIGHASH_SINGLE, SIGHASH_NONE):
            hash_sequence = sha256d(
                b"".join(struct.pack("<I", t.sequence) for t in self.vin))
        else:
            hash_sequence = zero

        if base_type == SIGHASH_ALL:
            hash_outputs = sha256d(b"".join(o.serialize() for o in self.vout))
        elif base_type == SIGHASH_SINGLE and n_in < len(self.vout):
            hash_outputs = sha256d(self.vout[n_in].serialize())
        else:
            hash_outputs = zero

        preimage = (
            struct.pack("<i", self.version)
            + hash_prevouts
            + hash_sequence
            + self.vin[n_in].prevout.serialize()
            + ser_varstr(script_code)
            + struct.pack("<q", value)
            + struct.pack("<I", self.vin[n_in].sequence)
            + hash_outputs
            + struct.pack("<I", self.locktime)
            + struct.pack("<I", hash_type)
        )
        return sha256d(preimage)

    # -- locktime (BIP65 semantics) -------------------------------------------
    def is_final(self, block_height: int, block_time: int) -> bool:
        if self.locktime == 0:
            return True
        threshold = block_height if self.locktime < 500_000_000 else block_time
        if self.locktime < threshold:
            return True
        return all(t.sequence == SEQUENCE_FINAL for t in self.vin)

    def __repr__(self):
        return f"<Transaction {self.txid_hex()[:16]}... {len(self.vin)}in/{len(self.vout)}out>"
