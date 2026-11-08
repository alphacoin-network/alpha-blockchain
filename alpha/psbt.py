"""BIP174 Partially Signed Bitcoin Transactions (PSBT v0).

Supports the full workflow: create -> fill UTXOs -> partial sign ->
combine -> finalize -> extract raw transaction.
"""

import base64
import io
import struct

from . import script
from .transaction import Transaction
from .utils import BytesReader, hash160, ser_varstr

PSBT_MAGIC = b"psbt\xff"

# global map keys
PSBT_GLOBAL_UNSIGNED_TX = 0x00
# per-input map keys
PSBT_IN_NON_WITNESS_UTXO = 0x00
PSBT_IN_WITNESS_UTXO = 0x01
PSBT_IN_PARTIAL_SIG = 0x02
PSBT_IN_SIGHASH_TYPE = 0x03
PSBT_IN_REDEEM_SCRIPT = 0x04
PSBT_IN_WITNESS_SCRIPT = 0x05
PSBT_IN_FINAL_SCRIPTSIG = 0x07
PSBT_IN_FINAL_SCRIPTWITNESS = 0x08
# per-output map keys
PSBT_OUT_REDEEM_SCRIPT = 0x00
PSBT_OUT_WITNESS_SCRIPT = 0x01


def _ser_kv(key: bytes, val: bytes) -> bytes:
    return ser_varstr(key) + ser_varstr(val)


def _deser_kv(f: BytesReader) -> tuple:
    k = f.read_varint()
    if k == 0:
        return None, None
    key = f.read(k)
    v = f.read_varint()
    return key, f.read(v)


def _ser_map(entries: dict) -> bytes:
    out = b""
    for k, v in entries.items():
        out += _ser_kv(k, v)
    return out + b"\x00"


def _deser_map(f: BytesReader) -> dict:
    entries = {}
    while True:
        k, v = _deser_kv(f)
        if k is None:
            return entries
        entries[k] = v


class PSBT:
    def __init__(self, tx: Transaction):
        self.tx = tx
        self.inputs = [{} for _ in tx.vin]
        self.outputs = [{} for _ in tx.vout]
        self.unknown = {}

    # -- serialization ---------------------------------------------------------
    def serialize(self) -> bytes:
        out = PSBT_MAGIC
        out += _ser_map({b"\x00": self.tx.serialize(include_witness=False)})
        for i in self.inputs:
            out += _ser_map(i)
        for o in self.outputs:
            out += _ser_map(o)
        return out

    @staticmethod
    def parse(data: bytes) -> "PSBT":
        if not data.startswith(PSBT_MAGIC):
            raise ValueError("bad PSBT magic")
        f = BytesReader(data[5:])
        gmap = _deser_map(f)
        tx = Transaction.deserialize(gmap[b"\x00"])
        p = PSBT(tx)
        for i in range(len(tx.vin)):
            p.inputs[i] = _deser_map(f)
        for i in range(len(tx.vout)):
            p.outputs[i] = _deser_map(f)
        return p

    def to_base64(self) -> str:
        return base64.b64encode(self.serialize()).decode()

    @staticmethod
    def from_base64(s: str) -> "PSBT":
        return PSBT.parse(base64.b64decode(s))

    # -- workflow -----------------------------------------------------------------
    def set_witness_utxo(self, n_in: int, txout) -> None:
        self.inputs[n_in][bytes([PSBT_IN_WITNESS_UTXO])] = txout.serialize()

    def set_non_witness_utxo(self, n_in: int, prev_tx: Transaction) -> None:
        self.inputs[n_in][bytes([PSBT_IN_NON_WITNESS_UTXO])] = \
            prev_tx.serialize()

    def input_utxo_spk(self, n_in: int):
        """scriptPubKey of the output this input spends."""
        inp = self.inputs[n_in]
        if bytes([PSBT_IN_WITNESS_UTXO]) in inp:
            from .transaction import TxOut
            return TxOut.parse(
                BytesReader(inp[bytes([PSBT_IN_WITNESS_UTXO])]))
        raw = inp.get(bytes([PSBT_IN_NON_WITNESS_UTXO]))
        if raw:
            prev = Transaction.deserialize(raw)
            return prev.vout[self.tx.vin[n_in].prevout.n]
        return None

    def input_value(self, n_in: int) -> int:
        inp = self.inputs[n_in]
        if bytes([PSBT_IN_WITNESS_UTXO]) in inp:
            from .transaction import TxOut
            return TxOut.parse(BytesReader(
                inp[bytes([PSBT_IN_WITNESS_UTXO])])).value
        raw = inp.get(bytes([PSBT_IN_NON_WITNESS_UTXO]))
        if raw:
            prev = Transaction.deserialize(raw)
            return prev.vout[self.tx.vin[n_in].prevout.n].value
        return 0

    def add_partial_sig(self, n_in: int, pubkey: bytes, sig: bytes) -> None:
        self.inputs[n_in][bytes([PSBT_IN_PARTIAL_SIG]) + pubkey] = sig

    def partial_sigs(self, n_in: int) -> dict:
        return {k[1:]: v for k, v in self.inputs[n_in].items()
                if k[:1] == bytes([PSBT_IN_PARTIAL_SIG])}

    def combine(self, *others: "PSBT") -> None:
        for o in others:
            for i, inp in enumerate(o.inputs):
                self.inputs[i].update(inp)
            for i, out in enumerate(o.outputs):
                self.outputs[i].update(out)

    def finalize(self) -> None:
        """Build final scriptSig/witness from partial sigs (single-sig types)."""
        for n_in, inp in enumerate(self.inputs):
            spk_txo = self.input_utxo_spk(n_in)
            if spk_txo is None:
                raise ValueError(f"input {n_in} missing UTXO")
            typ, data = script.solver(spk_txo.script_pubkey)
            sigs = self.partial_sigs(n_in)
            if typ == script.TX_PUBKEYHASH:
                pub = next(p for p in sigs if hash160(p) == data)
                self.tx.vin[n_in].script_sig = (script.push_data(sigs[pub])
                                                + script.push_data(pub))
            elif typ == script.TX_WITNESS_V0_KEYHASH:
                pub = next(p for p in sigs if hash160(p) == data)
                self.tx.vin[n_in].witness = [sigs[pub], pub]
            elif typ == script.TX_WITNESS_V1_TAPROOT:
                sig = next(iter(sigs.values()))
                self.tx.vin[n_in].witness = [sig]
            elif typ == script.TX_PUBKEY:
                self.tx.vin[n_in].script_sig = script.push_data(
                    next(iter(sigs.values())))
            else:
                raise ValueError(f"cannot finalize type {typ}")

    def extract(self) -> Transaction:
        return self.tx
