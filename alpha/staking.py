"""staking — time-locked ALPHA positions + pro-rata reward distribution.

Honest design: Alpha is proof-of-work, so "staking" is a yield/lock program,
not consensus. A staker locks real coins in a CLTV output spendable only by
their own key after the unlock height — the OP_RETURN record just indexes the
position. Rewards are paid by a funder via `stakedistribute`, pro-rata on
locked amounts.

Wire format (OP_RETURN, single push):
    "STK" | version(1) | op(1) | unlock_height(u32 LE) | owner_pkh(20)

op 0x01 STAKE: requires output0 to be the CLTV lock output (stake_spk) —
    the locked amount is taken from that output's value. The position
    closes when the outpoint is spent (unstake) — detected on inputs.
"""
import struct

from . import script as _script
from .utils import encode_script_num, hash_to_hex

MAGIC = b"STK"
VERSION = 1
OP_STAKE = 0x01


def encode_stake(unlock_height: int, pkh: bytes) -> bytes:
    return (MAGIC + bytes([VERSION, OP_STAKE])
            + struct.pack("<I", unlock_height) + pkh)


def stake_spk(unlock_height: int, pkh: bytes) -> bytes:
    """<unlock> CLTV DROP DUP HASH160 <pkh> EQUALVERIFY CHECKSIG"""
    return (_script.push_data(encode_script_num(unlock_height))
            + b"\xb1\x75\x76\xa9\x14" + pkh + b"\x88\xac")


def parse_payload(data: bytes):
    if (not data or data[:3] != MAGIC or len(data) != 29
            or data[3] != VERSION or data[4] != OP_STAKE):
        return None
    return {"op": OP_STAKE,
            "unlock": struct.unpack("<I", data[5:9])[0],
            "pkh": data[9:29]}


def find_payload(tx):
    for txo in tx.vout:
        typ, _ = _script.solver(txo.script_pubkey)
        if typ != _script.TX_NULL_DATA:
            continue
        ops = _script.script_ops(txo.script_pubkey)
        if len(ops) == 2 and ops[1].data is not None:
            p = parse_payload(ops[1].data)
            if p is not None:
                return p
    return None


def addr_pkh(spk: bytes):
    typ, data = _script.solver(spk)
    return data if typ in (_script.TX_PUBKEYHASH,
                           _script.TX_WITNESS_V0_KEYHASH) else None


class StakeDB:
    """Indexed stake positions — keyed by the locked outpoint (txid, 0)."""

    def __init__(self):
        self.stakes: dict[tuple, dict] = {}
        self.journal: dict[int, list] = {}

    def apply_block(self, block, height, lookup_script):
        j = []
        for tx in block.txs:
            # a spend of a locked outpoint closes the position
            for vin in tx.vin:
                if vin.is_coinbase():
                    continue
                k = vin.prevout.key()
                st = self.stakes.get(k)
                if st and st["open"]:
                    st["open"] = False
                    st["closed_height"] = height
                    j.append(("close", k))
            p = find_payload(tx)
            if p is None or not tx.vout:
                continue
            out0 = tx.vout[0]
            if (out0.value > 0
                    and out0.script_pubkey == stake_spk(p["unlock"], p["pkh"])):
                key = (tx.txid(), 0)
                self.stakes[key] = {
                    "id": tx.txid(), "pkh": p["pkh"],
                    "amount": out0.value, "unlock": p["unlock"],
                    "staked_height": height, "open": True}
                j.append(("open", key))
        if j:
            self.journal[height] = j

    def unapply_block(self, height):
        for op, key in self.journal.pop(height, []):
            if op == "open":
                self.stakes.pop(key, None)
            else:
                self.stakes[key]["open"] = True
                self.stakes[key].pop("closed_height", None)

    def listing(self):
        out = []
        for (txid, vout), s in self.stakes.items():
            out.append({"stake_id": hash_to_hex(s["id"]),
                        "owner_pkh": s["pkh"].hex(),
                        "amount_sats": s["amount"],
                        "amount_alpha": s["amount"] / 1e8,
                        "unlock_height": s["unlock"],
                        "staked_height": s["staked_height"],
                        "status": "locked" if s["open"] else "closed",
                        "closed_height": s.get("closed_height")})
        return out

    def stats(self, tip: int):
        open_ = [s for s in self.stakes.values() if s["open"]]
        return {"positions": len(open_),
                "total_staked_sats": sum(s["amount"] for s in open_),
                "total_staked_alpha": sum(s["amount"] for s in open_) / 1e8,
                "all_time_positions": len(self.stakes),
                "tip_height": tip}
