"""DEX — the Alpha decentralized exchange.

Counterparty-style on-chain order book: token sells are escrowed inside the
protocol state via OP_RETURN ops; buyers fill them by paying the seller's
address in ALPHA. Fully deterministic — every node computes the same
order book by replaying blocks.

Wire format (inside an OP_RETURN output, single push):

    "DEX" | version(1) | op(1) | payload...

    op=0x01 SELL   : token_id(32) | amount(u64 LE) | price_per_unit(u64 LE alphasats)
                     order_id = txid of the sell tx; tokens escrowed from
                     the first input's prevout script
    op=0x02 FILL   : order_id(32) | max_cost(u64 LE alphasats, optional)
                     requires an output paying >= amount*price alphasats to
                     the seller's script in the same tx; tokens go to the
                     first input's prevout script (the buyer).
                     If max_cost > 0 and the required payment exceeds it,
                     the fill is rejected — slippage protection.
    op=0x03 CANCEL : order_id(32)
                     only the seller's script may cancel; escrow returns
"""

import struct

from . import script as _script

MAGIC = b"DEX"
VERSION = 1
OP_SELL = 0x01
OP_FILL = 0x02
OP_CANCEL = 0x03


def encode_sell(token_id: bytes, amount: int, price: int) -> bytes:
    return (MAGIC + bytes([VERSION, OP_SELL]) + token_id
            + struct.pack("<QQ", amount, price))


def encode_fill(order_id: bytes, max_cost: int = 0) -> bytes:
    return MAGIC + bytes([VERSION, OP_FILL]) + order_id + struct.pack("<Q", max_cost)


def encode_cancel(order_id: bytes) -> bytes:
    return MAGIC + bytes([VERSION, OP_CANCEL]) + order_id


def parse_payload(data: bytes):
    if not data or data[:3] != MAGIC or len(data) < 5:
        return None
    version, op = data[3], data[4]
    if version != VERSION:
        return None
    try:
        if op == OP_SELL:
            return {"op": op, "token_id": data[5:37],
                    "amount": struct.unpack_from("<Q", data, 37)[0],
                    "price": struct.unpack_from("<Q", data, 45)[0]}
        if op == OP_FILL:
            mc = struct.unpack_from("<Q", data, 37)[0] if len(data) >= 45 else 0
            return {"op": op, "order_id": data[5:37], "max_cost": mc}
        if op == OP_CANCEL:
            return {"op": op, "order_id": data[5:37]}
    except (IndexError, struct.error):
        return None
    return None


def find_dex_payload(tx):
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


class DexDB:
    """Deterministic order-book indexer (mirrors TokenDB)."""

    def __init__(self):
        self.orders: dict[bytes, dict] = {}   # order_id -> order
        self.journal: dict[int, list] = {}
        self.needs_rebuild = False

    def apply_block(self, block, height, token_db, lookup_script):
        journal = []
        for tx in block.txs:
            p = find_dex_payload(tx)
            if p is None:
                continue
            sender = None
            if tx.vin and not tx.vin[0].is_coinbase():
                sender = lookup_script(tx.vin[0].prevout.key())
            self._apply(p, tx, sender, token_db, height, journal)
        if journal:
            self.journal[height] = journal

    def _apply(self, p, tx, sender, db, height, j):
        op = p["op"]
        if op == OP_SELL:
            if (sender is None or p["amount"] <= 0 or p["price"] <= 0
                    or p["token_id"] not in db.registry):
                return
            if db.balance(p["token_id"], sender) < p["amount"]:
                return  # can't sell what you don't have
            order_id = tx.txid()
            if order_id in self.orders:
                return
            db._debit(j, p["token_id"], sender, p["amount"])     # escrow
            self.orders[order_id] = {
                "order_id": order_id, "token_id": p["token_id"],
                "amount": p["amount"], "price": p["price"],
                "seller": sender, "height": height,
            }
            j.append(("order", order_id))
        elif op == OP_FILL:
            order = self.orders.get(p["order_id"])
            if order is None or sender is None or sender == order["seller"]:
                return
            need = order["amount"] * order["price"]
            if p.get("max_cost") and need > p["max_cost"]:
                return  # slippage protection — price moved past buyer's cap
            paid = sum(txo.value for txo in tx.vout
                       if txo.script_pubkey == order["seller"])
            if paid < need:
                return  # payment short → order stays open
            db._credit(j, order["token_id"], sender, order["amount"])
            del self.orders[p["order_id"]]
            j.append(("fill", order))
        elif op == OP_CANCEL:
            order = self.orders.get(p["order_id"])
            if order is None or sender != order["seller"]:
                return
            db._credit(j, order["token_id"], order["seller"], order["amount"])
            del self.orders[p["order_id"]]
            j.append(("cancel", order))

    def unapply_block(self, height: int, token_db) -> None:
        journal = self.journal.pop(height, None)
        if journal is None:
            if height <= max(self.journal, default=-1):
                self.needs_rebuild = True
            return
        for rec in reversed(journal):
            if rec[0] == "order":
                self.orders.pop(rec[1], None)
            elif rec[0] in ("fill", "cancel"):
                self.orders[rec[1]["order_id"]] = rec[1]
            elif rec[0] == "bal":
                _, tid, spk, delta = rec
                key = (tid, spk)
                token_db.balances[key] = (
                    token_db.balances.get(key, 0) - delta)
                if not token_db.balances[key]:
                    token_db.balances.pop(key, None)

    def rebuild(self, chain, token_db) -> None:
        self.orders.clear()
        self.journal.clear()
        self.needs_rebuild = False
        for entry in chain.active[1:]:
            block = chain.get_block(entry.hash)
            if block:
                self.apply_block(block, entry.height, token_db,
                                 chain.utxo_script_lookup())

    def list_orders(self, params):
        from .utils import hash_to_hex
        out = []
        for o in self.orders.values():
            info = o and None
            out.append({
                "order_id": hash_to_hex(o["order_id"]),
                "token_id": hash_to_hex(o["token_id"]),
                "amount": o["amount"],
                "price_alphasats": o["price"],
                "total_alpha": o["amount"] * o["price"] / 1e8,
                "seller": _script.extract_destination(o["seller"], params),
                "height": o["height"],
            })
        return out
