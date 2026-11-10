"""AMM — Alpha automated market maker.

Constant-product (x*y=k) liquidity pools for token↔token pairs. Pool
assets live inside the token-protocol state (escrowed like DEX orders),
so pools are fully trustless and deterministic — every node computes
identical reserves from block replay.

Wire format (OP_RETURN output, single push):

    "AMM" | version(1) | op(1) | payload...

    op=0x01 CREATE : token_a(32) | token_b(32) | fee_bps(u16 LE)
                     pool_id = txid; token_a < token_b required
    op=0x02 ADD    : pool_id(32) | amount_a(u64) | amount_b(u64)
                     first pool: shares = floor(sqrt(a*b));
                     later: shares proportional to min-side deposit
    op=0x03 REMOVE : pool_id(32) | shares(u64)
                     returns pro-rata reserves to the LP
    op=0x04 SWAP   : pool_id(32) | token_in(32) | amount_in(u64) | min_out(u64)
                     out = reserve_out*in_eff/(reserve_in+in_eff),
                     in_eff = in*(1-fee); rejected if out < min_out
                     (slippage protection) — tokens move between the
                     swapper's script and the pool ledger.
"""

import struct, math

from . import script as _script

MAGIC = b"AMM"
VERSION = 1
OP_CREATE = 0x01
OP_ADD = 0x02
OP_REMOVE = 0x03
OP_SWAP = 0x04
MAX_FEE_BPS = 1000            # 10% max fee


def encode_create(ta, tb, fee_bps):
    return MAGIC + bytes([VERSION, OP_CREATE]) + ta + tb + struct.pack("<H", fee_bps)

def encode_add(pool_id, a, b):
    return MAGIC + bytes([VERSION, OP_ADD]) + pool_id + struct.pack("<QQ", a, b)

def encode_remove(pool_id, shares):
    return MAGIC + bytes([VERSION, OP_REMOVE]) + pool_id + struct.pack("<Q", shares)

def encode_swap(pool_id, tin, amt, min_out):
    return (MAGIC + bytes([VERSION, OP_SWAP]) + pool_id + tin
            + struct.pack("<QQ", amt, min_out))


def parse_payload(data):
    if not data or data[:3] != MAGIC or len(data) < 5:
        return None
    if data[3] != VERSION:
        return None
    op = data[4]
    try:
        if op == OP_CREATE:
            return {"op": op, "ta": data[5:37], "tb": data[37:69],
                    "fee": struct.unpack_from("<H", data, 69)[0]}
        if op == OP_ADD:
            return {"op": op, "pid": data[5:37],
                    "a": struct.unpack_from("<Q", data, 37)[0],
                    "b": struct.unpack_from("<Q", data, 45)[0]}
        if op == OP_REMOVE:
            return {"op": op, "pid": data[5:37],
                    "shares": struct.unpack_from("<Q", data, 37)[0]}
        if op == OP_SWAP:
            return {"op": op, "pid": data[5:37], "tin": data[37:69],
                    "amt": struct.unpack_from("<Q", data, 69)[0],
                    "min_out": struct.unpack_from("<Q", data, 77)[0]}
    except (IndexError, struct.error):
        return None
    return None


def find_amm_payload(tx):
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


class AmmDB:
    """Deterministic AMM state (mirrors TokenDB/DexDB)."""

    def __init__(self):
        self.pools: dict[bytes, dict] = {}        # pool_id -> pool
        self.shares: dict[tuple, int] = {}        # (pool_id, spk) -> LP shares
        self.journal: dict[int, list] = {}
        self.needs_rebuild = False

    def quote(self, pool, tin, amt):
        if tin == pool["ta"]:
            rin, rout = pool["ra"], pool["rb"]
        else:
            rin, rout = pool["rb"], pool["ra"]
        eff = amt * (10000 - pool["fee"]) // 10000
        return rout * eff // (rin + eff) if rin + eff else 0

    def apply_block(self, block, height, token_db, lookup_script):
        journal = []
        for tx in block.txs:
            p = find_amm_payload(tx)
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
        if op == OP_CREATE:
            if (sender is None or p["ta"] >= p["tb"] or p["fee"] > MAX_FEE_BPS
                    or p["ta"] not in db.registry or p["tb"] not in db.registry):
                return
            pid = tx.txid()
            if pid in self.pools:
                return
            self.pools[pid] = {"pid": pid, "ta": p["ta"], "tb": p["tb"],
                               "ra": 0, "rb": 0, "fee": p["fee"],
                               "total_shares": 0}
            j.append(("pool", pid))
        elif op == OP_ADD:
            pool = self.pools.get(p["pid"])
            if (pool is None or sender is None or p["a"] <= 0 or p["b"] <= 0
                    or db.balance(pool["ta"], sender) < p["a"]
                    or db.balance(pool["tb"], sender) < p["b"]):
                return
            if pool["total_shares"] == 0:
                shares = math.isqrt(p["a"] * p["b"])
            else:
                shares = min(p["a"] * pool["total_shares"] // pool["ra"],
                             p["b"] * pool["total_shares"] // pool["rb"])
            if shares <= 0:
                return
            db._debit(j, pool["ta"], sender, p["a"])
            db._debit(j, pool["tb"], sender, p["b"])
            pool["ra"] += p["a"]; pool["rb"] += p["b"]
            pool["total_shares"] += shares
            key = (p["pid"], sender)
            self.shares[key] = self.shares.get(key, 0) + shares
            j.append(("res", pool, -p["a"], -p["b"], -shares))
            j.append(("share", p["pid"], sender, shares))
        elif op == OP_REMOVE:
            pool = self.pools.get(p["pid"])
            key = (p["pid"], sender)
            if (pool is None or sender is None or p["shares"] <= 0
                    or self.shares.get(key, 0) < p["shares"]):
                return
            a = p["shares"] * pool["ra"] // pool["total_shares"]
            b = p["shares"] * pool["rb"] // pool["total_shares"]
            pool["ra"] -= a; pool["rb"] -= b
            pool["total_shares"] -= p["shares"]
            self.shares[key] -= p["shares"]
            db._credit(j, pool["ta"], sender, a)
            db._credit(j, pool["tb"], sender, b)
            j.append(("res", pool, a, b, p["shares"]))
            j.append(("share", p["pid"], sender, -p["shares"]))
        elif op == OP_SWAP:
            pool = self.pools.get(p["pid"])
            if (pool is None or sender is None or p["amt"] <= 0
                    or p["tin"] not in (pool["ta"], pool["tb"])):
                return
            tout = pool["tb"] if p["tin"] == pool["ta"] else pool["ta"]
            out = self.quote(pool, p["tin"], p["amt"])
            if out <= 0 or out < p["min_out"]:
                return
            if db.balance(p["tin"], sender) < p["amt"]:
                return
            db._debit(j, p["tin"], sender, p["amt"])
            db._credit(j, tout, sender, out)
            if p["tin"] == pool["ta"]:
                pool["ra"] += p["amt"]; pool["rb"] -= out
                j.append(("swapres", pool, "a", -p["amt"], out))
            else:
                pool["rb"] += p["amt"]; pool["ra"] -= out
                j.append(("swapres", pool, "b", -p["amt"], out))

    def unapply_block(self, height, token_db):
        journal = self.journal.pop(height, None)
        if journal is None:
            if height <= max(self.journal, default=-1):
                self.needs_rebuild = True
            return
        for rec in reversed(journal):
            if rec[0] == "pool":
                self.pools.pop(rec[1], None)
            elif rec[0] == "res":
                pool, da, db_, ds = rec[1], rec[2], rec[3], rec[4]
                pool["ra"] += da; pool["rb"] += db_; pool["total_shares"] += ds
            elif rec[0] == "share":
                _, pid, spk, d = rec
                key = (pid, spk)
                self.shares[key] = self.shares.get(key, 0) - d
                if not self.shares[key]:
                    self.shares.pop(key, None)
            elif rec[0] == "swapres":
                pool, side, din, dout = rec[1], rec[2], rec[3], rec[4]
                if side == "a":
                    pool["ra"] += din; pool["rb"] += dout
                else:
                    pool["rb"] += din; pool["ra"] += dout
            elif rec[0] == "bal":
                _, tid, spk, delta = rec
                key = (tid, spk)
                token_db.balances[key] = token_db.balances.get(key, 0) - delta
                if not token_db.balances[key]:
                    token_db.balances.pop(key, None)

    def list_pools(self, params, token_db):
        from .utils import hash_to_hex
        out = []
        for p in self.pools.values():
            ta = token_db.registry.get(p["ta"])
            tb = token_db.registry.get(p["tb"])
            out.append({
                "pool_id": hash_to_hex(p["pid"]),
                "pair": f"{ta.name if ta else '?'}/{tb.name if tb else '?'}",
                "token_a": hash_to_hex(p["ta"]),
                "token_b": hash_to_hex(p["tb"]),
                "reserve_a": p["ra"], "reserve_b": p["rb"],
                "fee_bps": p["fee"], "total_shares": p["total_shares"],
            })
        return out
