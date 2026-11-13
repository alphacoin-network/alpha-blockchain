"""Address transaction index (txindex-style) — persistent SQLite.

Indexes every connected block's transaction outputs (incoming) and inputs
(outgoing, resolved via the pre-connect UTXO lookup). Powers instant
address history in the explorer/API/wallet — no block scanning.

Historical blocks indexed at startup are outputs-only (spent prevouts are
no longer resolvable); new blocks index both directions.
"""

import os
import sqlite3

from . import script
from .utils import hash_to_hex


class TxIndex:
    def __init__(self, params, data_dir: str | None = None):
        self.params = params
        path = (os.path.join(data_dir, "txindex.db")
                if data_dir else ":memory:")
        self.db = sqlite3.connect(path)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS addr_tx("
            " addr TEXT, txid TEXT, height INT, direction INT,"
            " value INT, time INT, UNIQUE(addr,txid,direction))")
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_addr ON addr_tx(addr)")
        self.db.commit()

    # -- indexing ---------------------------------------------------------
    def _addr(self, spk: bytes):
        try:
            return script.extract_destination(spk, self.params)
        except Exception:
            return None

    def apply_block(self, block, height: int, lookup=None):
        rows = []
        ts = block.header.timestamp
        for tx in block.txs:
            tid = tx.txid_hex()
            for vout in tx.vout:
                a = self._addr(vout.script_pubkey)
                if a:
                    rows.append((a, tid, height, 1, vout.value, ts))
            if lookup is not None:
                for txin in tx.vin:
                    if txin.is_coinbase():
                        continue
                    spk = lookup(txin.prevout.key())
                    if spk is None:
                        continue
                    a = self._addr(spk)
                    if a:
                        rows.append((a, tid, height, -1, 0, ts))
        if rows:
            self.db.executemany(
                "INSERT OR IGNORE INTO addr_tx VALUES(?,?,?,?,?,?)", rows)
            self.db.commit()

    def unapply_block(self, height: int):
        self.db.execute("DELETE FROM addr_tx WHERE height=?", (height,))
        self.db.commit()

    # -- query --------------------------------------------------------------
    def history(self, addr: str, limit: int = 100):
        cur = self.db.execute(
            "SELECT txid, height, direction, value, time FROM addr_tx"
            " WHERE addr=? ORDER BY height DESC LIMIT ?", (addr, limit))
        return [{"txid": r[0], "height": r[1], "direction": r[2],
                 "value": r[3], "time": r[4]} for r in cur.fetchall()]

    def backfill(self, chain, max_blocks: int = 100000):
        """Index all stored blocks (outputs-only for old blocks)."""
        tip = chain.height
        done = self.db.execute("SELECT COUNT(*) FROM addr_tx").fetchone()[0]
        if done:
            return 0
        n = 0
        for h in range(tip + 1):
            e = chain.get_block_index(h)
            if e is None:
                continue
            b = chain.get_block(e.hash)
            if b is None:
                continue
            self.apply_block(b, h, lookup=None)
            n += 1
            if n >= max_blocks:
                break
        return n
