"""Alpha AI — oracles (verifiable data feeds) + AI agent layer.

Meta-protocol (OP_RETURN), deterministic indexer like tokens/DEX/Web3.

    "AI" | version(1) | kind(1) | op(1) | payload...

kind=0x01 ORACLE — external data anchored on-chain, source = tx signer
    op=0x01 FEED_REG : name_len(1)|name | meta_len(1)|meta   feed_id=txid
    op=0x02 PUBLISH  : feed_id(32) | vlen(2 LE) | value | ts(u32 LE)
                       only the feed's publisher may post
kind=0x02 AGENT — AI/machine actors + M2M payment receipts
    op=0x01 REGISTER : name_len(1)|name | ep_len(1)|endpoint  agent_id=txid
    op=0x02 RECEIPT  : tag_len(1)|tag
                       payment attestation — first input = payer,
                       first non-OP_RETURN output = payee/amount
"""

import struct
from . import script as _script

MAGIC = b"AI"
VERSION = 1
K_ORACLE, K_AGENT = 1, 2


def _s(x, n=63):
    b = x.encode()[:n]
    return bytes([len(b)]) + b


def enc(k, op, *parts):
    return MAGIC + bytes([VERSION, k, op]) + b"".join(parts)


def feed_reg(name, meta=""):
    return enc(K_ORACLE, 1, _s(name), _s(meta))


def feed_pub(feed_id, value, ts=0):
    v = value.encode()[:512]
    return enc(K_ORACLE, 2, feed_id, struct.pack("<H", len(v)) + v,
               struct.pack("<I", ts))


def agent_reg(name, endpoint=""):
    return enc(K_AGENT, 1, _s(name), _s(endpoint, 128))


def agent_receipt(tag):
    return enc(K_AGENT, 2, _s(tag))


def parse_payload(data):
    if not data or data[:2] != MAGIC or len(data) < 4 or data[2] != VERSION:
        return None
    k, op = data[3], data[4]
    d = data[5:]
    try:
        def r(i, n=63):
            ln = d[i]
            return d[i + 1:i + 1 + ln].decode(), i + 1 + ln
        if k == K_ORACLE:
            if op == 1:
                name, i = r(0); meta, _ = r(i, 128)
                return {"k": k, "op": op, "name": name, "meta": meta}
            if op == 2:
                fid = d[:32]
                vl = struct.unpack_from("<H", d, 32)[0]
                val = d[34:34 + vl].decode()
                ts = struct.unpack_from("<I", d, 34 + vl)[0]
                return {"k": k, "op": op, "feed": fid, "value": val, "ts": ts}
        if k == K_AGENT:
            if op == 1:
                name, i = r(0); ep, _ = r(i, 128)
                return {"k": k, "op": op, "name": name, "ep": ep}
            if op == 2:
                tag, _ = r(0)
                return {"k": k, "op": op, "tag": tag}
    except (IndexError, UnicodeDecodeError, struct.error):
        return None
    return None


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


def first_output(tx):
    for txo in tx.vout:
        if _script.solver(txo.script_pubkey)[0] != _script.TX_NULL_DATA:
            return txo
    return None


class AiDB:
    def __init__(self):
        self.feeds: dict[bytes, dict] = {}
        self.datapoints: dict[bytes, list] = {}
        self.agents: dict[bytes, dict] = {}
        self.receipts: list = []
        self.journal: dict[int, list] = {}
        self.needs_rebuild = False

    def apply_block(self, block, height, lookup_script):
        journal = []
        for tx in block.txs:
            p = find_payload(tx)
            if p is None:
                continue
            sender = None
            if tx.vin and not tx.vin[0].is_coinbase():
                sender = lookup_script(tx.vin[0].prevout.key())
            out = first_output(tx)
            self._apply(p, tx, sender, out, height, journal)
        if journal:
            self.journal[height] = journal

    def _apply(self, p, tx, sender, out, height, j):
        if sender is None:
            return
        k, op = p["k"], p["op"]
        if k == K_ORACLE:
            if op == 1:
                fid = tx.txid()
                self.feeds[fid] = {"id": fid, "name": p["name"],
                                   "meta": p["meta"], "pub": sender,
                                   "height": height}
                self.datapoints[fid] = []
                j.append(("feed", fid))
            elif op == 2:
                f = self.feeds.get(p["feed"])
                if f and f["pub"] == sender:
                    pt = {"value": p["value"], "ts": p["ts"],
                          "height": height, "txid": tx.txid().hex()}
                    self.datapoints[f["id"]].append(pt)
                    f["latest"] = pt
                    j.append(("point", f, pt))
        elif k == K_AGENT:
            if op == 1:
                aid = tx.txid()
                self.agents[aid] = {"id": aid, "name": p["name"],
                                    "endpoint": p["ep"], "owner": sender,
                                    "height": height}
                j.append(("agent", aid))
            elif op == 2:
                rec = {"payer": sender,
                       "payee": out.script_pubkey if out else None,
                       "amount": out.value if out else 0,
                       "tag": p["tag"], "txid": tx.txid(), "height": height}
                self.receipts.append(rec)
                j.append(("receipt", rec))

    def unapply_block(self, height):
        journal = self.journal.pop(height, None)
        if journal is None:
            if height <= max(self.journal, default=-1):
                self.needs_rebuild = True
            return
        for rec in reversed(journal):
            if rec[0] == "feed":
                self.feeds.pop(rec[1], None)
                self.datapoints.pop(rec[1], None)
            elif rec[0] == "point":
                f, pt = rec[1], rec[2]
                self.datapoints[f["id"]].remove(pt)
                f["latest"] = self.datapoints[f["id"]][-1] \
                    if self.datapoints[f["id"]] else None
            elif rec[0] == "agent":
                self.agents.pop(rec[1], None)
            elif rec[0] == "receipt":
                self.receipts.remove(rec[1])

    def list_feeds(self, params):
        out = []
        for f in self.feeds.values():
            out.append({"feed_id": f["id"].hex(), "name": f["name"],
                        "meta": f["meta"],
                        "publisher": _script.extract_destination(f["pub"], params),
                        "latest": f.get("latest"),
                        "points": len(self.datapoints[f["id"]])})
        return out

    def list_agents(self, params):
        return [{"agent_id": a["id"].hex(), "name": a["name"],
                 "endpoint": a["endpoint"],
                 "owner": _script.extract_destination(a["owner"], params)}
                for a in self.agents.values()]

    def list_receipts(self, params):
        return [{"payer": _script.extract_destination(r["payer"], params),
                 "payee": _script.extract_destination(r["payee"], params)
                          if r["payee"] else None,
                 "amount": r["amount"] / 1e8, "tag": r["tag"],
                 "height": r["height"]} for r in self.receipts]
