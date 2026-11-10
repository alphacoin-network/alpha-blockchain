"""Alpha Enterprise — supply chain, certificates/audit, business registry.

Meta-protocol (OP_RETURN), deterministic indexer.

    "ENT" | version(1) | kind(1) | op(1) | payload...

kind=0x01 SUPPLY — product tracking + event history
    op=0x01 ITEM  : name_len|name | sku_len|sku          item_id=txid
    op=0x02 EVENT : item_id(32) | stage_len|stage | loc_len|loc | nlen(2)|note
kind=0x02 CERT — tamper-evident digital certificates
    op=0x01 ISSUE  : hash(32) | ctype_len|ctype | subj_len|subject  cert_id=txid
    op=0x02 REVOKE : cert_id(32)
kind=0x03 BIZ — corporate registry
    op=0x01 REGISTER : name_len|name | reg_len|regnum | jur_len|jur | meta(32)
    op=0x02 UPDATE   : biz_id(32) | field_len|field | val_len|val
"""

import struct
from . import script as _script

MAGIC = b"ENT"
VERSION = 1
K_SUPPLY, K_CERT, K_BIZ = 1, 2, 3


def _s(x, n=63):
    b = x.encode()[:n]
    return bytes([len(b)]) + b


def enc(k, op, *parts):
    return MAGIC + bytes([VERSION, k, op]) + b"".join(parts)


def item_reg(name, sku):
    return enc(K_SUPPLY, 1, _s(name), _s(sku))


def item_event(item_id, stage, loc, note):
    nb = note.encode()[:256]
    return enc(K_SUPPLY, 2, item_id, _s(stage), _s(loc),
               struct.pack("<H", len(nb)) + nb)


def cert_issue(h, ctype, subject):
    return enc(K_CERT, 1, h[:32].ljust(32, b"\x00"), _s(ctype), _s(subject))


def cert_revoke(cert_id):
    return enc(K_CERT, 2, cert_id)


def biz_reg(name, regnum, jur, meta=b""):
    return enc(K_BIZ, 1, _s(name), _s(regnum), _s(jur),
               meta[:32].ljust(32, b"\x00"))


def biz_update(biz_id, field, val):
    return enc(K_BIZ, 2, biz_id, _s(field), _s(val, 128))


def parse_payload(data):
    if not data or data[:3] != MAGIC or len(data) < 6 or data[3] != VERSION:
        return None
    k, op = data[4], data[5]
    d = data[6:]
    try:
        def r(i, n=255):
            ln = d[i]
            return d[i + 1:i + 1 + ln].decode(), i + 1 + ln
        if k == K_SUPPLY:
            if op == 1:
                name, i = r(0); sku, _ = r(i)
                return {"k": k, "op": op, "name": name, "sku": sku}
            if op == 2:
                iid = d[:32]
                st, i = r(32); loc, i = r(i)
                nl = struct.unpack_from("<H", d, i)[0]
                return {"k": k, "op": op, "item": iid, "stage": st,
                        "loc": loc, "note": d[i + 2:i + 2 + nl].decode()}
        if k == K_CERT:
            if op == 1:
                ct, i = r(32); subj, _ = r(i)
                return {"k": k, "op": op, "hash": d[:32],
                        "ctype": ct, "subj": subj}
            if op == 2:
                return {"k": k, "op": op, "cert": d[:32]}
        if k == K_BIZ:
            if op == 1:
                name, i = r(0); reg, i = r(i); jur, i = r(i)
                return {"k": k, "op": op, "name": name, "reg": reg,
                        "jur": jur, "meta": d[i:i + 32]}
            if op == 2:
                bid = d[:32]
                f, i = r(32); v, _ = r(i, 128)
                return {"k": k, "op": op, "biz": bid, "field": f, "val": v}
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


class EntDB:
    def __init__(self):
        self.items: dict[bytes, dict] = {}
        self.events: dict[bytes, list] = {}
        self.certs: dict[bytes, dict] = {}
        self.cert_by_hash: dict[bytes, bytes] = {}
        self.biz: dict[bytes, dict] = {}
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
            if sender is not None:
                self._apply(p, tx, sender, height, journal)
        if journal:
            self.journal[height] = journal

    def _apply(self, p, tx, sender, height, j):
        k, op = p["k"], p["op"]
        if k == K_SUPPLY:
            if op == 1:
                iid = tx.txid()
                self.items[iid] = {"id": iid, "name": p["name"],
                                   "sku": p["sku"], "owner": sender,
                                   "height": height}
                self.events[iid] = []
                j.append(("item", iid))
            elif op == 2:
                it = self.items.get(p["item"])
                if it and it["owner"] == sender:
                    ev = {"stage": p["stage"], "loc": p["loc"],
                          "note": p["note"], "height": height,
                          "txid": tx.txid().hex()}
                    self.events[it["id"]].append(ev)
                    j.append(("event", it["id"], ev))
        elif k == K_CERT:
            if op == 1:
                cid = tx.txid()
                self.certs[cid] = {"id": cid, "hash": p["hash"],
                                   "ctype": p["ctype"], "subj": p["subj"],
                                   "issuer": sender, "revoked": False,
                                   "height": height}
                self.cert_by_hash[p["hash"]] = cid
                j.append(("cert", cid))
            elif op == 2:
                c = self.certs.get(p["cert"])
                if c and c["issuer"] == sender and not c["revoked"]:
                    c["revoked"] = True
                    j.append(("unrevoke", p["cert"]))
        elif k == K_BIZ:
            if op == 1:
                bid = tx.txid()
                self.biz[bid] = {"id": bid, "name": p["name"],
                                 "reg": p["reg"], "jur": p["jur"],
                                 "meta": p["meta"].hex(), "owner": sender,
                                 "fields": {}, "height": height}
                j.append(("biz", bid))
            elif op == 2:
                b = self.biz.get(p["biz"])
                if b and b["owner"] == sender:
                    old = b["fields"].get(p["field"])
                    b["fields"][p["field"]] = p["val"]
                    j.append(("biz_field", b, p["field"], old))

    def unapply_block(self, height):
        journal = self.journal.pop(height, None)
        if journal is None:
            if height <= max(self.journal, default=-1):
                self.needs_rebuild = True
            return
        for rec in reversed(journal):
            if rec[0] == "item":
                self.items.pop(rec[1], None)
                self.events.pop(rec[1], None)
            elif rec[0] == "event":
                self.events[rec[1]].remove(rec[2])
            elif rec[0] == "cert":
                c = self.certs.pop(rec[1], None)
                if c:
                    self.cert_by_hash.pop(c["hash"], None)
            elif rec[0] == "unrevoke":
                self.certs[rec[1]]["revoked"] = False
            elif rec[0] == "biz":
                self.biz.pop(rec[1], None)
            elif rec[0] == "biz_field":
                b, f, old = rec[1], rec[2], rec[3]
                if old is None:
                    b["fields"].pop(f, None)
                else:
                    b["fields"][f] = old

    def verify_cert(self, h: bytes):
        cid = self.cert_by_hash.get(h)
        return self.certs.get(cid)

    def list_items(self, params):
        return [{"item_id": i["id"].hex(), "name": i["name"], "sku": i["sku"],
                 "events": len(self.events[i["id"]]),
                 "owner": _script.extract_destination(i["owner"], params)}
                for i in self.items.values()]

    def list_biz(self, params):
        return [{"biz_id": b["id"].hex(), "name": b["name"],
                 "reg": b["reg"], "jurisdiction": b["jur"],
                 "fields": b["fields"],
                 "owner": _script.extract_destination(b["owner"], params)}
                for b in self.biz.values()]
