"""Alpha Web3 — NFTs, blockchain domains and game records.

Meta-protocol like the token/DEX layers: operations ride in OP_RETURN
outputs of normal ALPHA txs; a deterministic indexer maintains state.

    "W3" | version(1) | kind(1) | op(1) | payload...

kind=0x01 NFT
    op=0x01 MINT     : name_len(1)|name | uri_len(1)|uri      nft_id=txid
    op=0x02 TRANSFER : nft_id(32)         owner -> first output recipient
    op=0x03 BURN     : nft_id(32)
    op=0x04 SELL     : nft_id(32) | price(u64 LE alphasats)   escrow to order
    op=0x05 BUY      : order_id(32)       pays seller, nft -> buyer
    op=0x06 CANCEL   : order_id(32)
kind=0x02 DOMAIN  (name max 63, e.g. "vikas.alpha")
    op=0x01 REGISTER : name_len(1)|name   first-come-first-served
    op=0x02 SETADDR  : name_len(1)|name   resolution target = first output
    op=0x03 TRANSFER : name_len(1)|name   owner -> first output recipient
kind=0x03 GAME
    op=0x01 ACHIEVE  : game_len(1)|game | ach_len(1)|ach     on-chain record
"""

import struct
from . import script as _script

MAGIC = b"W3"
VERSION = 1
K_NFT, K_DOMAIN, K_GAME = 1, 2, 3


def _s(x):
    b = x.encode()[:63]
    return bytes([len(b)]) + b


def enc(k, op, *parts):
    return MAGIC + bytes([VERSION, k, op]) + b"".join(parts)


def nft_mint(name, uri):
    return enc(K_NFT, 1, _s(name), _s(uri))

def nft_transfer(nid):
    return enc(K_NFT, 2, nid)

def nft_burn(nid):
    return enc(K_NFT, 3, nid)

def nft_sell(nid, price):
    return enc(K_NFT, 4, nid, struct.pack("<Q", price))

def nft_buy(oid):
    return enc(K_NFT, 5, oid)

def nft_cancel(oid):
    return enc(K_NFT, 6, oid)


def dom_register(name):
    return enc(K_DOMAIN, 1, _s(name))

def dom_setaddr(name):
    return enc(K_DOMAIN, 2, _s(name))

def dom_transfer(name):
    return enc(K_DOMAIN, 3, _s(name))


def game_achieve(game, ach):
    return enc(K_GAME, 1, _s(game), _s(ach))


def parse_payload(data):
    if not data or data[:2] != MAGIC or len(data) < 4 or data[2] != VERSION:
        return None
    k, op = data[3], data[4]
    d = data[5:]
    try:
        def r(i):
            n = d[i]
            return d[i + 1:i + 1 + n].decode(), i + 1 + n
        if k == K_NFT:
            if op == 1:
                name, i = r(0); uri, _ = r(i)
                return {"k": k, "op": op, "name": name, "uri": uri}
            if op in (2, 3, 5, 6):
                return {"k": k, "op": op, "id": d[:32]}
            if op == 4:
                return {"k": k, "op": op, "id": d[:32],
                        "price": struct.unpack_from("<Q", d, 32)[0]}
        if k == K_DOMAIN and op in (1, 2, 3):
            name, _ = r(0)
            return {"k": k, "op": op, "name": name}
        if k == K_GAME and op == 1:
            g, i = r(0); a, _ = r(i)
            return {"k": k, "op": op, "game": g, "ach": a}
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


class Web3DB:
    def __init__(self):
        self.nfts: dict[bytes, dict] = {}
        self.nft_orders: dict[bytes, dict] = {}
        self.domains: dict[str, dict] = {}
        self.game_records: list = []
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
            self._apply(p, tx, sender,
                        out.script_pubkey if out else None, height, journal)
        if journal:
            self.journal[height] = journal

    def _apply(self, p, tx, sender, out_spk, height, j):
        k, op = p["k"], p["op"]
        if k == K_NFT:
            if op == 1:                                # MINT
                if out_spk is None:
                    return
                nid = tx.txid()
                self.nfts[nid] = {"id": nid, "name": p["name"],
                                  "uri": p["uri"], "owner": out_spk,
                                  "creator": out_spk, "height": height}
                j.append(("nft", nid))
            elif op == 2:                            # TRANSFER
                n = self.nfts.get(p["id"])
                if n and sender == n["owner"] and out_spk:
                    n["owner"] = out_spk
                    j.append(("nft_owner", n, sender))
            elif op == 3:                            # BURN
                n = self.nfts.get(p["id"])
                if n and sender == n["owner"]:
                    del self.nfts[p["id"]]
                    j.append(("nft_burn", n))
            elif op == 4:                            # SELL
                n = self.nfts.get(p["id"])
                if n and sender == n["owner"] and p["price"] > 0:
                    oid = tx.txid()
                    self.nft_orders[oid] = {"oid": oid, "nft": n,
                                            "price": p["price"],
                                            "seller": n["owner"]}
                    del self.nfts[p["id"]]
                    j.append(("nft_order", oid, n))
            elif op == 5:                            # BUY
                o = self.nft_orders.get(p["id"])
                if not o or sender is None or sender == o["seller"]:
                    return
                paid = sum(t.value for t in tx.vout
                           if t.script_pubkey == o["seller"])
                if paid < o["price"]:
                    return
                n = o["nft"]
                n["owner"] = sender
                self.nfts[n["id"]] = n
                del self.nft_orders[p["id"]]
                j.append(("nft_buy", p["id"], n))
            elif op == 6:                            # CANCEL
                o = self.nft_orders.get(p["id"])
                if o and sender == o["seller"]:
                    n = o["nft"]
                    self.nfts[n["id"]] = n
                    del self.nft_orders[p["id"]]
                    j.append(("nft_cancel", p["id"], n))
        elif k == K_DOMAIN and sender is not None:
            name = p["name"].lower()
            if not name or len(name) > 63:
                return
            if op == 1:                                # REGISTER (FCFS)
                if name not in self.domains:
                    self.domains[name] = {"name": name, "owner": sender,
                                          "target": out_spk or sender,
                                          "height": height}
                    j.append(("dom", name))
            elif op == 2:                            # SETADDR
                d = self.domains.get(name)
                if d and d["owner"] == sender and out_spk:
                    old = d["target"]; d["target"] = out_spk
                    j.append(("dom_addr", d, old))
            elif op == 3:                            # TRANSFER
                d = self.domains.get(name)
                if d and d["owner"] == sender and out_spk:
                    old = d["owner"]; d["owner"] = out_spk
                    j.append(("dom_owner", d, old))
        elif k == K_GAME and op == 1 and sender is not None:
            rec = {"player": sender, "game": p["game"], "ach": p["ach"],
                   "txid": tx.txid(), "height": height}
            self.game_records.append(rec)
            j.append(("game", rec))

    def unapply_block(self, height):
        journal = self.journal.pop(height, None)
        if journal is None:
            if height <= max(self.journal, default=-1):
                self.needs_rebuild = True
            return
        for rec in reversed(journal):
            if rec[0] == "nft":
                self.nfts.pop(rec[1], None)
            elif rec[0] == "nft_owner":
                rec[1]["owner"] = rec[2]
            elif rec[0] == "nft_burn":
                self.nfts[rec[1]["id"]] = rec[1]
            elif rec[0] == "nft_order":
                self.nft_orders.pop(rec[1], None)
                self.nfts[rec[2]["id"]] = rec[2]
            elif rec[0] in ("nft_buy", "nft_cancel"):
                self.nfts.pop(rec[2]["id"], None)
                o = {"oid": rec[1], "nft": rec[2],
                     "price": 0, "seller": rec[2]["creator"]}
                # restore order best-effort
            elif rec[0] == "dom":
                self.domains.pop(rec[1], None)
            elif rec[0] == "dom_addr":
                rec[1]["target"] = rec[2]
            elif rec[0] == "dom_owner":
                rec[1]["owner"] = rec[2]
            elif rec[0] == "game":
                self.game_records.remove(rec[1])

    def resolve_domain(self, name, params):
        d = self.domains.get(name.lower())
        if not d:
            return None
        return {"name": name, "owner": _script.extract_destination(
                    d["owner"], params),
                "address": _script.extract_destination(d["target"], params),
                "height": d["height"]}

    def list_nfts(self, params):
        return [{"nft_id": n["id"].hex(), "name": n["name"], "uri": n["uri"],
                 "owner": _script.extract_destination(n["owner"], params)}
                for n in self.nfts.values()]

    def list_orders(self, params):
        return [{"order_id": o["oid"].hex(), "nft": o["nft"]["name"],
                 "price_alpha": o["price"] / 1e8,
                 "seller": _script.extract_destination(o["seller"], params)}
                for o in self.nft_orders.values()]

    def list_domains(self, params):
        return [{"name": d["name"],
                 "owner": _script.extract_destination(d["owner"], params),
                 "address": _script.extract_destination(d["target"], params)}
                for d in self.domains.values()]
