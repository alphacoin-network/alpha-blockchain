"""Alpha Escrow & Lending — trustless 3-party escrow + collateralized loans.

Meta-protocol (OP_RETURN), deterministic indexer.

    "ESC" | version(1) | kind(1) | op(1) | payload...

kind=0x01 ESCROW — depositor locks tokens; beneficiary+arbiter 3-party
    op=0x01 OPEN    : token_id(32)|amt(u64)|benef(20)|arb(20)|expiry(u32)|terms
    op=0x02 RELEASE : escrow_id(32)   depositor OR arbiter → to beneficiary
    op=0x03 DISPUTE : escrow_id(32)   depositor OR beneficiary → freeze
    op=0x04 CLAIM   : escrow_id(32)   beneficiary claims after expiry
    op=0x05 REFUND  : escrow_id(32)   arbiter → back to depositor
kind=0x02 LEND — borrower escrows collateral token; lender funds principal
    op=0x01 OPEN  : coll_tid(32)|coll_amt(8)|prin_tid(32)|prin(8)|int_bps(u16)|due(u32)
                    principal_tid = 32×0x00 → principal paid in ALPHA (real tx output)
    op=0x02 FUND  : loan_id(32)   lender escrows token principal, or pays ALPHA
    op=0x03 REPAY : loan_id(32)   borrower repays principal+interest → collateral back
    op=0x04 SEIZE : loan_id(32)   after due_height, lender takes collateral
kind=0x03 INVOICE — merchant payment links
    op=0x01 CREATE : amount(u64)|label_len|label     invoice_id=txid
    op=0x02 PAY    : invoice_id(32)   pays merchant's first-output address
"""

import struct
from . import script as _script
from .utils import hash_to_hex

MAGIC = b"ESC"
VERSION = 1
K_ESC, K_LEND, K_INV = 1, 2, 3
ZERO32 = b"\x00" * 32


def _s(x, n=200):
    b = x.encode()[:n]
    return bytes([len(b)]) + b


def enc(k, op, *parts):
    return MAGIC + bytes([VERSION, k, op]) + b"".join(parts)


def esc_open(tid, amt, benef, arb, expiry, terms=""):
    return enc(K_ESC, 1, tid, struct.pack("<Q", amt), benef[:20], arb[:20],
               struct.pack("<I", expiry), _s(terms))


def esc_op(op, eid):
    return enc(K_ESC, op, eid)


def lend_open(ctid, camt, ptid, pamt, bps, due):
    return enc(K_LEND, 1, ctid, struct.pack("<Q", camt), ptid,
               struct.pack("<Q", pamt), struct.pack("<H", bps),
               struct.pack("<I", due))


def lend_op(op, lid):
    return enc(K_LEND, op, lid)


def inv_create(amount, label):
    return enc(K_INV, 1, struct.pack("<Q", amount), _s(label))


def inv_pay(inv_id):
    return enc(K_INV, 2, inv_id)


def parse_payload(data):
    if not data or data[:3] != MAGIC or len(data) < 6 or data[3] != VERSION:
        return None
    k, op = data[4], data[5]
    d = data[6:]
    try:
        if k == K_ESC:
            if op == 1:
                tl = d[36]
                return {"k": k, "op": op, "tid": d[:32],
                        "amt": struct.unpack_from("<Q", d, 32)[0],
                        "benef": d[40:60], "arb": d[60:80],
                        "expiry": struct.unpack_from("<I", d, 80)[0] if len(d) >= 84 else 0,
                        "terms": d[84:84 + tl].decode() if len(d) > 84 else ""}
            if op in (2, 3, 4, 5):
                return {"k": k, "op": op, "id": d[:32]}
        if k == K_LEND:
            if op == 1:
                return {"k": k, "op": op, "ctid": d[:32],
                        "camt": struct.unpack_from("<Q", d, 32)[0],
                        "ptid": d[40:72],
                        "pamt": struct.unpack_from("<Q", d, 72)[0],
                        "bps": struct.unpack_from("<H", d, 80)[0],
                        "due": struct.unpack_from("<I", d, 82)[0]}
            if op in (2, 3, 4):
                return {"k": k, "op": op, "id": d[:32]}
        if k == K_INV:
            if op == 1:
                ll = struct.unpack_from("<Q", d, 0)[0]
                n = d[8]
                return {"k": k, "op": op, "amt": ll,
                        "label": d[9:9 + n].decode()}
            if op == 2:
                return {"k": k, "op": op, "id": d[:32]}
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


def _pkh(spk):
    if len(spk) == 25:
        return spk[3:23]
    if len(spk) == 22:
        return spk[2:22]
    return None


class EscrowDB:
    def __init__(self):
        self.escrows: dict[bytes, dict] = {}
        self.loans: dict[bytes, dict] = {}
        self.invoices: dict[bytes, dict] = {}
        self.journal: dict[int, list] = {}
        self.needs_rebuild = False

    def apply_block(self, block, height, token_db, lookup_script):
        journal = []
        for tx in block.txs:
            p = find_payload(tx)
            if p is None:
                continue
            sender = None
            if tx.vin and not tx.vin[0].is_coinbase():
                sender = lookup_script(tx.vin[0].prevout.key())
            if sender is not None:
                self._apply(p, tx, sender, token_db, height, journal)
        if journal:
            self.journal[height] = journal

    def _apply(self, p, tx, sender, db, height, j):
        k, op = p["k"], p["op"]
        if k == K_ESC:
            if op == 1:
                if (p["amt"] <= 0 or p["tid"] not in db.registry
                        or db.balance(p["tid"], sender) < p["amt"]):
                    return
                eid = tx.txid()
                db._debit(j, p["tid"], sender, p["amt"])
                self.escrows[eid] = {"id": eid, "tid": p["tid"],
                                     "amt": p["amt"], "dep": sender,
                                     "benef": p["benef"], "arb": p["arb"],
                                     "expiry": p["expiry"],
                                     "disputed": False, "open": True}
                j.append(("esc", eid))
            else:
                e = self.escrows.get(p["id"])
                if not e or not e["open"]:
                    return
                spk_pkh = _pkh(sender)
                benef_spk = self._spk_of(e["benef"], db)
                if op == 2 and (sender == e["dep"] or spk_pkh == e["arb"]):
                    if e["disputed"] and sender != e["dep"] and spk_pkh != e["arb"]:
                        return
                    db._credit(j, e["tid"], benef_spk, e["amt"])
                elif op == 3 and (sender == e["dep"] or sender == benef_spk):
                    e["disputed"] = True
                    j.append(("esc_dispute", e))
                    return
                elif op == 4 and sender == benef_spk \
                        and height >= e["expiry"] and not e["disputed"]:
                    db._credit(j, e["tid"], benef_spk, e["amt"])
                elif op == 5 and spk_pkh == e["arb"]:
                    db._credit(j, e["tid"], e["dep"], e["amt"])
                else:
                    return
                e["open"] = False
                j.append(("esc_close", e))
        elif k == K_LEND:
            if op == 1:
                if (p["camt"] <= 0 or p["pamt"] <= 0
                        or p["ctid"] not in db.registry
                        or db.balance(p["ctid"], sender) < p["camt"]
                        or (p["ptid"] != ZERO32 and p["ptid"] not in db.registry)):
                    return
                lid = tx.txid()
                db._debit(j, p["ctid"], sender, p["camt"])
                self.loans[lid] = {"id": lid, "ctid": p["ctid"],
                                   "camt": p["camt"], "ptid": p["ptid"],
                                   "pamt": p["pamt"], "bps": p["bps"],
                                   "due": p["due"], "borrower": sender,
                                   "lender": None, "state": "offered"}
                j.append(("loan", lid))
            else:
                l = self.loans.get(p["id"])
                if not l or l["state"] == "closed":
                    return
                if op == 2 and l["state"] == "offered" \
                        and sender != l["borrower"]:
                    if l["ptid"] == ZERO32:
                        # ALPHA principal — real payment to borrower required
                        paid = sum(t.value for t in tx.vout
                                   if t.script_pubkey == l["borrower"])
                        if paid < l["pamt"]:
                            return
                    else:
                        if db.balance(l["ptid"], sender) < l["pamt"]:
                            return
                        db._debit(j, l["ptid"], sender, l["pamt"])
                        db._credit(j, l["ptid"], l["borrower"], l["pamt"])
                    l["lender"] = sender
                    l["state"] = "active"
                    j.append(("loan_fund", l))
                elif op == 3 and l["state"] == "active" \
                        and sender == l["borrower"]:
                    repay = l["pamt"] * (10000 + l["bps"]) // 10000
                    if l["ptid"] == ZERO32:
                        paid = sum(t.value for t in tx.vout
                                   if t.script_pubkey == l["lender"])
                        if paid < repay:
                            return
                    else:
                        if db.balance(l["ptid"], sender) < repay:
                            return
                        db._debit(j, l["ptid"], sender, repay)
                        db._credit(j, l["ptid"], l["lender"], repay)
                    db._credit(j, l["ctid"], l["borrower"], l["camt"])
                    l["state"] = "closed"
                    j.append(("loan_close", l))
                elif op == 4 and l["state"] == "active" \
                        and sender == l["lender"] and height >= l["due"]:
                    db._credit(j, l["ctid"], l["lender"], l["camt"])
                    l["state"] = "closed"
                    j.append(("loan_seize", l))
        elif k == K_INV:
            if op == 1:
                iid = tx.txid()
                self.invoices[iid] = {"id": iid, "merchant": sender,
                                      "amt": p["amt"], "label": p["label"],
                                      "paid": False, "height": height}
                j.append(("inv", iid))
            elif op == 2:
                inv = self.invoices.get(p["id"])
                if inv and not inv["paid"]:
                    paid = sum(t.value for t in tx.vout
                               if t.script_pubkey == inv["merchant"])
                    if paid >= inv["amt"]:
                        inv["paid"] = True
                        inv["payer"] = sender
                        j.append(("inv_paid", inv))

    def _spk_of(self, pkh, db):
        for (tid, s) in db.balances:
            if _pkh(s) == pkh:
                return s
        return None

    def unapply_block(self, height, token_db):
        journal = self.journal.pop(height, None)
        if journal is None:
            if height <= max(self.journal, default=-1):
                self.needs_rebuild = True
            return
        for rec in reversed(journal):
            if rec[0] == "esc":
                self.escrows.pop(rec[1], None)
            elif rec[0] == "esc_dispute":
                rec[1]["disputed"] = False
            elif rec[0] == "esc_close":
                rec[1]["open"] = True
            elif rec[0] == "loan":
                self.loans.pop(rec[1], None)
            elif rec[0] == "loan_fund":
                rec[1]["lender"] = None
                rec[1]["state"] = "offered"
            elif rec[0] in ("loan_close", "loan_seize"):
                rec[1]["state"] = "active"
            elif rec[0] == "inv":
                self.invoices.pop(rec[1], None)
            elif rec[0] == "inv_paid":
                rec[1]["paid"] = False
            elif rec[0] == "bal":
                _, tid, spk, delta = rec
                key = (tid, spk)
                token_db.balances[key] = token_db.balances.get(key, 0) - delta
                if not token_db.balances[key]:
                    token_db.balances.pop(key, None)

    def list_escrows(self, params):
        out = []
        for e in self.escrows.values():
            out.append({"escrow_id": hash_to_hex(e["id"]), "open": e["open"],
                        "amount": e["amt"], "disputed": e["disputed"],
                        "expiry": e["expiry"],
                        "depositor": _script.extract_destination(e["dep"], params)})
        return out

    def list_loans(self, params):
        return [{"loan_id": hash_to_hex(l["id"]), "state": l["state"],
                 "collateral": l["camt"],
                 "principal_alpha": l["pamt"] / 1e8 if l["ptid"] == ZERO32 else l["pamt"],
                 "interest_bps": l["bps"], "due_height": l["due"]}
                for l in self.loans.values()]

    def list_invoices(self, params):
        return [{"invoice_id": hash_to_hex(i["id"]), "label": i["label"],
                 "amount": i["amt"] / 1e8, "paid": i["paid"],
                 "merchant": _script.extract_destination(i["merchant"], params)}
                for i in self.invoices.values()]
