"""Alpha Identity — decentralized identifiers (DIDs) + verifiable credentials.

did:alpha:<address> — your address IS your DID. Self-sovereign: only the
key holder controls the identity. Claims/credentials are anchored on-chain
via OP_RETURN ops (same trustless pattern as tokens/DEX/AMM); the claim's
content stays off-chain — only its hash is anchored (privacy-preserving).

Wire format (OP_RETURN, single push):

    "AID" | version(1) | op(1) | payload...

    op=0x01 REGISTER : label_len(1) | label | doc_hash(32, optional)
                       binds a human label / DID-document hash to the
                       sender's script (the DID)
    op=0x02 CLAIM    : subject_pkh(20) | ctype_len(1) | ctype | chash(32)
                       issuer attests a credential (e.g. "kyc") about a
                       subject — verifiable via issuer signature + chain
    op=0x03 REVOKE   : claim_id(32) — issuer revokes their claim
"""

from . import script as _script

MAGIC = b"AID"
VERSION = 1
OP_REGISTER = 0x01
OP_CLAIM = 0x02
OP_REVOKE = 0x03


def encode_register(label: str, doc_hash: bytes = b"") -> bytes:
    n = label.encode()[:64]
    return MAGIC + bytes([VERSION, OP_REGISTER, len(n)]) + n + doc_hash[:32]


def encode_claim(subject_pkh: bytes, ctype: str, chash: bytes) -> bytes:
    t = ctype.encode()[:32]
    return (MAGIC + bytes([VERSION, OP_CLAIM]) + subject_pkh[:20]
            + bytes([len(t)]) + t + chash[:32])


def encode_revoke(claim_id: bytes) -> bytes:
    return MAGIC + bytes([VERSION, OP_REVOKE]) + claim_id


def parse_payload(data):
    if not data or data[:3] != MAGIC or len(data) < 5 or data[3] != VERSION:
        return None
    op = data[4]
    try:
        if op == OP_REGISTER:
            nl = data[5]
            return {"op": op, "label": data[6:6+nl].decode(),
                    "doc_hash": data[6+nl:6+nl+32] or None}
        if op == OP_CLAIM:
            tl = data[25]
            return {"op": op, "subject": data[5:25],
                    "ctype": data[26:26+tl].decode(),
                    "chash": data[26+tl:26+tl+32]}
        if op == OP_REVOKE:
            return {"op": op, "claim_id": data[5:37]}
    except (IndexError, UnicodeDecodeError):
        return None
    return None


def find_identity_payload(tx):
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


class IdentityDB:
    def __init__(self):
        self.dids: dict[bytes, dict] = {}      # spk -> {label, doc_hash, height}
        self.claims: dict[bytes, dict] = {}    # claim_id -> claim
        self.journal: dict[int, list] = {}
        self.needs_rebuild = False

    def apply_block(self, block, height, lookup_script):
        journal = []
        for tx in block.txs:
            p = find_identity_payload(tx)
            if p is None:
                continue
            sender = None
            if tx.vin and not tx.vin[0].is_coinbase():
                sender = lookup_script(tx.vin[0].prevout.key())
            if sender is None:
                continue
            self._apply(p, tx, sender, height, journal)
        if journal:
            self.journal[height] = journal

    def _apply(self, p, tx, sender, height, j):
        if p["op"] == OP_REGISTER:
            self.dids[sender] = {"label": p["label"],
                                 "doc_hash": p["doc_hash"], "height": height}
            j.append(("did", sender, self.dids.get(sender)))
        elif p["op"] == OP_CLAIM:
            cid = tx.txid()
            self.claims[cid] = {"issuer": sender, "subject": p["subject"],
                                "ctype": p["ctype"], "chash": p["chash"],
                                "revoked": False, "height": height}
            j.append(("claim", cid))
        elif p["op"] == OP_REVOKE:
            c = self.claims.get(p["claim_id"])
            if c and c["issuer"] == sender and not c["revoked"]:
                c["revoked"] = True
                j.append(("revoke", p["claim_id"]))

    def unapply_block(self, height):
        journal = self.journal.pop(height, None)
        if journal is None:
            if height <= max(self.journal, default=-1):
                self.needs_rebuild = True
            return
        for rec in reversed(journal):
            if rec[0] == "did":
                self.dids.pop(rec[1], None) if rec[2] is None else \
                    self.dids.__setitem__(rec[1], rec[2])
            elif rec[0] == "claim":
                self.claims.pop(rec[1], None)
            elif rec[0] == "revoke":
                self.claims[rec[1]]["revoked"] = False

    def resolve(self, spk, params):
        """W3C-style DID resolution for a script's identity."""
        from .utils import hash160
        did = "did:alpha:" + _script.extract_destination(spk, params)
        prof = self.dids.get(spk)
        return {
            "did": did,
            "controller": _script.extract_destination(spk, params),
            "label": prof["label"] if prof else None,
            "claims": [self.claim_json(c, params)
                       for c in self.claims.values()
                       if len(spk) == 25 and c["subject"] == spk[3:23]],
            "registered": prof is not None,
        }

    def claim_json(self, c, params):
        from .utils import hash_to_hex
        return {"issuer": _script.extract_destination(c["issuer"], params),
                "type": c["ctype"], "hash": c["chash"].hex(),
                "revoked": c["revoked"], "height": c["height"]}
