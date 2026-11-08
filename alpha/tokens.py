"""ALP -- the Alpha Token Protocol.

Tokens live ON the base chain, exactly the way Omni Layer / colored coins
work on Bitcoin: token operations are metadata embedded in OP_RETURN
outputs of normal ALPHA transactions. The base-layer consensus rules do
not change; a parallel deterministic indexer (TokenDB) replays every
block and maintains token balances keyed by scriptPubKey (address).

Anyone can issue, mint, send or burn tokens -- fully decentralized.

Wire format (inside an OP_RETURN output, single push):

    "ALP" | version(1) | op(1) | payload...

    op=0x01 ISSUE : name_len(1) | name | decimals(1) | supply(u64 LE)
                    token_id = txid of the issuance transaction
                    supply credited to the first non-OP_RETURN output
    op=0x02 SEND  : token_id(32) | amount(u64 LE)
                    debited from the first input's prevout script,
                    credited to the first non-OP_RETURN output
    op=0x03 MINT  : token_id(32) | amount(u64 LE)
                    only valid when the issuer script signs the first input;
                    credited to the first non-OP_RETURN output
    op=0x04 BURN  : token_id(32) | amount(u64 LE)
                    debited from the first input's prevout script
"""

import struct
from dataclasses import dataclass, field

from . import script as _script

MAGIC = b"ALP"
VERSION = 1

OP_ISSUE = 0x01
OP_SEND = 0x02
OP_MINT = 0x03
OP_BURN = 0x04
OP_NAMES = {OP_ISSUE: "issue", OP_SEND: "send", OP_MINT: "mint",
            OP_BURN: "burn"}

MAX_TOKEN_NAME = 64
MAX_DECIMALS = 8
MAX_TOKEN_SUPPLY = (1 << 63) - 1


# ---------------------------------------------------------------------------
# Payload encoding / parsing
# ---------------------------------------------------------------------------
def encode_issue(name: str, decimals: int, supply: int) -> bytes:
    n = name.encode("utf-8")[:MAX_TOKEN_NAME]
    return (MAGIC + bytes([VERSION, OP_ISSUE, len(n)]) + n
            + bytes([decimals]) + struct.pack("<Q", supply))


def encode_send(token_id: bytes, amount: int) -> bytes:
    return MAGIC + bytes([VERSION, OP_SEND]) + token_id + struct.pack("<Q", amount)


def encode_mint(token_id: bytes, amount: int) -> bytes:
    return MAGIC + bytes([VERSION, OP_MINT]) + token_id + struct.pack("<Q", amount)


def encode_burn(token_id: bytes, amount: int) -> bytes:
    return MAGIC + bytes([VERSION, OP_BURN]) + token_id + struct.pack("<Q", amount)


def parse_payload(data: bytes):
    """Returns dict describing the op, or None if not an ALP payload."""
    if not data or data[:3] != MAGIC or len(data) < 5:
        return None
    version, op = data[3], data[4]
    if version != VERSION:
        return None
    try:
        if op == OP_ISSUE:
            nlen = data[5]
            name = data[6:6 + nlen].decode("utf-8")
            decimals = data[6 + nlen]
            supply = struct.unpack_from("<Q", data, 7 + nlen)[0]
            return {"op": OP_ISSUE, "name": name, "decimals": decimals,
                    "supply": supply}
        if op in (OP_SEND, OP_MINT, OP_BURN):
            token_id = data[5:37]
            amount = struct.unpack_from("<Q", data, 37)[0]
            return {"op": op, "token_id": token_id, "amount": amount}
    except (IndexError, UnicodeDecodeError, struct.error):
        return None
    return None


def find_token_payload(tx):
    """Return parsed ALP payload from a tx's OP_RETURN output, else None."""
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


def first_non_opreturn_output(tx):
    for n, txo in enumerate(tx.vout):
        typ, _ = _script.solver(txo.script_pubkey)
        if typ != _script.TX_NULL_DATA:
            return n, txo
    return None, None


# ---------------------------------------------------------------------------
# Token registry + balances
# ---------------------------------------------------------------------------
@dataclass
class TokenInfo:
    token_id: bytes
    name: str
    decimals: int
    supply: int                 # total outstanding (minted - burned)
    issuer_script: bytes
    created_height: int

    def to_json(self, params):
        from .utils import hash_to_hex
        return {
            "token_id": hash_to_hex(self.token_id),
            "name": self.name,
            "decimals": self.decimals,
            "supply": self.supply,
            "display_supply": self.supply / (10 ** self.decimals),
            "issuer": _script.extract_destination(self.issuer_script, params),
            "created_height": self.created_height,
        }


class TokenDB:
    """Deterministic token-state indexer driven by block connect/disconnect."""

    def __init__(self):
        self.registry: dict[bytes, TokenInfo] = {}
        self.balances: dict[tuple, int] = {}       # (token_id, script) -> amt
        self.journal: dict[int, list] = {}         # height -> undo records
        self.needs_rebuild = False

    # -- balance helpers -------------------------------------------------------
    def balance(self, token_id: bytes, spk: bytes) -> int:
        return self.balances.get((token_id, spk), 0)

    def balances_for(self, spk: bytes) -> dict:
        return {tid: amt for (tid, s), amt in self.balances.items()
                if s == spk and amt}

    def holders(self, token_id: bytes) -> dict:
        return {s: amt for (tid, s), amt in self.balances.items()
                if tid == token_id and amt}

    # -- mutation ---------------------------------------------------------------
    def _credit(self, j, token_id, spk, amount):
        key = (token_id, spk)
        self.balances[key] = self.balances.get(key, 0) + amount
        j.append(("bal", token_id, spk, amount))

    def _debit(self, j, token_id, spk, amount):
        key = (token_id, spk)
        self.balances[key] = self.balances.get(key, 0) - amount
        j.append(("bal", token_id, spk, -amount))

    # -- block application -------------------------------------------------------
    def apply_block(self, block, height: int, lookup_script) -> None:
        """Scan a connected block for ALP ops. `lookup_script(prevout)` must
        return the script_pubkey of the referenced output (or None)."""
        journal = []
        for tx in block.txs:
            p = find_token_payload(tx)
            if p is None:
                continue
            _, recipient = first_non_opreturn_output(tx)
            sender = None
            if tx.vin and not tx.vin[0].is_coinbase():
                sender = lookup_script(tx.vin[0].prevout.key())
            self._apply_op(p, tx, sender,
                           recipient.script_pubkey if recipient else None,
                           height, journal)
        if journal:
            self.journal[height] = journal

    def _apply_op(self, p, tx, sender, recipient, height, j) -> None:
        op = p["op"]
        if op == OP_ISSUE:
            if (recipient is None or not p["name"]
                    or p["decimals"] > MAX_DECIMALS
                    or not 0 < p["supply"] <= MAX_TOKEN_SUPPLY):
                return  # invalid issuance
            token_id = tx.txid()
            if token_id in self.registry:
                return
            self.registry[token_id] = TokenInfo(
                token_id=token_id, name=p["name"], decimals=p["decimals"],
                supply=p["supply"], issuer_script=recipient,
                created_height=height)
            j.append(("reg", token_id))
            self._credit(j, token_id, recipient, p["supply"])
        elif op == OP_SEND:
            token_id = p["token_id"]
            if (token_id not in self.registry or sender is None
                    or recipient is None or p["amount"] <= 0):
                return
            if self.balance(token_id, sender) < p["amount"]:
                return  # insufficient balance
            self._debit(j, token_id, sender, p["amount"])
            self._credit(j, token_id, recipient, p["amount"])
        elif op == OP_MINT:
            token_id = p["token_id"]
            info = self.registry.get(token_id)
            if (info is None or sender is None or recipient is None
                    or sender != info.issuer_script or p["amount"] <= 0):
                return  # only the issuer may mint
            info.supply += p["amount"]
            j.append(("supply", token_id, p["amount"]))
            self._credit(j, token_id, recipient, p["amount"])
        elif op == OP_BURN:
            token_id = p["token_id"]
            info = self.registry.get(token_id)
            if (info is None or sender is None or p["amount"] <= 0):
                return
            if self.balance(token_id, sender) < p["amount"]:
                return
            self._debit(j, token_id, sender, p["amount"])
            info.supply -= p["amount"]
            j.append(("supply", token_id, -p["amount"]))

    # -- reorg handling ------------------------------------------------------------
    def unapply_block(self, height: int) -> None:
        journal = self.journal.pop(height, None)
        if journal is None:
            if height <= max(self.journal, default=-1):
                self.needs_rebuild = True
            return
        for rec in reversed(journal):
            if rec[0] == "bal":
                _, tid, spk, delta = rec
                key = (tid, spk)
                self.balances[key] = self.balances.get(key, 0) - delta
                if not self.balances[key]:
                    self.balances.pop(key, None)
            elif rec[0] == "reg":
                self.registry.pop(rec[1], None)
            elif rec[0] == "supply":
                info = self.registry.get(rec[1])
                if info:
                    info.supply -= rec[2]

    def rebuild(self, chain) -> None:
        """Rebuild state by replaying the active chain (after deep reorg)."""
        self.registry.clear()
        self.balances.clear()
        self.journal.clear()
        self.needs_rebuild = False
        for entry in chain.active[1:]:
            block = chain.get_block(entry.hash)
            if block:
                self.apply_block(block, entry.height,
                                 chain.utxo_script_lookup())

    # -- queries -------------------------------------------------------------------
    def list_tokens(self, params):
        return [t.to_json(params) for t in self.registry.values()]

    def token_info(self, token_id: bytes, params):
        info = self.registry.get(token_id)
        if info is None:
            return None
        d = info.to_json(params)
        d["holders"] = len(self.holders(token_id))
        return d

    def balance_json(self, token_id: bytes, params):
        out = []
        for spk, amt in self.holders(token_id).items():
            info = self.registry.get(token_id)
            dec = info.decimals if info else 0
            out.append({
                "address": _script.extract_destination(spk, params),
                "balance": amt,
                "display_balance": amt / (10 ** dec),
            })
        return out
