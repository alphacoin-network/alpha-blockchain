"""AUSD — ALPHA-backed stablecoin engine.

Model: 1 AUSD = 10 ALPHA (fixed). Mint = user deposits ALPHA to the reserve
address with an OP_RETURN memo "AUSD-MINT:<base_units>"; the sync engine mints
AUSD to the sender. AUSD is a one-way conversion — it cannot be redeemed back
into ALPHA — but it is freely transferable P2P like ALPHA.

All reserve/issuer keys live in the node wallet — operator-run, like a
custodial stablecoin issuer (Tether-style), but fully on-chain auditable.
"""

import json
import os
import struct

from . import script, tokens as _tokens
from .wallet import Wallet
from .transaction import Transaction
from .utils import hash_to_hex, hex_to_hash

MINT_PREFIX = b"AUSD-MINT:"
FEED_NAME = "ALPHAUSD"
DEFAULT_PRICE = 0.001          # USD per ALPHA (operator-set reference)

# Reserve addresses that were live before reserves were aligned to the
# canonical token issuer. Deposits paid to any of these still mint AUSD.
KNOWN_LEGACY_RESERVES = {
    "alpha1qtex39sa94few5eupzwdg0sujap94sscan8jhj0",
}


class Ausd:
    def __init__(self, node):
        self.node = node
        self.token_id = None
        self._issuer = None
        # Dedicated AUSD reserve wallet — separate keys/file from the node
        # (referral) wallet so swap funds are isolated.
        wpath = (os.path.join(node.data_dir, "ausd_wallet.json")
                 if node.data_dir else None)
        self.wallet = Wallet(node.params, wpath)
        if self.wallet.hd_seed is None and not self.wallet.keys                 and not self.wallet.encrypted:
            self.wallet.init_hd()
        self._state_path = os.path.join(
            node.data_dir, "ausd_state.json") if node.data_dir else None
        st = self._load()
        # reserve must be STABLE across restarts — persist in state.
        # (new_address() makes a fresh key each call → address would
        # change every restart and orphan the issuer/token.)
        if st.get("reserve"):
            self.reserve = st["reserve"]
        else:
            # reserve = first address of the dedicated wallet (issuer too)
            funded = self.wallet.list_unspent(node.chain, 1)
            if funded:
                self.reserve = script.extract_destination(
                    funded[0]["script"], node.params)
            else:
                self.reserve = self.wallet.new_address("bech32")
            st["reserve"] = self.reserve
        self.token_id = (hex_to_hash(st["token_id"])
                         if st.get("token_id") else None)
        self.last_height = st.get("last_height", 0)
        self.processed = set(st.get("processed", []))
        self._issue_txid = st.get("issue_txid")
        self._issue_height = st.get("issue_height", 0)
        self._legacy = set(st.get("legacy_reserves", []))
        # reserves that were advertised to users before the canonical
        # issuer-reserve migration — deposits to these still mint
        self._legacy.update(KNOWN_LEGACY_RESERVES)
        if self.reserve:
            self._legacy.discard(self.reserve)

    # -- persistence ---------------------------------------------------------
    def _load(self):
        try:
            with open(self._state_path) as f:
                return json.load(f)
        except Exception:
            return {}

    def _save(self):
        if not self._state_path:
            return
        with open(self._state_path, "w") as f:
            json.dump({"token_id": (hash_to_hex(self.token_id)
                                    if self.token_id else None),
                       "reserve": self.reserve,
                       "last_height": self.last_height,
                       "processed": list(self.processed)[-5000:],
                       "issue_txid": self._issue_txid,
                       "issue_height": self._issue_height,
                       "legacy_reserves": list(self._legacy)}, f)

    # -- price -----------------------------------------------------------------
    def alpha_usd_price(self) -> float:
        """Latest ALPHA/USD from the oracle feed; fallback DEFAULT_PRICE."""
        try:
            for f in self.node.ai.list_feeds(self.node.params):
                if f.get("name") == FEED_NAME:
                    latest = f.get("latest")
                    if latest and latest.get("value") is not None:
                        return float(latest["value"])
        except Exception:
            pass
        return DEFAULT_PRICE

    def _feed_op(self, payload: bytes):
        tx = self.wallet.create_token_op_tx(
            self.node.chain, payload, self.reserve, self.reserve)
        self.node.submit_tx(tx)
        return tx

    def set_price(self, usd_per_alpha: float):
        """Publish a new ALPHA/USD price to the oracle feed (operator)."""
        fid = None
        for f in self.node.ai.list_feeds(self.node.params):
            if f.get("name") == FEED_NAME:
                fid = hex_to_hash(f["feed_id"])
                break
        if fid is None:
            from . import ai as _ai
            tx = self._feed_op(_ai.feed_reg(FEED_NAME,
                                            "ALPHA/USD reference price"))
            fid = hex_to_hash(tx.txid_hex())
        from . import ai as _ai
        self._feed_op(_ai.feed_pub(fid, str(usd_per_alpha), 0))
        return {"price": usd_per_alpha, "feed": FEED_NAME}

    # -- conversions -------------------------------------------------------------
    ALPHA_PER_AUSD = 10            # fixed rate: 1 AUSD = 10 ALPHA

    def alpha_for_ausd(self, ausd_base: int) -> int:
        """ALPHA sats needed to mint `ausd_base` AUSD base units.

        Fixed rate: 1 AUSD (100 base units) = 10 ALPHA.
        Per base unit: 10 ALPHA / 100 = 0.1 ALPHA = 1e7 sats.
        """
        return int(ausd_base) * 10_000_000

    # -- OP_RETURN memo scan -----------------------------------------------------
    @staticmethod
    def _memo(tx) -> bytes | None:
        for txo in tx.vout:
            typ, _ = script.solver(txo.script_pubkey)
            if typ != script.TX_NULL_DATA:
                continue
            ops = script.script_ops(txo.script_pubkey)
            if len(ops) == 2 and ops[1].data is not None:
                d = ops[1].data
                if d.startswith(MINT_PREFIX):
                    return d[len(MINT_PREFIX):]
        return None

    def _sender_addr(self, tx, block=None) -> str | None:
        # 1) resolve the first input's prevout — works for real-time sync
        #    (coin still unspent) and for prevouts created in `block`.
        try:
            spk = self.node.chain.utxo_script_lookup(block)(
                tx.vin[0].prevout.key())
            if spk:
                return script.extract_destination(spk, self.node.params)
        except Exception:
            pass
        # 2) catch-up fallback: the sender's change output is the largest
        #    payment that is not to a reserve address or OP_RETURN.
        ok_addrs = {self.reserve} | self._legacy
        best = None
        for o in tx.vout:
            typ, _ = script.solver(o.script_pubkey)
            if typ == script.TX_NULL_DATA:
                continue
            a = script.extract_destination(o.script_pubkey,
                                           self.node.params)
            if a is None or a in ok_addrs:
                continue
            if best is None or o.value > best[0]:
                best = (o.value, a)
        return best[1] if best else None

    def _resolve_token(self):
        """Pick the canonical AUSD token — newest token NAMED 'AUSD'.

        Any issuer is accepted for READ/info. Only the node whose reserve
        matches the token issuer can actually mint (it holds the keys).
        Deterministic across all nodes: (created_height, txid) ordering.
        """
        best = None
        for tid, info in self.node.tokens.registry.items():
            if getattr(info, "name", "") != "AUSD":
                continue
            key = (getattr(info, "created_height", 0), hash_to_hex(tid))
            issuer = script.extract_destination(
                getattr(info, "issuer_script", b""), self.node.params)                 if getattr(info, "issuer_script", None) else None
            if best is None or key > best[0]:
                best = (key, tid, issuer)
        if best is not None:
            self.token_id = best[1]
            issuer = best[2]
            # payments must go to the ISSUER address (mint keys live there);
            # old reserves remain valid for in-flight deposits
            if issuer and issuer != self.reserve:
                if self.reserve:
                    self._legacy.add(self.reserve)
                self.reserve = issuer
            self._issuer = issuer
            self._save()
            return self.token_id
        return None

    @property
    def can_mint(self) -> bool:
        """True only on the node that owns the reserve/issuer keys."""
        if self.token_id is None or self._issuer != self.reserve:
            return False
        try:
            return self.wallet._key_for_address(self.reserve) is not None
        except Exception:
            return False

    def _ensure_token(self):
        """Issue AUSD only if NO token named AUSD exists yet — prevents
        every node from spamming its own token onto the chain."""
        for info in self.node.tokens.registry.values():
            if getattr(info, "name", "") == "AUSD":
                return
        tip = self.node.chain.height
        if self._issue_txid and tip - self._issue_height < 20:
            return  # our issue tx may still confirm — wait
        supply = 10_000_000_000          # 100M AUSD issuer float (2 dp)
        payload = _tokens.encode_issue("AUSD", 2, supply)
        tx = self.wallet.create_token_op_tx(
            self.node.chain, payload, self.reserve, self.reserve)
        self.node.submit_tx(tx)
        self._issue_txid = tx.txid_hex()
        self._issue_height = tip
        self._save()

    # -- sync ---------------------------------------------------------------------
    def sync(self) -> dict:
        """Scan blocks since last_height for AUSD mint deposits."""
        if self.token_id is None:
            self._ensure_token()
        self._resolve_token()
        if self.token_id is None:
            return {"error": "no AUSD token issued"}
        if not self.can_mint:
            # this node doesn't hold issuer keys — the issuer node mints.
            # still advance last_height so we don't rescan the same range.
            tip0 = self.node.chain.height
            if tip0 > self.last_height:
                self.last_height = tip0
                self._save()
            return {"minted": 0, "height": self.last_height,
                    "issuer_node": False}
        tip = self.node.chain.height
        minted = 0
        reserve_spk = script.script_for_address(self.reserve, self.node.params)
        for h in range(self.last_height + 1, tip + 1):
            e = self.node.chain.get_block_index(h)
            if e is None:
                continue
            b = self.node.chain.get_block(e.hash)
            if b is None:
                continue
            for tx in b.txs:
                if tx.is_coinbase() or tx.txid_hex() in self.processed:
                    continue
                tid = tx.txid_hex()
                memo = self._memo(tx)
                if memo is not None:
                    try:
                        amt = int(memo)
                    except ValueError:
                        amt = 0
                    # mint only if tx actually paid >= required ALPHA to reserve
                    ok_addrs = {self.reserve} | self._legacy
                    paid = sum(
                        o.value for o in tx.vout
                        if script.extract_destination(o.script_pubkey,
                                                     self.node.params)
                        in ok_addrs)
                    sender = self._sender_addr(tx, b)
                    if (amt > 0 and sender
                            and paid >= self.alpha_for_ausd(amt)):
                        # mint to issuer then send to user
                        self.node.submit_tx(self.wallet.create_token_op_tx(
                            self.node.chain,
                            _tokens.encode_mint(self.token_id, amt),
                            self.reserve, self.reserve))
                        self.node.submit_tx(self.wallet.create_token_op_tx(
                            self.node.chain,
                            _tokens.encode_send(self.token_id, amt),
                            self.reserve, sender))
                        minted += 1
                self.processed.add(tid)
            self.last_height = h
            if len(self.processed) > 5000:
                self.processed = set(list(self.processed)[-5000:])
        self._save()
        return {"minted": minted, "height": self.last_height}

    def info(self):
        self._resolve_token()
        bal = {}
        try:
            bal = self.node.tokens.balance_json(self.token_id,
                                                self.node.params)
        except Exception:
            pass
        return {
            "token_id": hash_to_hex(self.token_id) if self.token_id else None,
            "reserve": self.reserve,
            "rate": "fixed",
            "alpha_per_ausd": float(self.ALPHA_PER_AUSD),
            "ausd_per_alpha": 1.0 / self.ALPHA_PER_AUSD,
            "alpha_usd_price": self.alpha_usd_price(),
        }
