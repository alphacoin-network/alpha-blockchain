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


class Ausd:
    def __init__(self, node):
        self.node = node
        self.token_id = None
        # Dedicated AUSD reserve wallet — separate keys/file from the node
        # (referral) wallet so swap funds are isolated.
        wpath = (os.path.join(node.data_dir, "ausd_wallet.json")
                 if node.data_dir else None)
        self.wallet = Wallet(node.params, wpath)
        if self.wallet.hd_seed is None and not self.wallet.keys                 and not self.wallet.encrypted:
            self.wallet.init_hd()
        # reserve = first address of the dedicated wallet (issuer too)
        funded = self.wallet.list_unspent(node.chain, 1)
        if funded:
            self.reserve = script.extract_destination(
                funded[0]["script"], node.params)
        else:
            self.reserve = self.wallet.new_address("bech32")
        self._state_path = os.path.join(
            node.data_dir, "ausd_state.json") if node.data_dir else None
        st = self._load()
        self.token_id = (hex_to_hash(st["token_id"])
                         if st.get("token_id") else None)
        self.last_height = st.get("last_height", 0)
        self.processed = set(st.get("processed", []))
        self._issue_txid = st.get("issue_txid")
        self._issue_height = st.get("issue_height", 0)

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
                       "last_height": self.last_height,
                       "processed": list(self.processed)[-5000:],
                       "issue_txid": self._issue_txid,
                       "issue_height": self._issue_height}, f)

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

    def _sender_addr(self, tx) -> str | None:
        try:
            spk = self.node.chain.utxo_script_lookup()(tx.vin[0].prevout.key())
            return script.extract_destination(spk, self.node.params) \
                if spk else None
        except Exception:
            return None

    def _resolve_token(self):
        """Find the newest AUSD token issued by OUR reserve (deterministic)."""
        best = None
        for tid, info in self.node.tokens.registry.items():
            if getattr(info, "name", "") != "AUSD":
                continue
            issuer = getattr(info, "issuer", None)
            if issuer != self.reserve:
                continue
            key = (info.created_height, hash_to_hex(tid))
            if best is None or key > best[0]:
                best = (key, tid)
        if best is not None:
            self.token_id = best[1]
            self._save()
            return self.token_id
        return None

    def _ensure_token(self):
        """Issue a fresh AUSD token under the dedicated reserve if none exists."""
        if self._resolve_token() is not None:
            return
        # only one node should issue: require registry to have no AUSD at all
        # OR no AUSD owned by us yet and we are the lowest datadir? — instead,
        # issue once and rely on _resolve_token picking the newest deterministically.
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
                    paid = sum(
                        o.value for o in tx.vout
                        if script.extract_destination(o.script_pubkey,
                                                     self.node.params)
                        == self.reserve)
                    sender = self._sender_addr(tx)
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
            "alpha_usd_price": self.alpha_usd_price(),
            "ausd_per_alpha": 1.0 / self.alpha_usd_price(),
        }
