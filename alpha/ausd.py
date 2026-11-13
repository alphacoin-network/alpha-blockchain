"""AUSD — ALPHA-backed stablecoin engine.

Model: 1 AUSD is redeemable for $1.00 worth of ALPHA at the operator-published
ALPHA/USD oracle price. Mint = user deposits ALPHA to the reserve address with
an OP_RETURN memo "AUSD-MINT:<base_units>"; the sync engine mints AUSD to the
sender. Redeem = user sends AUSD to the reserve; sync burns it and pays ALPHA.

All reserve/issuer keys live in the node wallet — operator-run, like a
custodial stablecoin issuer (Tether-style), but fully on-chain auditable.
"""

import json
import os
import struct

from . import script, tokens as _tokens
from .transaction import Transaction
from .utils import hash_to_hex, hex_to_hash

MINT_PREFIX = b"AUSD-MINT:"
FEED_NAME = "ALPHAUSD"
DEFAULT_PRICE = 0.001          # USD per ALPHA (operator-set reference)


class Ausd:
    def __init__(self, node):
        self.node = node
        self.token_id = None
        # reserve = node's first funded wallet address (issuer too)
        for u in node.wallet.list_unspent(node.chain, 1):
            self.reserve = script.extract_destination(
                u["script"], node.params)
            break
        else:
            self.reserve = node.wallet.new_address("bech32")
        self._state_path = os.path.join(
            node.data_dir, "ausd_state.json") if node.data_dir else None
        st = self._load()
        self.token_id = (hex_to_hash(st["token_id"])
                         if st.get("token_id") else None)
        self.last_height = st.get("last_height", 0)
        self.processed = set(st.get("processed", []))

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
                       "processed": list(self.processed)[-5000:]}, f)

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
        tx = self.node.wallet.create_token_op_tx(
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
    def alpha_for_ausd(self, ausd_base: int) -> int:
        """ALPHA sats needed to mint `ausd_base` AUSD base units."""
        price = self.alpha_usd_price()          # USD per ALPHA
        usd = ausd_base / 100.0                 # AUSD decimals=2 → cents
        alpha = usd / price                     # ALPHA coins
        return int(alpha * 1e8)

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
        """Find the AUSD token in the registry by name (lazy)."""
        if self.token_id is not None:
            return self.token_id
        for tid, info in self.node.tokens.registry.items():
            if getattr(info, "name", "") == "AUSD":
                self.token_id = tid
                self._save()
                return tid
        return None

    # -- sync ---------------------------------------------------------------------
    def sync(self) -> dict:
        """Scan blocks since last_height for mint deposits & AUSD redeems."""
        self._resolve_token()
        if self.token_id is None:
            return {"error": "no AUSD token issued"}
        tip = self.node.chain.height
        minted = redeemed = 0
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
                    # mint only if tx actually paid ALPHA to reserve
                    pays = any(
                        script.extract_destination(o.script_pubkey,
                                                   self.node.params)
                        == self.reserve for o in tx.vout)
                    sender = self._sender_addr(tx)
                    if amt > 0 and pays and sender:
                        # mint to issuer then send to user
                        self.node.submit_tx(self.node.wallet.create_token_op_tx(
                            self.node.chain,
                            _tokens.encode_mint(self.token_id, amt),
                            self.reserve, self.reserve))
                        self.node.submit_tx(self.node.wallet.create_token_op_tx(
                            self.node.chain,
                            _tokens.encode_send(self.token_id, amt),
                            self.reserve, sender))
                        minted += 1
                # redeem: AUSD sent to reserve → burn + pay ALPHA
                p = _tokens.find_token_payload(tx)
                if (p and p.get("op") == _tokens.OP_SEND
                        and p.get("token_id") == self.token_id
                        and p.get("amount", 0) > 0):
                    sender = self._sender_addr(tx)
                    # recipient = first non-opreturn output
                    _, rtxo = _tokens.first_non_opreturn_output(tx)
                    if (sender and rtxo is not None
                            and script.extract_destination(
                                rtxo.script_pubkey, self.node.params)
                            == self.reserve):
                        amt = p["amount"]
                        alpha_out = self.alpha_for_ausd(amt)
                        # burn reserve-held AUSD
                        self.node.submit_tx(
                            self.node.wallet.create_token_op_tx(
                                self.node.chain,
                                _tokens.encode_burn(self.token_id, amt),
                                self.reserve, self.reserve))
                        # pay ALPHA to redeemer (alpha_out is sats int)
                        try:
                            self.node.wallet.send_to_address(
                                self.node.chain, self.node.mempool,
                                sender, alpha_out, 1)
                        except Exception:
                            pass
                        redeemed += 1
                self.processed.add(tid)
            self.last_height = h
            if len(self.processed) > 5000:
                self.processed = set(list(self.processed)[-5000:])
        self._save()
        return {"minted": minted, "redeemed": redeemed,
                "height": self.last_height}

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
