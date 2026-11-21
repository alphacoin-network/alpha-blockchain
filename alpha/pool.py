"""Alpha mining pool — proportional share accounting + payouts.

Solo getwork/submitwork pays the full block reward to whoever finds the
block. Pool mode instead pays the coinbase to a pool payout address and
credits each miner a pro-rata share of every pool-mined block, based on
the verified "shares" (hashes meeting an easier pool target) they submitted
for that round.

State lives in <datadir>/pool_state.json:

    {
      "payout": "alpha1...",          # coinbase destination (operator wallet)
      "round_shares": {"alpha1..": n},# shares since last pool block
      "credits": {"alpha1..": [{"sats": int, "vest": int}]},
      "paid_total": int
    }

Credits vest at find_height + COINBASE_MATURITY (the reward itself is a
coinbase output, so it cannot be spent before maturity — same rule as
Bitcoin). A maintainer thread pays out matured credits automatically.
"""

import json
import os

from . import constants
from .utils import hash_to_hex

# Pool share target = block target * POOL_SHARE_MULT  (easier => more shares)
POOL_SHARE_MULT = 200
# Don't let the share target get trivially easy on low-difficulty chains
_POOL_TARGET_CAP = 1 << 255


class Pool:
    def __init__(self, node, data_dir: str | None = None):
        self.node = node
        self.path = (os.path.join(data_dir, "pool_state.json")
                     if data_dir else None)
        self.payout = None
        self.round_shares: dict = {}
        self.credits: dict = {}          # addr -> [{"sats","vest"}]
        self.paid_total = 0
        self._load()

    # -- persistence ---------------------------------------------------------
    def _load(self):
        if not self.path or not os.path.exists(self.path):
            return
        try:
            d = json.load(open(self.path))
            self.payout = d.get("payout")
            self.round_shares = d.get("round_shares", {})
            self.credits = d.get("credits", {})
            self.paid_total = d.get("paid_total", 0)
        except Exception:
            pass

    def save(self):
        if not self.path:
            return
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"payout": self.payout,
                           "round_shares": self.round_shares,
                           "credits": self.credits,
                           "paid_total": self.paid_total}, f)
            os.replace(tmp, self.path)
        except Exception:
            pass

    # -- payout address --------------------------------------------------------
    def payout_address(self) -> str:
        """The address pool coinbase rewards pay to. Lazily created from the
        node wallet on first use; operator can override via set_payout."""
        if self.payout:
            return self.payout
        addr = self.node.wallet.new_address("bech32")
        self.payout = addr
        self.save()
        return addr

    def set_payout(self, address: str):
        self.payout = address
        self.save()

    # -- shares ---------------------------------------------------------------
    def add_share(self, address: str):
        self.round_shares[address] = self.round_shares.get(address, 0) + 1
        self.save()

    def pool_target(self, bits: int) -> int:
        """Integer share target for a block template with these bits."""
        from .blockchain import compact_to_target
        return min(compact_to_target(bits) * POOL_SHARE_MULT,
                   _POOL_TARGET_CAP)

    # -- reward distribution ---------------------------------------------------
    def on_block(self, height: int, reward_sats: int):
        """A pool-mined block confirmed: split reward_sats pro-rata over the
        shares accumulated this round, then reset the round."""
        shares = self.round_shares
        self.round_shares = {}
        self.save()
        total = sum(shares.values())
        if total <= 0 or reward_sats <= 0:
            return {}
        vest = height + constants.COINBASE_MATURITY
        payout = {}
        remaining = reward_sats
        # largest-remainder style: floor each, give dust remainder to the
        # biggest shareholder so the total always equals reward_sats
        items = sorted(shares.items(), key=lambda kv: -kv[1])
        acc = 0
        for i, (addr, n) in enumerate(items):
            if i == len(items) - 1:
                sats = remaining
            else:
                sats = reward_sats * n // total
                remaining -= sats
            if sats <= 0:
                continue
            self.credits.setdefault(addr, []).append(
                {"sats": sats, "vest": vest})
            payout[addr] = sats
            acc += sats
        self.save()
        return payout

    # -- payouts ---------------------------------------------------------------
    def due_payouts(self, chain) -> list:
        """Send matured credits. Returns list of txid_hex sent."""
        height = chain.height
        sent = []
        for addr, entries in list(self.credits.items()):
            keep = []
            for e in entries:
                if e["vest"] > height:
                    keep.append(e)
                    continue
                if e["sats"] < 546:    # dust — nothing to send
                    self.paid_total += e["sats"]
                    continue
                try:
                    tx = self.node.wallet.create_transaction(
                        chain, [(addr, e["sats"])], fee_rate=1)
                    self.node.submit_tx(tx)
                    self.paid_total += e["sats"]
                    sent.append(tx.txid_hex())
                except Exception:
                    keep.append(e)      # insufficient funds etc — retry later
            self.credits[addr] = keep
            if not keep:
                del self.credits[addr]
        if sent:
            self.save()
        return sent

    def prune(self):
        """Drop empty credit entries."""
        self.credits = {a: v for a, v in self.credits.items() if v}

    # -- info ------------------------------------------------------------------
    def info(self, address: str | None = None) -> dict:
        h = self.node.chain.height
        entries = ([(address, self.credits.get(address, []))]
                   if address else list(self.credits.items()))
        pending = vested = 0
        for _, ents in entries:
            for e in ents:
                pending += e["sats"]
                if e["vest"] <= h:
                    vested += e["sats"]
        return {
            "payout_address": self.payout,
            "round_shares_total": sum(self.round_shares.values()),
            "miners_in_round": len(self.round_shares),
            "pending_sats": pending,
            "pending_alpha": pending / 1e8,
            "vested_sats": vested,
            "vested_alpha": vested / 1e8,
            "paid_total_sats": self.paid_total,
            "share_mult": POOL_SHARE_MULT,
        }
