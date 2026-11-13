"""The mempool: validation and tracking of unconfirmed transactions.

Policy mirrors Bitcoin's mempool acceptance: inputs must be available (UTXO
or in-mempool parents), scripts must verify, the tx must be final for the
next block, and double-spends are handled with basic RBF (BIP125) rules.
"""

import threading
from dataclasses import dataclass

from . import constants, script
from .blockchain import Blockchain, ChainError, UTXO
from .transaction import Transaction
from .utils import median, now


class MempoolError(Exception):
    pass


@dataclass
class MempoolEntry:
    tx: Transaction
    fee: int
    time: int

    @property
    def fee_rate(self) -> float:
        return self.fee / max(1, self.tx.vsize())


class Mempool:
    def __init__(self, chain: Blockchain):
        self.chain = chain
        self.txs: dict[bytes, MempoolEntry] = {}          # txid -> entry
        self.spends: dict[tuple, bytes] = {}              # outpoint -> txid
        self.lock = threading.RLock()

    def __len__(self):
        return len(self.txs)

    def get(self, txid: bytes) -> MempoolEntry | None:
        return self.txs.get(txid)

    # -- coin lookup across UTXO + mempool -------------------------------------
    def _lookup_coin(self, key) -> UTXO | None:
        coin = self.chain.utxo.get(key)
        if coin is not None:
            return coin
        parent_txid, n = key
        parent = self.txs.get(parent_txid)
        if parent is not None and n < len(parent.tx.vout):
            return UTXO(parent.tx.vout[n], 0, False)
        return None

    def is_spent(self, key) -> bool:
        return key in self.spends

    # -- acceptance ---------------------------------------------------------------
    def accept(self, tx: Transaction) -> int:
        """Validate and admit a transaction. Returns the fee paid."""
        with self.lock:
            try:
                Blockchain.check_transaction(tx)
            except ChainError as e:
                raise MempoolError(str(e))
            if tx.is_coinbase():
                raise MempoolError("coinbase not allowed in mempool")
            txid = tx.txid()
            if txid in self.txs:
                raise MempoolError("transaction already in mempool")

            next_height = self.chain.height + 1
            block_time = median(
                [e.header.timestamp for e in
                 self.chain.active[-constants.MEDIAN_TIME_SPAN:]])
            if not tx.is_final(next_height, max(block_time, now())):
                raise MempoolError("transaction is not final")

            coins = {}
            in_sum = 0
            conflicts = set()
            for txin in tx.vin:
                key = txin.prevout.key()
                coin = self._lookup_coin(key)
                if coin is None:
                    raise MempoolError("missing input (orphan)")
                if coin.is_coinbase and (
                        next_height - coin.height
                        < self.chain.params.coinbase_maturity):
                    raise MempoolError("immature coinbase")
                if key in self.spends:
                    conflicts.add(self.spends[key])
                in_sum += coin.txout.value
                if in_sum > constants.MAX_MONEY:
                    raise MempoolError("input sum too large")
                coins[key] = coin

            if conflicts:
                old_fee = self._check_rbf(tx, conflicts)

            # sequence locks (BIP68)
            prev_mtp = self.chain.tip.median_time_past()
            if not Blockchain._sequence_locks_ok(tx, coins, next_height,
                                                 prev_mtp):
                raise MempoolError("sequence locks not satisfied")

            # script verification (BIP341 needs every input's prevout)
            flags = script.STANDARD_SCRIPT_FLAGS
            prevouts = {
                "amounts": [coins[t.prevout.key()].txout.value
                            for t in tx.vin],
                "spks": [coins[t.prevout.key()].txout.script_pubkey
                         for t in tx.vin],
            }
            for n_in, txin in enumerate(tx.vin):
                coin = coins[txin.prevout.key()]
                try:
                    script.verify_script(
                        txin.script_sig, coin.txout.script_pubkey, tx,
                        n_in, coin.txout.value, flags,
                        block_height=next_height, block_time=prev_mtp,
                        all_prevouts=prevouts)
                except script.ScriptError as e:
                    raise MempoolError(
                        f"script failed: input {n_in} "
                        f"(spk {coin.txout.script_pubkey.hex()[:20]}…): {e}")

            out_sum = tx.total_output_value()
            if out_sum > in_sum:
                raise MempoolError("outputs exceed inputs")
            fee = in_sum - out_sum
            if fee > constants.MAX_MONEY:
                raise MempoolError("absurd fee")
            if conflicts and fee <= old_fee:
                raise MempoolError(
                    "replacement fee must exceed conflicting tx fee")

            # package limits (Bitcoin: <=25 ancestors/descendants, <=101k WU)
            anc = self._ancestors(tx)
            if len(anc) >= 25:
                raise MempoolError(
                    f"too many unconfirmed ancestors ({len(anc)})")
            if sum(self.txs[t].tx.weight() for t in anc) \
                    + tx.weight() > 101_000:
                raise MempoolError("ancestor package too large")
            for dep in {t.prevout.txid for t in tx.vin} & set(self.txs):
                if len(self._descendants_of(dep)) >= 25:
                    raise MempoolError(
                        "parent has too many unconfirmed descendants")

            # replace conflicts (RBF)
            for old_txid in conflicts:
                self._remove(old_txid)

            self.txs[txid] = MempoolEntry(tx, fee, now())
            for txin in tx.vin:
                self.spends[txin.prevout.key()] = txid
            return fee

    def _check_rbf(self, new_tx: Transaction, conflicts: set) -> int:
        """Basic BIP125: conflicts must signal RBF. Returns their total fee."""
        old_fee = 0
        for txid in conflicts:
            entry = self.txs.get(txid)
            if entry is None:
                raise MempoolError("conflict with unknown mempool tx")
            if not any(i.signals_rbf() for i in entry.tx.vin):
                raise MempoolError("conflicting tx does not signal RBF")
            old_fee += entry.fee
        return old_fee

    def _ancestors(self, tx) -> set:
        out = set()
        stack = [t.prevout.txid for t in tx.vin]
        while stack:
            tid = stack.pop()
            if tid in out or tid not in self.txs:
                continue
            out.add(tid)
            stack += [i.prevout.txid for i in self.txs[tid].tx.vin]
        return out

    def _descendants_of(self, txid) -> set:
        out = set()
        changed = True
        while changed:
            changed = False
            for t, e in self.txs.items():
                if t in out or t == txid:
                    continue
                if any(i.prevout.txid in out | {txid}
                       for i in e.tx.vin):
                    out.add(t)
                    changed = True
        return out

    def ancestor_feerate(self, txid) -> float:
        """CPFP package rate: fee/vsize of tx + all mempool ancestors."""
        anc = self._ancestors(self.txs[txid].tx) | {txid}
        fee = sum(self.txs[t].fee for t in anc)
        vb = sum(self.txs[t].tx.vsize() for t in anc)
        return fee / max(1, vb)

    def estimate_fee(self, conf_target: int = 6) -> float:
        """estimatesmartfee-style: the Nth-highest package feerate."""
        if not self.txs:
            return -1.0
        rates = sorted((self.ancestor_feerate(t) for t in self.txs),
                       reverse=True)
        return rates[min(len(rates) - 1, max(0, conf_target - 1))]

    def _remove(self, txid: bytes) -> None:
        entry = self.txs.pop(txid, None)
        if entry is None:
            return
        for txin in entry.tx.vin:
            self.spends.pop(txin.prevout.key(), None)
        # drop descendants that spent this tx's outputs
        orphans = [t for t, e in self.txs.items()
                   if any(i.prevout.txid == txid for i in e.tx.vin)]
        for t in orphans:
            self._remove(t)

    # -- block production ---------------------------------------------------------
    def remove_for_block(self, block) -> None:
        """Drop txs confirmed in the block and any conflicts."""
        with self.lock:
            confirmed = {tx.txid() for tx in block.txs}
            conflicts = []
            for tx in block.txs:
                if tx.is_coinbase():
                    continue
                for txin in tx.vin:
                    other = self.spends.get(txin.prevout.key())
                    if other is not None and other not in confirmed:
                        conflicts.append(other)
            for txid in confirmed | set(conflicts):
                self._remove(txid)
            # also expire txs whose inputs just got spent by the block
            stale = [t for t, e in self.txs.items()
                     if any(self.chain.utxo.get(i.prevout.key()) is None
                            and i.prevout.txid not in self.txs
                            for i in e.tx.vin)]
            for t in stale:
                self._remove(t)

    def ordered_by_fee(self):
        return sorted(self.txs.values(),
                      key=lambda e: e.fee_rate, reverse=True)
