"""The blockchain: block index, UTXO set, validation, difficulty retargeting,
reorganizations, and the genesis block.

Consensus rules implemented (same as Bitcoin):
  * subsidy: 50 coins halved every 210,000 blocks (main/test), 150 (regtest)
  * PoW: sha256d(header) <= target from nBits; retarget every 2016 blocks,
    clamped to [timespan/4, timespan*4]
  * timestamp > median time of previous 11 blocks, < now + 2h
  * coinbase: first tx only, scriptSig 2..100 bytes, BIP34 height push
  * coinbase outputs spendable after 100 confirmations
  * unique txids per block; inputs must exist and not be spent
  * input sum >= output sum (the difference is the miner's fee)
  * every input script must verify (incl. segwit rules + witness commitment)
  * block weight <= 4,000,000; sigops <= 20,000 (weighted)
  * most-work (chainwork) chain selection with reorgs
"""

import os
import struct
import threading
from dataclasses import dataclass

from . import constants, script, utils
from .block import (
    Block, BlockHeader, get_witness_reserved_value, witness_commitment,
)
from .transaction import OutPoint, Transaction, TxIn, TxOut
from .utils import (
    BytesReader, compact_to_target, encode_script_num, hash_to_hex,
    median, now,
)


class ChainError(Exception):
    """Raised when a block or transaction violates consensus rules."""


# ---------------------------------------------------------------------------
# UTXO / block index records
# ---------------------------------------------------------------------------
@dataclass
class UTXO:
    txout: TxOut
    height: int
    is_coinbase: bool
    mtp: int = 0          # median time past of the creating block (for CSV)


@dataclass(eq=False)  # identity-based: avoids deep recursive __eq__ via parent
class BlockIndexEntry:
    header: BlockHeader
    height: int
    hash: bytes                 # wire order
    chainwork: int
    parent: "BlockIndexEntry | None"

    def median_time_past(self) -> int:
        """Median timestamp of this entry and up to 10 ancestors."""
        times = []
        e = self
        for _ in range(constants.MEDIAN_TIME_SPAN):
            if e is None:
                break
            times.append(e.header.timestamp)
            e = e.parent
        return median(times) if times else 0


# ---------------------------------------------------------------------------
# Genesis block
# ---------------------------------------------------------------------------
# Genesis pays to the uncompressed pubkey of private key 1 (point G). Like
# Bitcoin's genesis coinbase, this output is NOT spendable (kept out of the
# UTXO set), faithfully reproducing the original quirk.
GENESIS_PUBKEY = bytes.fromhex(
    "04"
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")


def make_genesis_block(params) -> Block:
    """Build the genesis block in the exact layout of Bitcoin's genesis."""
    msg = params.genesis_message
    script_sig = (b"\x04" + params.pow_limit_bits.to_bytes(4, "little")
                  + b"\x01\x04" + script.push_data(msg))
    coinbase = Transaction(
        version=1,
        vin=[TxIn(
            prevout=OutPoint(constants.COINBASE_PREV_HASH,
                             constants.COINBASE_PREV_VOUT),
            script_sig=script_sig,
            sequence=constants.SEQUENCE_FINAL)],
        vout=[TxOut(params.initial_subsidy, script.script_p2pk(GENESIS_PUBKEY))],
        locktime=0)
    header = BlockHeader(
        version=1,
        prev_hash=b"\x00" * 32,
        merkle=coinbase.txid(),
        timestamp=params.genesis_timestamp,
        bits=params.pow_limit_bits,
        nonce=0,
    )
    return Block(header, [coinbase])


# ---------------------------------------------------------------------------
# Blockchain
# ---------------------------------------------------------------------------
class Blockchain:
    def __init__(self, params=None, data_dir: str | None = None,
                 autoload: bool = True):
        self.params = params or constants.MAINNET
        self.data_dir = data_dir
        self.lock = threading.RLock()

        self.index: dict[bytes, BlockIndexEntry] = {}
        self.blocks: dict[bytes, Block] = {}
        self.active: list[BlockIndexEntry] = []        # active chain by height
        self.utxo: dict[tuple, UTXO] = {}
        self.undo: dict[int, dict] = {}                # height -> spent utxos
        self.orphans: dict[bytes, list] = {}           # prev_hash -> [Block]
        self.known_orphan: set = set()

        # optional index hooks (e.g. the token layer):
        #   on_block_connected(block, entry, lookup_script)
        #   on_block_disconnected(entry)
        self.on_block_connected = None
        self.on_block_disconnected = None

        genesis = make_genesis_block(self.params)
        self._init_chain(genesis)
        if data_dir and autoload:
            self._load()

    def load(self) -> None:
        """(Re)load the stored chain. Call after registering index hooks."""
        if self.data_dir:
            self._load()

    # -- construction --------------------------------------------------------
    def _init_chain(self, genesis: Block) -> None:
        h = genesis.hash()
        entry = BlockIndexEntry(
            header=genesis.header, height=0, hash=h,
            chainwork=utils.work_from_bits(genesis.header.bits), parent=None)
        self.index[h] = entry
        self.blocks[h] = genesis
        self.active = [entry]
        # The genesis coinbase output is intentionally not added to the UTXO
        # set -- same as Bitcoin.

    @property
    def tip(self) -> BlockIndexEntry:
        return self.active[-1]

    @property
    def height(self) -> int:
        return self.tip.height

    def best_block_hash(self) -> bytes:
        return self.tip.hash

    # -- persistence -----------------------------------------------------------
    def _blocks_path(self) -> str:
        return os.path.join(self.data_dir, "blocks.dat")

    def _store_block(self, block: Block) -> None:
        if not self.data_dir:
            return
        os.makedirs(self.data_dir, exist_ok=True)
        with open(self._blocks_path(), "ab") as f:
            payload = block.serialize()
            f.write(struct.pack("<I", len(payload)) + payload)

    def _load(self) -> None:
        path = self._blocks_path()
        if not os.path.exists(path):
            return
        with open(path, "rb") as f:
            data = f.read()
        r = BytesReader(data)
        while not r.eof():
            try:
                size = r.read_u32()
                block = Block.deserialize(r.read(size))
            except Exception:
                break  # corrupt tail (e.g. crashed mid-write) — stop loading
            if block.hash() == self.active[0].hash:
                continue
            try:
                self.add_block(block, store=False)
            except ChainError:
                continue  # skip known side-chain / invalid data on load

    # -- money supply -----------------------------------------------------------
    def subsidy(self, height: int) -> int:
        halvings = height // self.params.halving_interval
        if halvings >= constants.MAX_HALVINGS:
            return 0
        return self.params.initial_subsidy >> halvings

    def total_supply(self) -> int:
        return sum(utxo.txout.value for utxo in self.utxo.values())

    # -- difficulty ---------------------------------------------------------------
    def next_work_required(self, prev: BlockIndexEntry) -> int:
        """Bitcoin's GetNextWorkRequired retarget rule."""
        height = prev.height + 1
        interval = self.params.pow_interval
        if height % interval != 0:
            return prev.header.bits

        first = prev
        for _ in range(interval - 1):
            first = first.parent
            if first is None:
                return self.params.pow_limit_bits

        target_timespan = self.params.pow_target_timespan
        actual = prev.header.timestamp - first.header.timestamp
        actual = max(target_timespan // 4, min(actual, target_timespan * 4))

        new_target = compact_to_target(prev.header.bits) * actual // target_timespan
        limit = compact_to_target(self.params.pow_limit_bits)
        if new_target > limit:
            new_target = limit
        return utils.target_to_compact(new_target)

    def get_block_index(self, height: int) -> BlockIndexEntry | None:
        if 0 <= height < len(self.active):
            return self.active[height]
        return None

    def get_block(self, h: bytes) -> Block | None:
        return self.blocks.get(h)

    def prune(self, keep_blocks: int = 288) -> int:
        """Bitcoin --prune: drop old block bodies, keep headers + UTXO set.

        Keeps the last `keep_blocks` blocks on the active chain. Returns the
        number of bodies pruned.
        """
        cutoff = self.height - keep_blocks
        pruned = 0
        for e in self.active:
            if e.height >= cutoff:
                break
            if self.blocks.pop(e.hash, None) is not None:
                pruned += 1
        return pruned

    def is_pruned(self, h: bytes) -> bool:
        """True if `h` is a known block whose body has been pruned."""
        return h in self.index and h not in self.blocks

    # ------------------------------------------------------------------
    # assumeutxo (BIP-proposed fast-sync): dump/load a UTXO snapshot
    # ------------------------------------------------------------------
    def dump_utxo_snapshot(self) -> bytes:
        """Serialize the whole UTXO set + tip hash (like dumptxoutset)."""
        from .utils import ser_compact_size
        out = self.tip.hash + ser_compact_size(len(self.utxo))
        for (txid, n), coin in self.utxo.items():
            out += (txid + struct.pack("<I", n)
                    + coin.txout.serialize()
                    + struct.pack("<i", coin.height)
                    + bytes([1 if coin.is_coinbase else 0])
                    + struct.pack("<I", coin.mtp))
        return out

    def load_utxo_snapshot(self, data: bytes):
        """Load a snapshot produced by dump_utxo_snapshot (assumeutxo).

        The snapshot's block hash is trusted as the new tip's ancestor;
        entries after it get connected normally. This mirrors Core's
        assumeutxo+snapshot-load flow.
        """
        from .utils import BytesReader
        r = BytesReader(data)
        base_hash = r.read(32)
        n = r.read_varint()
        from .transaction import TxOut
        utxo = {}
        for _ in range(n):
            txid = r.read(32)
            vout = r.read_u32()
            txo = TxOut.parse(r)
            h = r.read_i32()
            cb = bool(r.read(1)[0])
            mtp = r.read_u32()
            utxo[(txid, vout)] = UTXO(txo, h, cb, mtp)
        self.utxo = utxo
        return {"base_blockhash": hash_to_hex(base_hash),
                "coins_loaded": len(utxo)}

    # -- block acceptance ---------------------------------------------------------
    def add_block(self, block: Block, store: bool = True) -> BlockIndexEntry:
        """Validate a block and connect it (possibly triggering a reorg)."""
        with self.lock:
            h = block.hash()
            if h in self.index:
                raise ChainError("duplicate block")
            self._check_block(block)
            entry = self._accept_header(block)
            cp = (self.params.checkpoints or {}).get(entry.height)
            if cp is not None and hash_to_hex(h) != cp:
                raise ChainError("block conflicts with checkpoint")
            self.blocks[h] = block
            if entry.chainwork > self.tip.chainwork:
                self._activate(entry)
            # try to attach orphans that were waiting on this block
            for child in self.orphans.pop(h, []):
                try:
                    self.add_block(child, store=store)
                except ChainError:
                    pass
            if (store and entry.height < len(self.active)
                    and self.active[entry.height] is entry):
                self._store_block(block)
            return entry

    def _check_block(self, block: Block) -> None:
        """CheckBlock: context-free validity."""
        if not block.txs:
            raise ChainError("block has no transactions")
        if block.weight() > constants.MAX_BLOCK_WEIGHT:
            raise ChainError("block too heavy")
        if not block.check_merkle():
            raise ChainError("bad merkle root")
        if not block.txs[0].is_coinbase():
            raise ChainError("first tx must be coinbase")
        if any(tx.is_coinbase() for tx in block.txs[1:]):
            raise ChainError("multiple coinbase transactions")
        seen = set()
        for tx in block.txs:
            self.check_transaction(tx)
            tid = tx.txid()
            if tid in seen:
                raise ChainError("duplicate txid in block")
            seen.add(tid)

    @staticmethod
    def check_transaction(tx: Transaction) -> None:
        """CheckTransaction: context-free tx validity (same as Bitcoin)."""
        if not tx.vin:
            raise ChainError("tx has no inputs")
        if not tx.vout:
            raise ChainError("tx has no outputs")
        if tx.weight() > constants.MAX_BLOCK_WEIGHT:
            raise ChainError("tx too large")
        total = 0
        for txo in tx.vout:
            if txo.value < 0:
                raise ChainError("negative output value")
            if txo.value > constants.MAX_MONEY:
                raise ChainError("output value too large")
            total += txo.value
            if total > constants.MAX_MONEY:
                raise ChainError("output sum too large")
        if tx.is_coinbase():
            if not (constants.COINBASE_SCRIPT_MIN <= len(tx.vin[0].script_sig)
                    <= constants.COINBASE_SCRIPT_MAX):
                raise ChainError("bad coinbase scriptSig size")
        else:
            for txin in tx.vin:
                if txin.prevout.is_null():
                    raise ChainError("null prevout in non-coinbase input")
            seen = set()
            for txin in tx.vin:
                if txin.prevout.key() in seen:
                    raise ChainError("duplicate input")
                seen.add(txin.prevout.key())

    def _accept_header(self, block: Block) -> BlockIndexEntry:
        """Contextual header checks + index insertion."""
        h = block.hash()
        prev_hash = block.header.prev_hash
        parent = self.index.get(prev_hash)
        if parent is None:
            self.orphans.setdefault(prev_hash, []).append(block)
            raise ChainError("orphan block (unknown parent)")

        height = parent.height + 1
        # PoW: skip check only for the hardcoded genesis (never reaches here)
        if not block.header.check_pow(self.params.pow_limit_bits):
            raise ChainError("insufficient proof of work")

        required_bits = self.next_work_required(parent)
        if block.header.bits != required_bits:
            raise ChainError("incorrect difficulty bits")

        if block.header.timestamp <= parent.median_time_past():
            raise ChainError("timestamp not greater than median time past")
        if block.header.timestamp > now() + constants.MAX_FUTURE_BLOCK_TIME:
            raise ChainError("timestamp too far in the future")

        # tx finality in block context (locktime vs this block's height/time)
        for tx in block.txs[1:]:
            if not tx.is_final(height, block.header.timestamp):
                raise ChainError("non-final transaction in block")

        # BIP34: coinbase must start with a push of the block height
        cb_script = block.txs[0].vin[0].script_sig
        expected_push = script.push_data(encode_script_num(height))
        if not cb_script.startswith(expected_push):
            raise ChainError("coinbase missing block height (BIP34)")

        chainwork = parent.chainwork + utils.work_from_bits(block.header.bits)
        entry = BlockIndexEntry(block.header, height, h, chainwork, parent)
        self.index[h] = entry
        return entry

    @staticmethod
    def _sequence_locks_ok(tx: Transaction, coins: dict, height: int,
                           prev_mtp: int) -> bool:
        """BIP68/BIP112 relative lock-time check for tx inputs."""
        if tx.version < 2:
            return True
        min_height = -1
        min_time = -1
        for key, coin in coins.items():
            seq = next(t.sequence for t in tx.vin if t.prevout.key() == key)
            if seq & constants.SEQUENCE_LOCKTIME_DISABLE_FLAG:
                continue
            masked = seq & constants.SEQUENCE_LOCKTIME_MASK
            if seq & constants.SEQUENCE_LOCKTIME_TYPE_FLAG:
                t = coin.mtp + (masked << constants.SEQUENCE_LOCKTIME_GRANULARITY)
                min_time = max(min_time, t)
            else:
                min_height = max(min_height, coin.height + masked)
        if min_height >= height:
            return False
        if min_time >= prev_mtp:
            return False
        return True

    # -- chain activation / reorgs -------------------------------------------------
    def _find_fork(self, entry: BlockIndexEntry) -> BlockIndexEntry:
        e = entry
        while e is not None and (e.height >= len(self.active)
                                 or self.active[e.height].hash != e.hash):
            e = e.parent
        return e

    def _activate(self, new_tip: BlockIndexEntry) -> None:
        fork = self._find_fork(new_tip)
        if fork is None:
            raise ChainError("cannot reorganize before genesis")
        cps = self.params.checkpoints or {}
        last_cp = max(cps) if cps else -1
        if fork.height < last_cp <= self.tip.height:
            raise ChainError("reorg would undo a checkpointed block")
        # collect blocks to connect (from fork's child to new_tip)
        to_connect = []
        e = new_tip
        while e is not fork:
            to_connect.append(e)
            e = e.parent
        to_connect.reverse()

        # disconnect back to the fork
        while self.tip is not fork:
            self._disconnect(self.tip)
        # connect the new branch
        for e in to_connect:
            self._connect(e)

    def _connect(self, entry: BlockIndexEntry) -> None:
        block = self.blocks[entry.hash]
        spent = self._connect_block(block, entry)
        self.undo[entry.height] = spent
        while len(self.active) > entry.height:
            self.active.pop()
        self.active.append(entry)

    def _disconnect(self, entry: BlockIndexEntry) -> None:
        block = self.blocks[entry.hash]
        self._disconnect_block(block, entry)
        self.active.pop()

    def _connect_block(self, block: Block, entry: BlockIndexEntry) -> dict:
        """Full consensus validation + UTXO update. Returns spent-outpoint map."""
        height = entry.height
        spent: dict = {}
        fees = 0
        total_sigops_weight = 0

        mtp = entry.median_time_past()
        flags = script.STANDARD_SCRIPT_FLAGS

        prev_mtp = entry.parent.median_time_past() if entry.parent else 0

        # -- per-transaction validation --------------------------------------
        for tx_i, tx in enumerate(block.txs):
            if tx.is_coinbase():
                continue

            tx_in_sum = 0
            view = {}
            # pass 1: resolve ALL input coins (BIP341 sighash needs every
            # prevout's amount + scriptPubKey before any script runs)
            for txin in tx.vin:
                key = txin.prevout.key()
                coin = self.utxo.get(key) or view.get(key)
                if coin is None:
                    # outputs created earlier in this same block are spendable
                    coin = self._utxo_from_block_txs(block, tx_i, key, height)
                if coin is None:
                    raise ChainError("input spent or missing")
                if coin.is_coinbase and (height - coin.height
                                         < self.params.coinbase_maturity):
                    raise ChainError("immature coinbase spend")
                if key in spent:
                    raise ChainError("double spend in block")
                tx_in_sum += coin.txout.value
                view[key] = coin
                if tx_in_sum > constants.MAX_MONEY:
                    raise ChainError("input sum too large")

            prevouts = {
                "amounts": [view[t.prevout.key()].txout.value for t in tx.vin],
                "spks": [view[t.prevout.key()].txout.script_pubkey
                         for t in tx.vin],
            }
            # pass 2: verify every input script + sigops
            for n_in, txin in enumerate(tx.vin):
                coin = view[txin.prevout.key()]
                try:
                    script.verify_script(
                        txin.script_sig, coin.txout.script_pubkey, tx,
                        n_in, coin.txout.value, flags,
                        block_height=height, block_time=mtp,
                        all_prevouts=prevouts)
                except script.ScriptError as e:
                    raise ChainError(f"script verification failed: {e}")

                # sigops: p2sh redeem + witness program (weighted per BIP141)
                total_sigops_weight += 4 * script.count_p2sh_sigops(
                    txin.script_sig, coin.txout.script_pubkey)
                total_sigops_weight += script.count_witness_sigops(
                    coin.txout.script_pubkey, txin.script_sig, txin.witness)

            if not self._sequence_locks_ok(tx, view, height, prev_mtp):
                raise ChainError("sequence locks not satisfied")

            if tx_in_sum < tx.total_output_value():
                raise ChainError("inputs less than outputs")
            fee = tx_in_sum - tx.total_output_value()
            if fee < 0 or fee > constants.MAX_MONEY:
                raise ChainError("bad fee")
            fees += fee
            spent.update(view)

            base_sig = sum(script.get_sig_op_count(o.script_pubkey)
                           for o in tx.vout) + \
                sum(script.get_sig_op_count(i.script_sig) for i in tx.vin)
            total_sigops_weight += base_sig * 4

        if total_sigops_weight > constants.MAX_BLOCK_SIGOPS_COST:
            raise ChainError("too many sigops")

        # -- segwit witness commitment (BIP141) --------------------------------
        self._check_witness_commitment(block)

        # -- block reward ------------------------------------------------------
        reward = block.txs[0].total_output_value()
        if reward > self.subsidy(height) + fees:
            raise ChainError("coinbase pays too much")

        # -- index hook (token layer etc.): runs while spent coins still exist
        if self.on_block_connected is not None:
            self.on_block_connected(block, entry,
                                    self.utxo_script_lookup(block))

        # -- apply to UTXO set --------------------------------------------------
        applied_spent = {}
        for tx_i, tx in enumerate(block.txs):
            if not tx.is_coinbase():
                for txin in tx.vin:
                    key = txin.prevout.key()
                    coin = self.utxo.pop(key, None)
                    if coin is None:
                        # spent an output created earlier in this block
                        coin = self._consume_intrablock(block, tx_i, key)
                    if coin is None:
                        raise ChainError("internal: missing spend")
                    applied_spent[key] = coin
            tid = tx.txid()
            for n, txo in enumerate(tx.vout):
                self.utxo[(tid, n)] = UTXO(txo, height, tx.is_coinbase(), mtp)
        return applied_spent

    def _utxo_from_block_txs(self, block: Block, before_tx: int, key,
                             height: int) -> UTXO | None:
        """Look up an output created by an earlier tx in the same block."""
        for tx in block.txs[:before_tx]:
            if tx.txid() == key[0]:
                n = key[1]
                if n < len(tx.vout):
                    return UTXO(tx.vout[n], height, tx.is_coinbase())
        return None

    def _consume_intrablock(self, block: Block, before_tx: int, key) -> UTXO | None:
        for tx in block.txs[:before_tx]:
            if tx.txid() == key[0]:
                n = key[1]
                if n < len(tx.vout):
                    return UTXO(tx.vout[n], -1, tx.is_coinbase())
        return None

    def _check_witness_commitment(self, block: Block) -> None:
        has_witness = block.has_witness()
        commitment = None
        for txo in reversed(block.txs[0].vout):
            spk = txo.script_pubkey
            # OP_RETURN PUSH36( aa21a9ed || 32-byte commitment )
            if (len(spk) == 38 and spk[0] == script.OP_RETURN
                    and spk[1] == 0x24 and spk[2:6] == b"\xaa\x21\xa9\xed"):
                commitment = spk[6:]
        reserved = get_witness_reserved_value(block)
        if has_witness:
            if commitment is None or reserved is None:
                raise ChainError("missing witness commitment")
            if witness_commitment(block, reserved) != commitment:
                raise ChainError("bad witness commitment")
        else:
            if commitment is not None and reserved is None:
                raise ChainError("unexpected witness commitment")

    def _disconnect_block(self, block: Block, entry: BlockIndexEntry) -> None:
        if self.on_block_disconnected is not None:
            self.on_block_disconnected(entry)
        height = entry.height
        spent = self.undo.pop(height, {})
        # remove outputs created by this block (reverse tx order)
        for tx in reversed(block.txs):
            tid = tx.txid()
            for n in range(len(tx.vout)):
                self.utxo.pop((tid, n), None)
        # restore spent outputs
        for key, coin in spent.items():
            self.utxo[key] = coin

    # -- helpers -------------------------------------------------------------
    def get_utxo(self, txid: bytes, n: int) -> UTXO | None:
        return self.utxo.get((txid, n))

    def utxo_script_lookup(self, block: Block | None = None):
        """Return a lookup(prevout_key) -> script_pubkey for block indexing.

        Resolves inputs against the current UTXO set plus outputs created
        earlier inside `block` (for intra-block chains).
        """
        def lookup(key) -> bytes | None:
            coin = self.utxo.get(key)
            if coin is not None:
                return coin.txout.script_pubkey
            if block is not None:
                for tx in block.txs:
                    if tx.txid() == key[0] and key[1] < len(tx.vout):
                        return tx.vout[key[1]].script_pubkey
            return None
        return lookup

    def block_locator(self) -> list:
        """Bitcoin getheaders locator: tip back with exponentially wider steps."""
        hashes = []
        step = 1
        i = len(self.active) - 1
        while i >= 0:
            hashes.append(self.active[i].hash)
            if len(hashes) >= 10:
                step *= 2
            i -= step
            if i < 0 and len(hashes) and hashes[-1] != self.active[0].hash:
                hashes.append(self.active[0].hash)
        return hashes
