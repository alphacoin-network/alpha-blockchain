"""Mining: block template construction and the proof-of-work loop.

Mirrors Bitcoin's CreateNewBlock + the miner nonce grind, including the
BIP34 height push in the coinbase, extranonce grinding, segwit witness
commitments (BIP141), and fee collection from mempool transactions.
"""

import os
import struct

from . import constants, script, utils
from .block import Block, BlockHeader, witness_commitment
from .blockchain import Blockchain
from .mempool import Mempool
from .transaction import OutPoint, Transaction, TxIn, TxOut
from .utils import encode_script_num, now


def create_coinbase(height: int, params, payout_script: bytes, fees: int,
                    extra_data: bytes = b"", reserved: bytes | None = None,
                    with_commitment: bytes | None = None) -> Transaction:
    """Build the block's coinbase transaction.

    Follows Bitcoin layout: BIP34 height push + arbitrary coinbase data;
    optional segwit reserved-value witness + commitment output.
    """
    script_sig = script.push_data(encode_script_num(height))
    script_sig += script.push_data(extra_data[:96])
    txin = TxIn(
        prevout=OutPoint(constants.COINBASE_PREV_HASH,
                         constants.COINBASE_PREV_VOUT),
        script_sig=script_sig,
        sequence=constants.SEQUENCE_FINAL,
        witness=[reserved] if reserved is not None else [],
    )
    reward = params.initial_subsidy >> (
        min(height // params.halving_interval, constants.MAX_HALVINGS))
    vout = [TxOut(reward + fees, payout_script)]
    if with_commitment is not None:
        commitment_script = (bytes([script.OP_RETURN, 0x24])
                             + b"\xaa\x21\xa9\xed" + with_commitment)
        vout.append(TxOut(0, commitment_script))
    return Transaction(version=1, vin=[txin], vout=vout, locktime=0)


def create_block_template(chain: Blockchain, mempool: Mempool | None,
                          payout_script: bytes,
                          extra_data: bytes = b"/Alpha/",
                          extranonce: int = 0,
                          reserved: bytes | None = None) -> Block:
    """Assemble a candidate block from the chain tip + mempool."""
    params = chain.params
    tip = chain.tip
    height = tip.height + 1

    # pick mempool transactions by fee rate, within the weight limit
    chosen = []
    fees = 0
    weight = 0
    if mempool is not None:
        for entry in mempool.ordered_by_fee():
            w = entry.tx.weight()
            if weight + w > constants.MAX_BLOCK_WEIGHT:
                continue
            chosen.append(entry.tx)
            fees += entry.fee
            weight += w

    need_witness = any(tx.has_witness() for tx in chosen)
    if need_witness and reserved is None:
        reserved = os.urandom(32)

    # extranonce makes each miner's template unique (no duplicate grinding)
    coinbase_data = extra_data + extranonce.to_bytes(4, "little")

    # first pass: build coinbase without commitment to compute wtxid root
    coinbase = create_coinbase(height, params, payout_script, fees,
                               coinbase_data, reserved)
    block_txs = [coinbase] + chosen
    block = Block(txs=block_txs)

    if need_witness:
        commitment = witness_commitment(block, reserved)
        # rebuild coinbase with the commitment output
        coinbase = create_coinbase(height, params, payout_script, fees,
                                   coinbase_data, reserved, commitment)
        block.txs[0] = coinbase

    header = BlockHeader(
        version=constants.BLOCK_VERSION,
        prev_hash=tip.hash,
        merkle=b"\x00" * 32,
        timestamp=max(now(), tip.median_time_past() + 1),
        bits=chain.next_work_required(tip),
        nonce=0,
    )
    block.header = header
    block.compute_merkle()
    return block


def mine_block(block: Block, pow_limit_bits: int, max_tries: int | None = None,
               extranonce_start: int = 0) -> bool:
    """Grind the nonce (and the coinbase extranonce on overflow).

    Returns True if a valid proof-of-work was found.
    The serialized 80-byte header is kept in a buffer and only the 4
    nonce bytes are patched per hash — Bitcoin-miner style, ~3-5x faster
    than re-serializing every iteration.
    """
    from hashlib import sha256 as _sh
    target = block.header.target()
    tb = target.to_bytes(32, "big")          # digest compare, no int alloc
    buf = bytearray(block.header.serialize())          # nonce LE @ offset 76
    extranonce = extranonce_start
    tries = 0
    while True:
        n = int.from_bytes(buf[76:80], "little") + 1
        while n < 0x100000000:
            buf[76] = n & 0xFF
            buf[77] = (n >> 8) & 0xFF
            buf[78] = (n >> 16) & 0xFF
            buf[79] = (n >> 24) & 0xFF
            tries += 1
            if _sh(_sh(buf).digest()).digest()[::-1] <= tb:
                block.header.nonce = n
                block._hash = None
                return True
            if max_tries is not None and tries >= max_tries:
                return False
            n += 1
        # nonce exhausted: bump the coinbase extranonce -> new merkle root
        extranonce += 1
        cb = block.txs[0]
        cb.vin[0].script_sig += script.push_data(
            encode_script_num(extranonce))
        block.compute_merkle()
        block.header.nonce = 0
        buf = bytearray(block.header.serialize())
