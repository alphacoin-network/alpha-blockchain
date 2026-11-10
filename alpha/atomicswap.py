"""atomicswap — Hash Time-Locked Contracts (HTLC) for trustless
cross-chain atomic swaps, the same construction used by Bitcoin,
Litecoin and every Bitcoin-derived chain.

The contract (classic swap script):

    OP_IF
        OP_SHA256 <secret_hash> OP_EQUALVERIFY
        OP_DUP OP_HASH160 <claim_pubhash>
    OP_ELSE
        <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP
        OP_DUP OP_HASH160 <refund_pubhash>
    OP_ENDIF
    OP_EQUALVERIFY OP_CHECKSIG

  * Claim path : claimer reveals the preimage + sig → gets the coins.
  * Refund path: after <locktime>, refunder takes the coins back.

Both sides lock coins on their own chain into the same secret-hash;
whoever claims first reveals the secret, letting the other side claim.
"""

import secrets as _secrets

from . import crypto, script
from .base58 import b58encode_check
from .transaction import OutPoint, SIGHASH_ALL, Transaction, TxIn, TxOut
from .utils import hash160, sha256, encode_script_num
from .script import (
    OP_CHECKLOCKTIMEVERIFY, OP_CHECKSIG, OP_DROP, OP_DUP, OP_ELSE,
    OP_ENDIF, OP_EQUALVERIFY, OP_HASH160, OP_IF, OP_SHA256,
    OP_TRUE, OP_FALSE, push_data, push_int)

SEED_SIZE = 32


def make_secret() -> tuple:
    """(secret, sha256(secret)) — initiator keeps secret, counterparty gets hash."""
    secret = _secrets.token_bytes(SEED_SIZE)
    return secret, sha256(secret)


def htlc_script(secret_hash: bytes, claim_pkh: bytes, refund_pkh: bytes,
                locktime: int) -> bytes:
    """The swap redeem script."""
    return (
        bytes([OP_IF])
        + bytes([OP_SHA256]) + push_data(secret_hash) + bytes([OP_EQUALVERIFY])
        + bytes([OP_DUP, OP_HASH160]) + push_data(claim_pkh)
        + bytes([OP_ELSE])
        + push_int(locktime) + bytes([OP_CHECKLOCKTIMEVERIFY, OP_DROP])
        + bytes([OP_DUP, OP_HASH160]) + push_data(refund_pkh)
        + bytes([OP_ENDIF])
        + bytes([OP_EQUALVERIFY, OP_CHECKSIG])
    )


def htlc_address(redeem: bytes, params) -> str:
    """P2SH address that funds the contract (send coins here)."""
    return b58encode_check(
        bytes([params.base58_script_address]) + hash160(redeem))


def decode_htlc(redeem: bytes) -> dict:
    """Parse a swap redeem script back into its parts."""
    ops = list(script.parse_script(redeem))
    if len(ops) != 17 or ops[0].opcode != OP_IF or ops[1].opcode != OP_SHA256:
        raise ValueError("not an Alpha HTLC script")
    return {
        "secret_hash": ops[2].data.hex() if ops[2].data else None,
        "claim_pkh": ops[6].data.hex() if ops[6].data else None,
        "locktime": int.from_bytes(ops[8].data, "little") if ops[8].data else 0,
        "refund_pkh": ops[13].data.hex() if ops[13].data else None,
    }


def _spend_tx(prev: OutPoint, value: int, redeem: bytes, key,
              dest_spk: bytes, fee: int, script_sig_extra: bytes,
              locktime: int = 0, sequence: int = 0xFFFFFFFF) -> Transaction:
    """Sign one input spending an HTLC output."""
    tx = Transaction(
        2,
        [TxIn(prevout=prev, sequence=sequence)],
        [TxOut(value - fee, dest_spk)],
        locktime,
    )
    sighash = tx.signature_hash(redeem, 0, SIGHASH_ALL)
    sig = crypto.ecdsa_sign_der(sighash, key.priv) + bytes([SIGHASH_ALL])
    script_sig = (push_data(sig) + push_data(key.pubkey)
                  + script_sig_extra + push_data(redeem))
    tx.vin[0].script_sig = script_sig
    return tx


def build_redeem(prev: OutPoint, value: int, redeem: bytes, secret: bytes,
                 key, dest_spk: bytes, fee: int = 1000) -> Transaction:
    """Claim side: reveals the secret. Works immediately (no timelock)."""
    return _spend_tx(prev, value, redeem, key, dest_spk, fee,
                     push_data(secret) + bytes([OP_TRUE]))


def build_refund(prev: OutPoint, value: int, redeem: bytes, key,
                 dest_spk: bytes, locktime: int,
                 fee: int = 1000) -> Transaction:
    """Refund side: valid only after locktime (CLTV)."""
    return _spend_tx(prev, value, redeem, key, dest_spk, fee,
                     bytes([OP_FALSE]),
                     locktime=locktime, sequence=0xFFFFFFFE)
