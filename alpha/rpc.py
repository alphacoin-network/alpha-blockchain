"""JSON-RPC server -- bitcoind-style interface over HTTP.

`alphad` runs this; `alpha-cli` (or curl) calls it.
"""

import json
import os
import threading
import time
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import constants, crypto, amm as _amm, dex as _dex, identity as _id, merkleproof, script, tokens as _tokens, wallet as _wallet
from .base58 import b58encode_check
from .block import Block
from .transaction import (
    OutPoint, SIGHASH_ALL, Transaction, TxIn, TxOut)
from .utils import (
    BytesReader, compact_to_target, hash160, hash_to_hex, hex_to_hash, now,
)


class RPCError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def _addr_pkh(address: str, params) -> bytes:
    """Extract the 20-byte pubkey-hash from a P2PKH/bech32 address."""
    from .base58 import b58decode_check
    from .bech32 import decode_segwit_address
    if address.startswith(params.bech32_hrp + "1"):
        ver, prog = decode_segwit_address(params.bech32_hrp, address)
        if ver == 0 and len(prog) == 20:
            return bytes(prog)
        raise ValueError("bech32 address must be v0 P2WPKH for swaps")
    raw = b58decode_check(address)
    if raw[0] == params.base58_pubkey_address and len(raw) == 21:
        return raw[1:]
    raise ValueError("address must be P2PKH or P2WPKH for swaps")


RPC_PARSE_ERROR = -32700
RPC_INVALID_REQUEST = -32600
RPC_METHOD_NOT_FOUND = -32601
RPC_INVALID_PARAMS = -32602
RPC_MISC_ERROR = -1
RPC_INVALID_ADDRESS_OR_KEY = -5
RPC_WALLET_INSUFFICIENT_FUNDS = -6


def coins(amount: int) -> float:
    """alphasats -> ALPHA decimal for JSON output."""
    return float(Decimal(amount) / Decimal(constants.COIN))


def sats(amount) -> int:
    """ALPHA decimal -> alphasats."""
    return int(Decimal(str(amount)) * constants.COIN)


def tx_to_json(tx: Transaction, params, block=None, block_height=None,
               tip_height=None) -> dict:
    def script_json(spk: bytes):
        typ, data = script.solver(spk)
        out = {"asm": script_asm(spk), "hex": spk.hex(), "type": typ}
        addr = script.extract_destination(spk, params)
        if addr:
            out["address"] = addr
        return out

    def script_asm(spk: bytes) -> str:
        try:
            parts = []
            for op in script.parse_script(spk):
                if op.data is not None:
                    parts.append(op.data.hex() if op.data else "0")
                else:
                    parts.append(f"OP_{op.opcode:#x}")
            return " ".join(parts)
        except script.ScriptError:
            return spk.hex()

    d = {
        "txid": tx.txid_hex(),
        "hash": hash_to_hex(tx.wtxid()),
        "version": tx.version,
        "size": tx.total_size(),
        "vsize": tx.vsize(),
        "weight": tx.weight(),
        "locktime": tx.locktime,
        "vin": [],
        "vout": [],
    }
    for i, tin in enumerate(tx.vin):
        vin = {"sequence": tin.sequence}
        if tin.is_coinbase():
            vin["coinbase"] = tin.script_sig.hex()
        else:
            vin["txid"] = hash_to_hex(tin.prevout.txid)
            vin["vout"] = tin.prevout.vout
            vin["scriptSig"] = {"asm": script_asm(tin.script_sig),
                                "hex": tin.script_sig.hex()}
        if tin.witness:
            vin["txinwitness"] = [w.hex() for w in tin.witness]
        d["vin"].append(vin)
    for n, tout in enumerate(tx.vout):
        d["vout"].append({
            "value": coins(tout.value),
            "n": n,
            "scriptPubKey": script_json(tout.script_pubkey),
        })
    if block is not None and tip_height is not None:
        d["confirmations"] = tip_height - block_height + 1
        d["blockhash"] = block.hash_hex() if hasattr(block, "hash_hex") else block
    return d


def block_to_json(block: Block, entry, chain, verbosity: int = 1) -> dict:
    d = {
        "hash": block.hash_hex(),
        "confirmations": chain.height - entry.height + 1,
        "height": entry.height,
        "version": block.header.version,
        "merkleroot": hash_to_hex(block.header.merkle),
        "time": block.header.timestamp,
        "mediantime": entry.median_time_past(),
        "nonce": block.header.nonce,
        "bits": f"{block.header.bits:08x}",
        "difficulty": difficulty(block.header.bits, chain.params),
        "chainwork": f"{entry.chainwork:064x}",
        "nTx": len(block.txs),
        "size": block.total_size(),
        "weight": block.weight(),
        "previousblockhash": (hash_to_hex(block.header.prev_hash)
                              if entry.height else None),
        "tx": [tx.txid_hex() for tx in block.txs],
    }
    if verbosity >= 2:
        d["tx"] = [tx_to_json(tx, chain.params, block, entry.height,
                              chain.height) for tx in block.txs]
    return d


def difficulty(bits: int, params) -> float:
    """Bitcoin difficulty = pow_limit_target / current_target."""
    limit = compact_to_target(params.pow_limit_bits)
    cur = compact_to_target(bits)
    return limit / cur if cur else 0.0


# ---------------------------------------------------------------------------
# RPC method implementations
# ---------------------------------------------------------------------------
class RPCMethods:
    def __init__(self, node):
        self.node = node

    # -- chain ------------------------------------------------------------
    def getblockcount(self):
        return self.node.chain.height

    def getbestblockhash(self):
        return hash_to_hex(self.node.chain.best_block_hash())

    def getblockhash(self, height: int):
        e = self.node.chain.get_block_index(int(height))
        if e is None:
            raise RPCError(RPC_INVALID_PARAMS, "block height out of range")
        return hash_to_hex(e.hash)

    def getblock(self, blockhash: str, verbosity: int = 1):
        h = hex_to_hash(blockhash)
        entry = self.node.chain.index.get(h)
        block = self.node.chain.get_block(h)
        if entry is None or block is None:
            raise RPCError(RPC_INVALID_PARAMS, "block not found")
        return block_to_json(block, entry, self.node.chain, int(verbosity))

    def getblockheader(self, blockhash: str):
        h = hex_to_hash(blockhash)
        entry = self.node.chain.index.get(h)
        if entry is None:
            raise RPCError(RPC_INVALID_PARAMS, "block not found")
        return {
            "hash": hash_to_hex(entry.hash),
            "confirmations": self.node.chain.height - entry.height + 1,
            "height": entry.height,
            "version": entry.header.version,
            "merkleroot": hash_to_hex(entry.header.merkle),
            "time": entry.header.timestamp,
            "mediantime": entry.median_time_past(),
            "nonce": entry.header.nonce,
            "bits": f"{entry.header.bits:08x}",
            "difficulty": difficulty(entry.header.bits, self.node.params),
            "chainwork": f"{entry.chainwork:064x}",
        }

    def getblockchaininfo(self):
        chain = self.node.chain
        return {
            "chain": self.node.params.name,
            "blocks": chain.height,
            "headers": chain.height,
            "bestblockhash": hash_to_hex(chain.best_block_hash()),
            "difficulty": difficulty(chain.tip.header.bits, self.node.params),
            "mediantime": chain.tip.median_time_past(),
            "chainwork": f"{chain.tip.chainwork:064x}",
            "initialblockdownload": False,
            "size_on_disk": sum(len(b.serialize()) for b in chain.blocks.values()),
            "pruned": False,
            "supply": coins(chain.total_supply()),
        }

    def getdifficulty(self):
        return difficulty(self.node.chain.tip.header.bits, self.node.params)

    def gettxout(self, txid: str, n: int):
        coin = self.node.chain.get_utxo(hex_to_hash(txid), int(n))
        if coin is None:
            return None
        return {
            "bestblock": hash_to_hex(self.node.chain.best_block_hash()),
            "confirmations": self.node.chain.height - coin.height + 1,
            "value": coins(coin.txout.value),
            "scriptPubKey": {
                "hex": coin.txout.script_pubkey.hex(),
                "type": script.solver(coin.txout.script_pubkey)[0],
                "address": script.extract_destination(
                    coin.txout.script_pubkey, self.node.params),
            },
            "coinbase": coin.is_coinbase,
        }

    # -- mempool ------------------------------------------------------------
    def getrawmempool(self):
        return [hash_to_hex(t) for t in self.node.mempool.txs]

    def getmempoolinfo(self):
        return {
            "size": len(self.node.mempool),
            "bytes": sum(e.tx.total_size()
                         for e in self.node.mempool.txs.values()),
            "usage": len(self.node.mempool),
            "mempoolminfee": 0.00001,
        }

    # -- transactions ---------------------------------------------------------
    def _find_tx(self, txid: bytes):
        entry = self.node.mempool.get(txid)
        if entry:
            return entry.tx, None, None
        for e in self.node.chain.active:
            block = self.node.chain.get_block(e.hash)
            if block is None:
                continue
            for tx in block.txs:
                if tx.txid() == txid:
                    return tx, block, e.height
        return None, None, None

    def getrawtransaction(self, txid: str, verbose: bool = False):
        h = hex_to_hash(txid)
        tx, block, height = self._find_tx(h)
        if tx is None:
            raise RPCError(RPC_INVALID_ADDRESS_OR_KEY, "no such transaction")
        if not verbose:
            return tx.serialize().hex()
        return tx_to_json(tx, self.node.params, block, height,
                          self.node.chain.height)

    def decoderawtransaction(self, hexstr: str):
        try:
            tx = Transaction.deserialize(bytes.fromhex(hexstr))
        except (ValueError, KeyError, IndexError) as e:
            raise RPCError(RPC_INVALID_PARAMS, f"tx decode failed: {e}")
        return tx_to_json(tx, self.node.params)

    def sendrawtransaction(self, hexstr: str):
        try:
            tx = Transaction.deserialize(bytes.fromhex(hexstr))
        except (ValueError, KeyError, IndexError) as e:
            raise RPCError(RPC_INVALID_PARAMS, f"tx decode failed: {e}")
        try:
            self.node.submit_tx(tx)
        except Exception as e:
            raise RPCError(RPC_MISC_ERROR, str(e))
        return tx.txid_hex()

    # -- wallet -----------------------------------------------------------------
    def getnewaddress(self, addrtype: str = "bech32"):
        return self.node.wallet.new_address(addrtype)

    def getaddresses(self):
        return self.node.wallet.addresses()

    def getbalance(self, minconf: int = 1):
        return coins(self.node.wallet.balance(self.node.chain, int(minconf)))

    def listunspent(self, minconf: int = 0):
        out = []
        for u in self.node.wallet.list_unspent(self.node.chain, int(minconf)):
            out.append({
                "txid": hash_to_hex(u["txid"]),
                "vout": u["vout"],
                "address": script.extract_destination(
                    u["script"], self.node.params),
                "amount": coins(u["value"]),
                "confirmations": u["confirmations"],
                "spendable": True,
            })
        return out

    def sendmany(self, _dummy, outputs: dict, fee_rate=1):
        outs = []
        for addr, amt in outputs.items():
            try:
                outs.append((addr, sats(amt)))
            except Exception:
                raise RPCError(RPC_INVALID_ADDRESS_OR_KEY,
                               f"bad output {addr}")
        try:
            tx = self.node.wallet.create_transaction(
                self.node.chain, outs, int(fee_rate))
            self.node.submit_tx(tx)
        except ValueError as e:
            raise RPCError(RPC_WALLET_INSUFFICIENT_FUNDS, str(e))
        except Exception as e:
            raise RPCError(RPC_MISC_ERROR, str(e))
        return tx.txid_hex()

    def createrawtransaction(self, inputs: list, outputs) -> str:
        vin = []
        for i in inputs:
            seq = int(i.get("sequence", 0xFFFFFFFF))
            vin.append(TxIn(prevout=OutPoint(hex_to_hash(i["txid"]),
                                           int(i["vout"])), sequence=seq))
        vout = []
        for addr, amt in (outputs.items() if isinstance(outputs, dict)
                          else []):
            if addr == "data":
                vout.append(TxOut(0, script.script_op_return(
                    bytes.fromhex(amt))))
                continue
            try:
                spk = script.script_for_address(addr, self.node.params)
            except ValueError:
                raise RPCError(RPC_INVALID_ADDRESS_OR_KEY,
                               f"bad address {addr}")
            vout.append(TxOut(sats(amt), spk))
        tx = Transaction(version=constants.TX_VERSION, vin=vin, vout=vout,
                         locktime=0)
        return tx.serialize().hex()

    def signrawtransactionwithwallet(self, hexstr: str):
        try:
            tx = Transaction.deserialize(bytes.fromhex(hexstr))
        except Exception as e:
            raise RPCError(RPC_INVALID_PARAMS, f"tx decode failed: {e}")
        complete = True
        for i, txin in enumerate(tx.vin):
            coin = self.node.chain.utxo.get(txin.prevout.key())
            if coin is None:
                entry = self.node.mempool.get(txin.prevout.txid)
                if entry and txin.prevout.vout < len(entry.tx.vout):
                    out = entry.tx.vout[txin.prevout.vout]
                    spk, val = out.script_pubkey, out.value
                else:
                    complete = False
                    continue
            else:
                spk, val = coin.txout.script_pubkey, coin.txout.value
            key = self.node.wallet._key_for_script(spk)
            if key is None:
                complete = False
                continue
            try:
                _wallet.Wallet.sign_input(tx, i, spk, val, key)
            except ValueError:
                complete = False
        return {"hex": tx.serialize().hex(), "complete": complete}

    def signrawtransaction(self, hexstr: str):
        return self.signrawtransactionwithwallet(hexstr)

    def getreceivedbyaddress(self, address: str):
        try:
            spk = script.script_for_address(address, self.node.params)
        except ValueError:
            raise RPCError(RPC_INVALID_ADDRESS_OR_KEY, "invalid address")
        total = 0
        for e in self.node.chain.active:
            block = self.node.chain.get_block(e.hash)
            for tx in block.txs:
                total += sum(o.value for o in tx.vout
                             if o.script_pubkey == spk)
        return coins(total)

    def listreceivedbyaddress(self, minconf: int = 0):
        received = {}
        confs = {}
        tip = self.node.chain.height
        for e in self.node.chain.active:
            block = self.node.chain.get_block(e.hash)
            for tx in block.txs:
                for o in tx.vout:
                    addr = script.extract_destination(o.script_pubkey,
                                                      self.node.params)
                    if addr is None:
                        continue
                    received[addr] = received.get(addr, 0) + o.value
                    confs[addr] = max(confs.get(addr, 0),
                                      tip - e.height + 1)
        return [{"address": a, "amount": coins(v),
                 "confirmations": confs[a]} for a, v in received.items()]

    def signmessage(self, address: str, message: str):
        try:
            return self.node.wallet.sign_message(address, message)
        except ValueError as e:
            raise RPCError(RPC_INVALID_ADDRESS_OR_KEY, str(e))

    def verifymessage(self, address: str, signature: str, message: str):
        return _wallet.verify_message(address, signature, message,
                                      self.node.params)

    def sendtoaddress(self, address: str, amount, fee_rate=1):
        try:
            script.script_for_address(address, self.node.params)
        except ValueError:
            raise RPCError(RPC_INVALID_ADDRESS_OR_KEY, "invalid address")
        try:
            tx = self.node.wallet.create_transaction(
                self.node.chain, [(address, sats(amount))], int(fee_rate))
            self.node.submit_tx(tx)
        except ValueError as e:
            raise RPCError(RPC_WALLET_INSUFFICIENT_FUNDS, str(e))
        except Exception as e:
            raise RPCError(RPC_MISC_ERROR, str(e))
        return tx.txid_hex()

    # -- burning + multisig -------------------------------------------------------
    def burnalpha(self, amount, note: str = ""):
        """Provably burn ALPHA: sends coins to an OP_RETURN output, which is
        unspendable by consensus — the same mechanism used on Bitcoin."""
        data = ("ALPHABURN:" + str(note)).encode()
        burn_spk = script.script_op_return(data)
        try:
            tx = self.node.wallet.create_transaction(
                self.node.chain, [(burn_spk, sats(amount))], 1)
            self.node.submit_tx(tx)
        except ValueError as e:
            raise RPCError(RPC_WALLET_INSUFFICIENT_FUNDS, str(e))
        except Exception as e:
            raise RPCError(RPC_MISC_ERROR, str(e))
        return {"txid": tx.txid_hex(), "burned": float(amount),
                "note": str(note)}

    def createmultisig(self, nrequired: int, keys: list):
        """Create a m-of-n P2SH multisig address (bitcoind createmultisig)."""
        pubs = []
        for k in keys:
            pk = crypto.parse_pubkey(bytes.fromhex(k))
            pubs.append(crypto.serialize_pubkey(pk, True))
        n = int(nrequired)
        if n < 1 or n > len(pubs) or len(pubs) > 15:
            raise RPCError(RPC_INVALID_PARAMS,
                           "need 1 <= nrequired <= len(keys) <= 15")
        redeem = script.script_multisig(n, pubs)
        addr = b58encode_check(
            bytes([self.node.params.base58_script_address])
            + hash160(redeem))
        return {"address": addr, "redeemScript": redeem.hex()}

    # -- atomic swaps (HTLC) ---------------------------------------------------
    def createswap(self, amount, claim_address: str, refund_address: str,
                   locktime: int):
        """Initiate an atomic swap: creates an HTLC and funds it.

        claim_address  — counterparty claims with the secret
        refund_address — you get coins back after locktime if unclaimed"""
        from . import atomicswap
        params = self.node.params
        secret, secret_hash = atomicswap.make_secret()
        try:
            claim_pkh = _addr_pkh(claim_address, params)
            refund_pkh = _addr_pkh(refund_address, params)
        except ValueError as e:
            raise RPCError(RPC_INVALID_ADDRESS_OR_KEY, str(e))
        redeem = atomicswap.htlc_script(secret_hash, claim_pkh, refund_pkh,
                                        int(locktime))
        htlc_addr = atomicswap.htlc_address(redeem, params)
        txid = self.sendtoaddress(htlc_addr, amount)
        return {
            "contract_address": htlc_addr,
            "redeem_script": redeem.hex(),
            "secret": secret.hex(),
            "secret_hash": secret_hash.hex(),
            "locktime": int(locktime),
            "funding_txid": txid,
            "amount": float(amount),
            "warning": "share secret_hash+redeem with counterparty; "
                       "keep 'secret' until they lock their side",
        }

    def decodeswap(self, redeem_hex: str):
        """Decode a swap contract (redeem script)."""
        from . import atomicswap
        try:
            return atomicswap.decode_htlc(bytes.fromhex(redeem_hex))
        except Exception as e:
            raise RPCError(RPC_INVALID_PARAMS, str(e))

    def redeemswap(self, txid: str, vout: int, value, redeem_hex: str,
                   secret_hex: str, dest_address: str, fee=1000):
        """Claim the contract using the secret (counterparty side)."""
        from . import atomicswap
        key = self.node.wallet._key_for_address(dest_address)
        if key is None:
            raise RPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "dest_address not in this wallet")
        try:
            tx = atomicswap.build_redeem(
                OutPoint(hex_to_hash(txid), int(vout)), sats(value),
                bytes.fromhex(redeem_hex), bytes.fromhex(secret_hex),
                key, script.script_for_address(dest_address,
                                               self.node.params),
                int(fee))
        except Exception as e:
            raise RPCError(RPC_MISC_ERROR, str(e))
        self.node.submit_tx(tx)
        return tx.txid_hex()

    def refundswap(self, txid: str, vout: int, value, redeem_hex: str,
                   dest_address: str, fee=1000):
        """Refund the contract after the locktime has passed."""
        from . import atomicswap
        key = self.node.wallet._key_for_address(dest_address)
        if key is None:
            raise RPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "dest_address not in this wallet")
        info = atomicswap.decode_htlc(bytes.fromhex(redeem_hex))
        try:
            tx = atomicswap.build_refund(
                OutPoint(hex_to_hash(txid), int(vout)), sats(value),
                bytes.fromhex(redeem_hex), key,
                script.script_for_address(dest_address,
                                          self.node.params),
                info["locktime"], int(fee))
        except Exception as e:
            raise RPCError(RPC_MISC_ERROR, str(e))
        self.node.submit_tx(tx)
        return tx.txid_hex()

    # -- wallet encryption (bitcoind encryptwallet/walletpassphrase/walletlock) --
    def encryptwallet(self, passphrase: str):
        w = self.node.wallet
        if w.is_encrypted():
            raise RPCError(RPC_MISC_ERROR, "wallet already encrypted")
        w.encrypt(str(passphrase))
        return "wallet encrypted; Alpha server stopping is not required"

    def walletpassphrase(self, passphrase: str, timeout: int = 60):
        w = self.node.wallet
        if not w.is_encrypted():
            raise RPCError(RPC_MISC_ERROR, "wallet is not encrypted")
        try:
            w.unlock(str(passphrase), int(timeout))
        except ValueError:
            raise RPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "the passphrase is incorrect")
        return None

    def walletlock(self):
        self.node.wallet.lock()
        return None

    def walletpassphrasechange(self, old: str, new: str):
        try:
            self.node.wallet.change_passphrase(str(old), str(new))
        except ValueError as e:
            raise RPCError(RPC_INVALID_ADDRESS_OR_KEY, str(e))
        return None

    def dumpprivkey(self, address: str):
        try:
            return self.node.wallet.export_wif(address)
        except ValueError:
            raise RPCError(RPC_INVALID_ADDRESS_OR_KEY, "address not in wallet")

    def importprivkey(self, wif: str):
        try:
            k = self.node.wallet.import_wif(wif)
        except ValueError as e:
            raise RPCError(RPC_INVALID_ADDRESS_OR_KEY, str(e))
        return k.address("bech32", self.node.params)

    def getwalletinfo(self):
        w = self.node.wallet
        return {
            "balance": coins(w.balance(self.node.chain)),
            "keypoolsize": len(w.all_key_records()) or len(w.keys),
            "txcount": len(w.list_unspent(self.node.chain)),
            "encrypted": w.is_encrypted(),
            "unlocked_until": w._unlock_until if w.is_encrypted() else 0,
        }

    def validateaddress(self, address: str):
        try:
            spk = script.script_for_address(address, self.node.params)
        except ValueError:
            return {"isvalid": False}
        return {
            "isvalid": True,
            "address": address,
            "scriptPubKey": spk.hex(),
            "isscript": spk[0] == script.OP_HASH160 if spk else False,
            "iswitness": script.witness_program(spk) is not None,
        }

    # -- tokens (ALP protocol) ------------------------------------------------------
    def _wallet_scripts(self):
        out = {}
        for k in self.node.wallet.keys:
            for spk in k.scripts():
                out[spk] = k
        return out

    def _find_token_address(self, token_id: bytes, min_amount: int = 1,
                            issuer_only: bool = False):
        """Find a wallet address holding >= min_amount of the token (or the
        issuer address). Returns (script_pubkey, address)."""
        owned = self._wallet_scripts()
        info = self.node.tokens.registry.get(token_id)
        for (tid, spk), amt in self.node.tokens.balances.items():
            if tid != token_id or spk not in owned or amt < min_amount:
                continue
            if issuer_only and (info is None or spk != info.issuer_script):
                continue
            return spk, script.extract_destination(spk, self.node.params)
        return None, None

    def _submit_token_op(self, payload: bytes, signer_spk: bytes,
                         signer_addr: str, recipient_addr: str | None,
                         value: int = 546):
        tx = self.node.wallet.create_token_op_tx(
            self.node.chain, payload, signer_addr, recipient_addr, value)
        self.node.submit_tx(tx)
        return tx

    def _funded_address(self):
        """A wallet address that currently has spendable UTXOs."""
        for u in self.node.wallet.list_unspent(self.node.chain, 1):
            return u["script"], script.extract_destination(
                u["script"], self.node.params)
        return None, None

    def createtoken(self, name: str, decimals: int = 0, supply=0,
                    address: str | None = None):
        """Issue a new ALP token. token_id = the txid of this transaction."""
        if address is None:
            _, address = self._funded_address()
            if address is None:
                raise RPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                               "wallet has no spendable outputs")
        signer_spk = script.script_for_address(address, self.node.params)
        payload = _tokens.encode_issue(str(name), int(decimals), sats(0)
                                       if False else int(Decimal(str(supply))
                                       * (10 ** int(decimals))))
        tx = self._submit_token_op(payload, signer_spk, address, address)
        return {"token_id": tx.txid_hex(), "txid": tx.txid_hex(),
                "address": address}

    def sendtoken(self, token_id: str, address: str, amount,
                  fromaddress: str | None = None):
        tid = hex_to_hash(token_id)
        if tid not in self.node.tokens.registry:
            raise RPCError(RPC_INVALID_PARAMS, "unknown token")
        amt = int(Decimal(str(amount)) * 1)  # raw units
        info = self.node.tokens.registry[tid]
        amt = int(Decimal(str(amount)) * (10 ** info.decimals))
        if fromaddress is None:
            spk, fromaddress = self._find_token_address(tid, amt)
            if spk is None:
                raise RPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                               "no wallet address holds enough of this token")
        else:
            spk = script.script_for_address(fromaddress, self.node.params)
        payload = _tokens.encode_send(tid, amt)
        tx = self._submit_token_op(payload, spk, fromaddress, address)
        return tx.txid_hex()

    def minttoken(self, token_id: str, amount, address: str | None = None):
        tid = hex_to_hash(token_id)
        info = self.node.tokens.registry.get(tid)
        if info is None:
            raise RPCError(RPC_INVALID_PARAMS, "unknown token")
        amt = int(Decimal(str(amount)) * (10 ** info.decimals))
        spk, signer = self._find_token_address(tid, 1, issuer_only=True)
        if spk is None:
            raise RPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "issuer address not in wallet")
        payload = _tokens.encode_mint(tid, amt)
        tx = self._submit_token_op(payload, spk, signer, address or signer)
        return tx.txid_hex()

    def burntoken(self, token_id: str, amount, address: str | None = None):
        tid = hex_to_hash(token_id)
        info = self.node.tokens.registry.get(tid)
        if info is None:
            raise RPCError(RPC_INVALID_PARAMS, "unknown token")
        amt = int(Decimal(str(amount)) * (10 ** info.decimals))
        if address is None:
            spk, address = self._find_token_address(tid, amt)
        else:
            spk = script.script_for_address(address, self.node.params)
        if spk is None:
            raise RPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                           "no wallet address holds enough of this token")
        payload = _tokens.encode_burn(tid, amt)
        tx = self._submit_token_op(payload, spk, address, address)
        return tx.txid_hex()

    # -- DEX (on-chain order book) ------------------------------------------------
    def dexsell(self, token_id: str, amount, total_price_alpha,
                address: str | None = None):
        """Place a sell order: escrow `amount` tokens for `total_price_alpha`.
        order_id = txid of this transaction."""
        tid = hex_to_hash(token_id)
        info = self.node.tokens.registry.get(tid)
        if info is None:
            raise RPCError(RPC_INVALID_PARAMS, "unknown token")
        raw_amt = int(Decimal(str(amount)) * (10 ** info.decimals))
        raw_price = int(Decimal(str(total_price_alpha)) * 10**8 // raw_amt)
        if raw_amt <= 0 or raw_price <= 0:
            raise RPCError(RPC_INVALID_PARAMS, "bad amount/price")
        if address is None:
            spk, address = self._find_token_address(tid, raw_amt)
            if spk is None:
                raise RPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                               "no wallet address holds enough of this token")
        else:
            spk = script.script_for_address(address, self.node.params)
        tx = self._submit_token_op(_dex.encode_sell(tid, raw_amt, raw_price),
                                   spk, address, address)
        return {"order_id": tx.txid_hex(), "amount": float(amount),
                "price_alpha": float(total_price_alpha)}

    def dexfill(self, order_id: str, maxalpha=None):
        """Fill an open order: pays the seller, tokens come to your wallet.
        maxalpha — slippage cap: fill rejected if cost exceeds it."""
        oid = hex_to_hash(order_id)
        order = self.node.dex.orders.get(oid)
        if order is None:
            raise RPCError(RPC_INVALID_PARAMS, "unknown/closed order")
        max_cost = (int(Decimal(str(maxalpha)) * 10**8)
                    if maxalpha is not None else 0)
        seller_addr = script.extract_destination(order["seller"],
                                                 self.node.params)
        if seller_addr is None:
            raise RPCError(RPC_INVALID_PARAMS, "order has non-std seller")
        # pick a funded address that isn't the seller's
        buyer_addr = None
        for u in self.node.wallet.list_unspent(self.node.chain, 1):
            a = script.extract_destination(u["script"], self.node.params)
            if a != seller_addr:
                buyer_addr = a
                break
        if buyer_addr is None:
            raise RPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                           "no funded address other than the seller's")
        need = order["amount"] * order["price"]
        tx = self.node.wallet.create_token_op_tx(
            self.node.chain, _dex.encode_fill(oid, max_cost),
            buyer_addr, seller_addr, need)
        self.node.submit_tx(tx)
        return {"txid": tx.txid_hex(), "paid_alpha": need / 1e8}

    def dexswap(self, token_id: str, total_alpha, maxalpha=None):
        """Market buy — fills the cheapest open orders for `token_id`
        until `total_alpha` is spent. Multi-hop fast swap in one call."""
        tid = hex_to_hash(token_id)
        budget = int(Decimal(str(total_alpha)) * 10**8)
        cap = (int(Decimal(str(maxalpha)) * 10**8)
               if maxalpha is not None else None)
        # cheapest matching orders first — fast best-price execution
        orders = sorted(
            (o for o in self.node.dex.orders.values() if o["token_id"] == tid),
            key=lambda o: o["price"])
        fills, spent = [], 0
        for o in orders:
            need = o["amount"] * o["price"]
            if spent + need > budget:
                break
            if cap is not None and need > cap:
                continue
            seller_addr = script.extract_destination(o["seller"],
                                                     self.node.params)
            buyer_addr = None
            for u in self.node.wallet.list_unspent(self.node.chain, 1):
                a = script.extract_destination(u["script"], self.node.params)
                if a != seller_addr:
                    buyer_addr = a
                    break
            if buyer_addr is None:
                break
            tx = self.node.wallet.create_token_op_tx(
                self.node.chain, _dex.encode_fill(o["order_id"], cap or 0),
                buyer_addr, seller_addr, need)
            self.node.submit_tx(tx)
            fills.append(tx.txid_hex())
            spent += need
        if not fills:
            raise RPCError(RPC_INVALID_PARAMS, "no fillable orders for token")
        return {"fills": fills, "spent_alpha": spent / 1e8}

    def dexcancel(self, order_id: str):
        """Cancel your own open order; escrowed tokens return to you."""
        oid = hex_to_hash(order_id)
        order = self.node.dex.orders.get(oid)
        if order is None:
            raise RPCError(RPC_INVALID_PARAMS, "unknown/closed order")
        seller_addr = script.extract_destination(order["seller"],
                                                 self.node.params)
        tx = self._submit_token_op(_dex.encode_cancel(oid),
                                   order["seller"], seller_addr, seller_addr)
        return tx.txid_hex()

    def dexorders(self):
        return self.node.dex.list_orders(self.node.params)

    # -- AMM (constant-product liquidity pools) ----------------------------------
    def _amt_units(self, tid, amount):
        info = self.node.tokens.registry.get(tid)
        if info is None:
            raise RPCError(RPC_INVALID_PARAMS, "unknown token")
        return int(Decimal(str(amount)) * (10 ** info.decimals))

    def ammcreate(self, token_a: str, token_b: str, fee_bps: int = 30):
        """Create a liquidity pool for a token pair. pool_id = txid."""
        ta, tb = sorted((hex_to_hash(token_a), hex_to_hash(token_b)))
        if ta == tb:
            raise RPCError(RPC_INVALID_PARAMS, "need two different tokens")
        _, signer = self._funded_address()
        tx = self._submit_token_op(
            _amm.encode_create(ta, tb, int(fee_bps)), signer, signer, signer)
        return {"pool_id": tx.txid_hex(), "fee_bps": int(fee_bps)}

    def ammadd(self, pool_id: str, amount_a, amount_b, address: str = None):
        """Add liquidity — deposits both tokens, mints LP shares."""
        pid = hex_to_hash(pool_id)
        pool = self.node.amm.pools.get(pid)
        if pool is None:
            raise RPCError(RPC_INVALID_PARAMS, "unknown pool")
        ra, rb = self._amt_units(pool["ta"], amount_a), self._amt_units(pool["tb"], amount_b)
        if address is None:
            # need an address holding BOTH tokens — search wallet scripts
            owned = self._wallet_scripts()
            address = None
            for (tid, spk), amt in self.node.tokens.balances.items():
                if tid == pool["ta"] and spk in owned and amt >= ra \
                        and self.node.tokens.balance(pool["tb"], spk) >= rb:
                    address = script.extract_destination(spk, self.node.params)
                    break
            if address is None:
                raise RPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                               "no wallet address holds enough of both tokens")
        spk = script.script_for_address(address, self.node.params)
        tx = self._submit_token_op(_amm.encode_add(pid, ra, rb), spk, address, address)
        return tx.txid_hex()

    def ammremove(self, pool_id: str, shares: int, address: str = None):
        """Remove liquidity — burns LP shares, returns pro-rata tokens."""
        pid = hex_to_hash(pool_id)
        owned = self._wallet_scripts()
        if address is None:
            address = next((script.extract_destination(s, self.node.params)
                            for (p, s), v in self.node.amm.shares.items()
                            if p == pid and s in owned and v >= int(shares)), None)
            if address is None:
                raise RPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "no LP shares")
        spk = script.script_for_address(address, self.node.params)
        tx = self._submit_token_op(_amm.encode_remove(pid, int(shares)),
                                   spk, address, address)
        return tx.txid_hex()

    def ammswap(self, pool_id: str, token_in: str, amount_in,
                min_out=0, address: str = None):
        """Swap in one call — constant product, min_out = slippage cap."""
        pid, tin = hex_to_hash(pool_id), hex_to_hash(token_in)
        pool = self.node.amm.pools.get(pid)
        if pool is None:
            raise RPCError(RPC_INVALID_PARAMS, "unknown pool")
        tout = pool["tb"] if tin == pool["ta"] else pool["ta"]
        raw_in = self._amt_units(tin, amount_in)
        raw_min = self._amt_units(tout, min_out) if min_out else 0
        if address is None:
            spk, address = self._find_token_address(tin, raw_in)
            if spk is None:
                raise RPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                               "no wallet address holds enough of token_in")
        else:
            spk = script.script_for_address(address, self.node.params)
        est = self.node.amm.quote(pool, tin, raw_in)
        tx = self._submit_token_op(
            _amm.encode_swap(pid, tin, raw_in, raw_min), spk, address, address)
        info_out = self.node.tokens.registry.get(tout)
        return {"txid": tx.txid_hex(), "expected_out":
                est / (10 ** info_out.decimals) if info_out else est}

    def ammpools(self):
        return self.node.amm.list_pools(self.node.params, self.node.tokens)

    def ammquote(self, pool_id: str, token_in: str, amount_in):
        """Dry-run a swap — returns expected output (no tx)."""
        pid, tin = hex_to_hash(pool_id), hex_to_hash(token_in)
        pool = self.node.amm.pools.get(pid)
        if pool is None:
            raise RPCError(RPC_INVALID_PARAMS, "unknown pool")
        tout = pool["tb"] if tin == pool["ta"] else pool["ta"]
        est = self.node.amm.quote(pool, tin, self._amt_units(tin, amount_in))
        info_out = self.node.tokens.registry.get(tout)
        return {"expected_out": est / (10 ** info_out.decimals)
                if info_out else est, "token_out": tout.hex()}

    # -- Identity (DID + verifiable credentials) --------------------------------
    def registeridentity(self, label: str, address: str = None):
        """Anchor your DID on-chain — did:alpha:<address> gets a label."""
        if address is None:
            _, address = self._funded_address()
        spk = script.script_for_address(address, self.node.params)
        tx = self._submit_token_op(
            _id.encode_register(label), spk, address, address)
        return {"did": "did:alpha:" + address, "txid": tx.txid_hex()}

    def issuecredential(self, subject_address: str, ctype: str,
                        credential_hash: str = "", address: str = None):
        """Issue a verifiable credential to a subject DID (e.g. 'kyc').
        Only the hash is anchored on-chain — privacy-preserving."""
        if address is None:
            _, address = self._funded_address()
        spk = script.script_for_address(address, self.node.params)
        try:
            subj = _addr_pkh(subject_address, self.node.params)
        except ValueError as e:
            raise RPCError(RPC_INVALID_ADDRESS_OR_KEY, str(e))
        ch = bytes.fromhex(credential_hash) if credential_hash else b""
        tx = self._submit_token_op(
            _id.encode_claim(subj, ctype, ch), spk, address, address)
        return {"claim_id": tx.txid_hex(),
                "issuer": "did:alpha:" + address,
                "subject": "did:alpha:" + subject_address}

    def revokecredential(self, claim_id: str):
        """Revoke a credential you issued."""
        cid = hex_to_hash(claim_id)
        c = self.node.identity.claims.get(cid)
        if c is None:
            raise RPCError(RPC_INVALID_PARAMS, "unknown claim")
        issuer = script.extract_destination(c["issuer"], self.node.params)
        tx = self._submit_token_op(
            _id.encode_revoke(cid), c["issuer"], issuer, issuer)
        return tx.txid_hex()

    def resolveidentity(self, address: str):
        """Resolve a DID — returns its on-chain document + claims."""
        try:
            spk = script.script_for_address(address, self.node.params)
        except ValueError:
            raise RPCError(RPC_INVALID_ADDRESS_OR_KEY, "invalid address")
        return self.node.identity.resolve(spk, self.node.params)

    def updateidentity(self, label: str, doc_hash_hex: str = "",
                       address: str = None):
        """Update your DID profile — label + metadata/document hash."""
        if address is None:
            _, address = self._funded_address()
        spk = script.script_for_address(address, self.node.params)
        dh = bytes.fromhex(doc_hash_hex) if doc_hash_hex else b""
        tx = self._submit_token_op(
            _id.encode_register(label, dh), spk, address, address)
        return {"did": "did:alpha:" + address, "txid": tx.txid_hex()}

    def alphaidchallenge(self, address: str, domain: str,
                         nonce: str = None):
        """Alpha ID sign-in challenge — a canonical message the wallet signs
        to prove DID control to an app (verify with verifymessage)."""
        import secrets as _s
        nonce = nonce or _s.token_hex(8)
        msg = (f"Sign in to {domain} with Alpha ID\n"
               f"Address: {address}\nNonce: {nonce}")
        return {"message": msg, "sign_with": "signmessage",
                "verify_with": "verifymessage"}

    def verifycredential(self, claim_id: str, issuer_address: str = None):
        """Check a credential is real, unrevoked, and (optionally) issued
        by a specific issuer — reusable verification."""
        cid = hex_to_hash(claim_id)
        c = self.node.identity.claims.get(cid)
        if c is None:
            return {"valid": False, "reason": "claim not found"}
        issuer = script.extract_destination(c["issuer"], self.node.params)
        if issuer_address is not None and issuer != issuer_address:
            return {"valid": False, "reason": "issuer mismatch"}
        return {"valid": not c["revoked"], "revoked": c["revoked"],
                "type": c["ctype"], "hash": c["chash"].hex(),
                "issuer": issuer, "height": c["height"]}

    # -- RWA (compliant real-world asset tokens) ---------------------------------
    def createrwatoken(self, name: str, decimals: int = 0, supply=0,
                       kyc_required: bool = False,
                       issuer_can_clawback: bool = False,
                       kyc_issuer_address: str = None,
                       address: str = None):
        """Issue a permissioned RWA token — whitelist KYC recipients and/or
        issuer clawback for securities-style compliance."""
        flags = (_tokens.FLAG_KYC_REQUIRED if kyc_required else 0) | \
                (_tokens.FLAG_CLAWBACK if issuer_can_clawback else 0)
        kip = b""
        if kyc_issuer_address:
            kip = _addr_pkh(kyc_issuer_address, self.node.params)
        if address is None:
            _, address = self._funded_address()
        spk = script.script_for_address(address, self.node.params)
        amt = int(Decimal(str(supply)) * (10 ** int(decimals)))
        payload = _tokens.encode_issue_rwa(name, int(decimals), amt,
                                           flags, kip)
        tx = self._submit_token_op(payload, spk, address, address)
        return {"token_id": tx.txid_hex(), "kyc_required": kyc_required,
                "issuer_can_clawback": issuer_can_clawback}

    def rwaclawback(self, token_id: str, holder_address: str, amount,
                    address: str = None):
        """Compliance seizure — issuer reclaims tokens from a holder.
        Only valid for tokens issued with issuer_can_clawback."""
        tid = hex_to_hash(token_id)
        info = self.node.tokens.registry.get(tid)
        if info is None or not (info.flags & _tokens.FLAG_CLAWBACK):
            raise RPCError(RPC_INVALID_PARAMS,
                           "not a clawback-enabled RWA token")
        if address is None:
            issuer = script.extract_destination(info.issuer_script,
                                                self.node.params)
            address = issuer
        spk = script.script_for_address(address, self.node.params)
        raw = int(Decimal(str(amount)) * (10 ** info.decimals))
        tx = self._submit_token_op(
            _tokens.encode_clawback(tid, _addr_pkh(holder_address,
                                    self.node.params), raw),
            spk, address, address)
        return tx.txid_hex()

    def rwaretire(self, token_id: str, amount, beneficiary: str = "",
                  address: str = None):
        """Permanently retire tokens (e.g. carbon credit offset) — public,
        immutable retirement certificate anchored on-chain."""
        tid = hex_to_hash(token_id)
        info = self.node.tokens.registry.get(tid)
        if info is None:
            raise RPCError(RPC_INVALID_PARAMS, "unknown token")
        if address is None:
            spk, address = self._find_token_address(tid, 1)
            if spk is None:
                raise RPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                               "no wallet address holds the token")
        else:
            spk = script.script_for_address(address, self.node.params)
        raw = int(Decimal(str(amount)) * (10 ** info.decimals))
        tx = self._submit_token_op(
            _tokens.encode_retire(tid, raw, beneficiary), spk, address, address)
        return {"txid": tx.txid_hex(), "beneficiary": beneficiary}

    def rwadistribute(self, token_id: str, alpha_amount):
        """Dividend/rental income — pro-rata ALPHA to all holders."""
        tid = hex_to_hash(token_id)
        holders = self.node.tokens.holders(tid)
        if not holders:
            raise RPCError(RPC_INVALID_PARAMS, "no holders")
        total = sum(holders.values())
        total_sat = int(Decimal(str(alpha_amount)) * 10**8)
        outs, paid = [], 0
        for spk, amt in holders.items():
            share = total_sat * amt // total
            if share > 0:
                addr = script.extract_destination(spk, self.node.params)
                if addr:
                    outs.append((addr, share))
                    paid += share
        if not outs:
            raise RPCError(RPC_INVALID_PARAMS, "nothing distributable")
        outputs = [(script.script_for_address(a, self.node.params), s)
                   for a, s in outs]
        tx = self.node.wallet.create_transaction(self.node.chain, outputs, 1)
        self.node.submit_tx(tx)
        return {"txid": tx.txid_hex(), "paid_alpha": paid / 1e8,
                "holders_paid": len(outs)}

    def rwabacking(self, token_id: str, asset_class: str, custodian: str,
                   audit_hash_hex: str = "", address: str = None):
        """Anchor physical-backing provenance — issuer records the asset's
        class (real_estate/gold/...), custodian and audit/appraisal hash."""
        tid = hex_to_hash(token_id)
        info = self.node.tokens.registry.get(tid)
        if info is None:
            raise RPCError(RPC_INVALID_PARAMS, "unknown token")
        if address is None:
            address = script.extract_destination(info.issuer_script,
                                                 self.node.params)
        spk = script.script_for_address(address, self.node.params)
        ah = bytes.fromhex(audit_hash_hex) if audit_hash_hex else b""
        tx = self._submit_token_op(
            _tokens.encode_assetmeta(tid, asset_class, custodian, ah),
            spk, address, address)
        return tx.txid_hex()

    def retirementcerts(self):
        return [{"txid": c["txid"].hex(), "amount": c["amount"],
                 "beneficiary": c["beneficiary"], "height": c["height"]}
                for c in self.node.tokens.retirements]

    def kycstatus(self, address: str):
        """Reusable KYC check — returns all valid 'kyc' claims for a DID,
        with issuers. Apps trust whichever issuers they accept."""
        try:
            pkh = _addr_pkh(address, self.node.params)
        except ValueError:
            raise RPCError(RPC_INVALID_ADDRESS_OR_KEY, "invalid address")
        valid = [c for c in self.node.identity.claims.values()
                 if c["subject"] == pkh and c["ctype"] == "kyc"
                 and not c["revoked"]]
        return {"did": "did:alpha:" + address, "kyc_verified": bool(valid),
                "issuers": [script.extract_destination(c["issuer"],
                            self.node.params) for c in valid],
                "count": len(valid)}

    def listtokens(self):
        return self.node.tokens.list_tokens(self.node.params)

    def gettokeninfo(self, token_id: str):
        d = self.node.tokens.token_info(hex_to_hash(token_id),
                                        self.node.params)
        if d is None:
            raise RPCError(RPC_INVALID_PARAMS, "unknown token")
        return d

    def gettokenbalance(self, token_id: str, address: str | None = None):
        tid = hex_to_hash(token_id)
        info = self.node.tokens.registry.get(tid)
        if info is None:
            raise RPCError(RPC_INVALID_PARAMS, "unknown token")
        if address is not None:
            spk = script.script_for_address(address, self.node.params)
            amt = self.node.tokens.balance(tid, spk)
            return {"address": address, "balance": amt,
                    "display_balance": amt / 10 ** info.decimals}
        return self.node.tokens.balance_json(tid, self.node.params)

    def listtokenbalances(self, address: str | None = None):
        if address is not None:
            spks = [script.script_for_address(address, self.node.params)]
        else:
            spks = list(self._wallet_scripts())
        out = []
        for spk in spks:
            for tid, amt in self.node.tokens.balances_for(spk).items():
                info = self.node.tokens.registry.get(tid)
                out.append({
                    "token_id": hash_to_hex(tid),
                    "name": info.name if info else "?",
                    "address": script.extract_destination(spk,
                                                          self.node.params),
                    "balance": amt,
                    "display_balance": amt / 10 ** (info.decimals if info
                                                    else 0),
                })
        return out

    def gettokenholders(self, token_id: str):
        return self.node.tokens.balance_json(hex_to_hash(token_id),
                                             self.node.params)

    # -- proofs / misc ---------------------------------------------------------------
    def gettxoutproof(self, txids: list, blockhash: str | None = None):
        wanted = {hex_to_hash(t) for t in txids}
        if blockhash:
            block = self.node.chain.get_block(hex_to_hash(blockhash))
        else:
            block = None
            for e in self.node.chain.active:
                b = self.node.chain.get_block(e.hash)
                if b and any(tx.txid() in wanted for tx in b.txs):
                    block = b
                    break
        if block is None:
            raise RPCError(RPC_INVALID_PARAMS, "block not found")
        return merkleproof.txout_proof(block, wanted).hex()

    def verifytxoutproof(self, hexstr: str):
        try:
            matched, root, header = merkleproof.verify_proof(
                bytes.fromhex(hexstr))
        except (ValueError, KeyError, IndexError) as e:
            raise RPCError(RPC_INVALID_PARAMS, f"bad proof: {e}")
        return [hash_to_hex(t) for t in matched]

    def getchaintips(self):
        parents = {e.parent.hash for e in self.node.chain.index.values()
                   if e.parent}
        tips = []
        for h, e in self.node.chain.index.items():
            if h in parents:
                continue
            on_main = (e.height < len(self.node.chain.active)
                       and self.node.chain.active[e.height] is e)
            tips.append({
                "height": e.height,
                "hash": hash_to_hex(h),
                "branchlen": 0 if on_main else e.height - (
                    self.node.chain._find_fork(e).height if e.parent else 0),
                "status": "active" if on_main else "valid-fork",
            })
        return tips

    def getblockstats(self, hash_or_height):
        if isinstance(hash_or_height, str) and len(hash_or_height) == 64:
            entry = self.node.chain.index.get(hex_to_hash(hash_or_height))
        else:
            entry = self.node.chain.get_block_index(int(hash_or_height))
        if entry is None:
            raise RPCError(RPC_INVALID_PARAMS, "block not found")
        block = self.node.chain.get_block(entry.hash)
        fees = 0
        total_out = 0
        for tx in block.txs[1:]:
            in_sum = 0
            for tin in tx.vin:
                c = self.node.chain.utxo.get(tin.prevout.key())
                if c:
                    in_sum += c.txout.value
            if in_sum:
                fees += max(0, in_sum - tx.total_output_value())
            total_out += tx.total_output_value()
        return {
            "height": entry.height,
            "hash": hash_to_hex(entry.hash),
            "blockhash": hash_to_hex(entry.hash),
            "time": entry.header.timestamp,
            "mediantime": entry.median_time_past(),
            "txs": len(block.txs),
            "total_size": block.total_size(),
            "total_weight": block.weight(),
            "subsidy": coins(self.node.chain.subsidy(entry.height)),
            "totalfee": coins(fees),
            "total_out": coins(total_out + block.txs[0].total_output_value()),
        }

    def decodescript(self, hexstr: str):
        spk = bytes.fromhex(hexstr)
        typ, data = script.solver(spk)
        out = {"asm": "", "type": typ}
        addr = script.extract_destination(spk, self.node.params)
        if addr:
            out["address"] = addr
        if typ == script.TX_SCRIPTHASH:
            out["p2sh"] = addr
        wp = script.witness_program(spk)
        if wp:
            out["segwit"] = {"version": wp[0], "program": wp[1].hex(),
                             "address": addr}
        return out

    def uptime(self):
        return int(time.time()) - self.node.start_time

    def getnetworkhashps(self, nblocks: int = 120):
        tip = self.node.chain.tip
        n = min(int(nblocks), tip.height)
        if n <= 0:
            return 0
        first = self.node.chain.get_block_index(tip.height - n)
        work = tip.chainwork - first.chainwork
        timespan = max(1, tip.header.timestamp - first.header.timestamp)
        return work / timespan

    def scantxoutset(self, action: str = "start"):
        if action != "start":
            return {"success": False}
        unspents = []
        total = 0
        for (txid, n), c in self.node.chain.utxo.items():
            unspents.append({
                "txid": hash_to_hex(txid), "vout": n,
                "amount": coins(c.txout.value),
                "height": c.height,
                "scriptPubKey": c.txout.script_pubkey.hex(),
                "address": script.extract_destination(c.txout.script_pubkey,
                                                      self.node.params),
            })
            total += c.txout.value
        return {"success": True, "unspents": unspents,
                "total_amount": coins(total)}

    def getmempoolentry(self, txid: str):
        e = self.node.mempool.get(hex_to_hash(txid))
        if e is None:
            raise RPCError(RPC_INVALID_PARAMS, "tx not in mempool")
        return {"size": e.tx.total_size(), "vsize": e.tx.vsize(),
                "weight": e.tx.weight(), "fee": coins(e.fee),
                "time": e.time, "feerate": e.fee_rate}

    def listtransactions(self, count: int = 10):
        owned = set(self._wallet_scripts())
        out = []
        tip = self.node.chain.height
        for e in reversed(self.node.chain.active):
            block = self.node.chain.get_block(e.hash)
            if block is None:
                continue
            for tx in block.txs:
                got = sum(o.value for o in tx.vout
                          if o.script_pubkey in owned)
                if got:
                    out.append({
                        "txid": tx.txid_hex(), "category": "receive",
                        "amount": coins(got),
                        "confirmations": tip - e.height + 1,
                        "blockhash": block.hash_hex(),
                        "blockheight": e.height,
                    })
                if len(out) >= int(count):
                    return out
        return out

    def sendopreturn(self, data_hex: str, address: str | None = None):
        """Embed arbitrary data in the chain via OP_RETURN."""
        if address is None:
            address = self.node.wallet.new_address("bech32")
        spk = script.script_for_address(address, self.node.params)
        tx = self.node.wallet.create_token_op_tx(
            self.node.chain, bytes.fromhex(data_hex), address, address)
        self.node.submit_tx(tx)
        return tx.txid_hex()

    # -- mining -------------------------------------------------------------------
    def generatetoaddress(self, nblocks: int, address: str):
        try:
            spk = script.script_for_address(address, self.node.params)
        except ValueError:
            raise RPCError(RPC_INVALID_ADDRESS_OR_KEY, "invalid address")
        hashes = []
        for _ in range(int(nblocks)):
            block = self.node.generate_block(spk)
            hashes.append(block.hash_hex())
        return hashes

    def generate(self, nblocks: int = 1):
        addr = self.node.wallet.new_address("bech32")
        return self.generatetoaddress(nblocks, addr)

    # -- remote/browser mining (getwork) ----------------------------------------
    _work_cache: dict = {}

    def getwork(self, address: str):
        """Return a block template for external/browser mining.
        Header is 80 bytes; the caller hashes `data` + nonce (4B LE)."""
        import secrets as _sec
        try:
            spk = script.script_for_address(address, self.node.params)
        except ValueError:
            raise RPCError(RPC_INVALID_ADDRESS_OR_KEY, "invalid address")
        block = self.node.get_block_template(spk)
        wid = _sec.token_hex(8)
        self.__class__._work_cache[wid] = block
        if len(self.__class__._work_cache) > 64:      # bound the cache
            self.__class__._work_cache.popitem()
        hdr = block.header.serialize()
        return {
            "workid": wid,
            "data": hdr[:-4].hex(),                    # first 76 bytes
            "target": "%064x" % compact_to_target(block.header.bits),
            "height": block.header.__dict__.get("n", None) or self.node.chain.height + 1,
        }

    def submitwork(self, workid: str, nonce):
        """Submit a found nonce for a getwork template."""
        block = self.__class__._work_cache.pop(workid, None)
        if block is None:
            raise RPCError(RPC_INVALID_PARAMS, "unknown/expired workid")
        block.header.nonce = int(nonce) & 0xFFFFFFFF
        target = compact_to_target(block.header.bits)
        if int.from_bytes(block.header.hash(), "little") > target:
            raise RPCError(RPC_INVALID_PARAMS, "nonce does not meet target")
        self.node.submit_block(block)
        return {"hash": block.hash_hex(), "height": self.node.chain.height,
                "accepted": True}

    def getmininginfo(self):
        return {
            "blocks": self.node.chain.height,
            "difficulty": difficulty(self.node.chain.tip.header.bits,
                                     self.node.params),
            "networkhashps": 0,
            "pooledtx": len(self.node.mempool),
            "chain": self.node.params.name,
        }

    # -- network ------------------------------------------------------------------
    def addnode(self, nodeaddr: str):
        if ":" in nodeaddr:
            ip, port = nodeaddr.rsplit(":", 1)
            port = int(port)
        else:
            ip, port = nodeaddr, self.node.params.default_port
        ok = self.node.connect(ip, port)
        if not ok:
            raise RPCError(RPC_MISC_ERROR, "could not connect")
        return None

    def getpeerinfo(self):
        out = []
        for p in self.node.peers:
            out.append({
                "addr": f"{p.addr[0]}:{p.addr[1]}",
                "inbound": p.inbound,
                "handshake": p.handshake_done,
                "version": p.peer_version.get("version"),
                "subver": (p.peer_version.get("user_agent") or b"").decode(
                    "utf-8", "replace"),
                "startingheight": p.peer_version.get("start_height", 0),
            })
        return out

    def getconnectioncount(self):
        return len([p for p in self.node.peers if p.handshake_done])

    def getnetworkinfo(self):
        return {
            "version": 70015,
            "subversion": "/Alpha:0.1.0/",
            "protocolversion": 70015,
            "localservices": "0000000000000409",
            "connections": len(self.node.peers),
            "networkactive": True,
        }

    def estimatesmartfee(self, conf_target: int = 6):
        return {"feerate": 0.00001000, "blocks": int(conf_target)}

    # -- PSBT (BIP174) -----------------------------------------------------------
    def createpsbt(self, outputs: dict, locktime: int = 0):
        """Create an unfunded PSBT spending nothing (caller fills inputs)."""
        from . import psbt as _psbt
        tx = Transaction.deserialize(
            bytes.fromhex(self.createrawtransaction([], outputs)))
        tx.locktime = int(locktime)
        return _psbt.PSBT(tx).to_base64()

    def walletcreatefundedpsbt(self, outputs: dict, conf_target: int = 6):
        """Build + fund a PSBT from the wallet."""
        from . import psbt as _psbt
        tx = self.node.wallet.create_transaction(
            self.node.chain,
            [(a, sats(v)) for a, v in outputs.items()])
        p = _psbt.PSBT(tx)
        for n_in, txin in enumerate(tx.vin):
            coin = self.node.chain.utxo.get(txin.prevout.key())
            if coin is not None:
                p.set_witness_utxo(n_in, coin.txout)
        return p.to_base64()

    def walletprocesspsbt(self, b64: str):
        """Sign what we can in a PSBT. Returns updated PSBT."""
        from . import psbt as _psbt
        p = _psbt.PSBT.from_base64(b64)
        complete = True
        for n_in in range(len(p.tx.vin)):
            spk_txo = p.input_utxo_spk(n_in)
            if spk_txo is None:
                complete = False
                continue
            typ, data = script.solver(spk_txo.script_pubkey)
            try:
                key = self.node.wallet._key_for_script(
                    spk_txo.script_pubkey)
                if key is None:
                    complete = False
                    continue
                val = p.input_value(n_in)
                spk = spk_txo.script_pubkey
                if typ == script.TX_WITNESS_V1_TAPROOT:
                    from . import schnorr
                    amounts = [p.input_value(i)
                               for i in range(len(p.tx.vin))]
                    spks = [p.input_utxo_spk(i).script_pubkey
                            for i in range(len(p.tx.vin))]
                    sighash = p.tx.signature_hash_v1(
                        n_in, amounts, spks, 0x00)
                    sig = schnorr.schnorr_sign(
                        sighash, schnorr.taproot_tweak(key.priv))
                    p.add_partial_sig(n_in, b"", sig)
                elif typ == script.TX_WITNESS_V0_KEYHASH:
                    code = script.script_p2pkh(data)
                    sh = p.tx.signature_hash_v0(code, n_in, val, SIGHASH_ALL)
                    sig = crypto.ecdsa_sign_der(sh, key.priv) + b"\x01"
                    p.add_partial_sig(n_in, key.pubkey, sig)
                elif typ in (script.TX_PUBKEYHASH, script.TX_PUBKEY):
                    sh = p.tx.signature_hash(spk, n_in, SIGHASH_ALL)
                    sig = crypto.ecdsa_sign_der(sh, key.priv) + b"\x01"
                    p.add_partial_sig(n_in, key.pubkey, sig)
                else:
                    complete = False
            except Exception:
                complete = False
        return {"psbt": p.to_base64(), "complete": complete}

    def finalizepsbt(self, b64: str):
        """Finalize all inputs and extract the raw transaction."""
        from . import psbt as _psbt
        p = _psbt.PSBT.from_base64(b64)
        try:
            p.finalize()
        except Exception as e:
            raise RPCError(RPC_MISC_ERROR, f"finalize failed: {e}")
        return {"hex": p.extract().serialize(include_witness=True).hex(),
                "complete": True}

    def combinepsbt(self, psbts: list):
        from . import psbt as _psbt
        ps = [_psbt.PSBT.from_base64(b) for b in psbts]
        ps[0].combine(*ps[1:])
        return ps[0].to_base64()

    def decodepsbt(self, b64: str):
        from . import psbt as _psbt
        p = _psbt.PSBT.from_base64(b64)
        return {"tx": tx_to_json(p.tx, self.node.params),
                "inputs": [
                    {"has_utxo": any(k[:1] == bytes([0]) or k[:1] == bytes([1])
                                     for k in inp),
                     "partial_sigs": len(p.partial_sigs(i))}
                    for i, inp in enumerate(p.inputs)]}

    # -- descriptors + filters --------------------------------------------------
    def getdescriptorinfo(self, descriptor: str):
        from . import descriptors
        spk = descriptors.expand(descriptor, self.node.params)
        return {"descriptor": descriptor,
                "scriptpubkey": spk.hex(),
                "type": descriptors.descriptor_type(descriptor)}

    def deriveaddresses(self, descriptor: str, range_: int = 1):
        from . import descriptors
        spk = descriptors.expand(descriptor, self.node.params)
        dest = script.extract_destination(spk, self.node.params)
        return [dest] * range_ if dest else []

    def getblockfilter(self, blockhash: str, filtertype: str = "basic"):
        """BIP158 compact filter for a block."""
        from . import filters as _f
        block = self.node.chain.get_block(hex_to_hash(blockhash))
        if block is None:
            raise RPCError(RPC_INVALID_PARAMS, "block not found")
        key = int.from_bytes(block.header.hash()[:16], "little")
        filt, n = _f.block_filter(block, key)
        return {"filter": filt.hex(), "header": block.header.hash().hex(),
                "type": filtertype, "block_hash": block.header.hash().hex()}

    def estimatesmartfee(self, conf_target: int = 6, estimate_mode: str = "CONSERVATIVE"):
        return {"feerate": self.node.mempool.estimate_fee(conf_target),
                "blocks": conf_target}

    def stop(self):
        threading.Thread(target=self.node.stop, daemon=True).start()
        return "Alpha node stopping"


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------
def make_handler(rpc: RPCMethods, auth: str | None = None):
    """HTTP handler. If `auth` ("user:pass") is set, HTTP Basic auth is
    required -- same scheme bitcoind uses with its .cookie file."""
    expected = ("Basic " + __import__("base64").b64encode(
        auth.encode()).decode()) if auth else None

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _authorized(self) -> bool:
            if expected is None:
                return True
            if self.headers.get("Authorization") == expected:
                return True
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="alphad"')
            self.end_headers()
            return False

        # -- bitcoind-compatible REST endpoints ----------------------------------
        def do_GET(self):
            if not self._authorized():
                return
            try:
                result = self._rest(self.path)
            except RPCError as e:
                self._reply({"error": {"code": e.code, "message": str(e)}}, 404)
                return
            except Exception as e:  # noqa: BLE001
                self._reply({"error": {"code": -1, "message": str(e)}}, 500)
                return
            if result is None:
                self._reply({"error": {"code": -5,
                                       "message": "not found"}}, 404)
            else:
                self._reply(result)

        def _rest(self, path: str):
            parts = [p for p in path.split("/") if p]
            if not parts or parts[0] != "rest":
                return None
            route = parts[1:]
            if route == ["chaininfo.json"]:
                return rpc.getblockchaininfo()
            if route == ["mempool", "info.json"]:
                return rpc.getmempoolinfo()
            if route == ["mempool", "contents.json"]:
                return {"txids": rpc.getrawmempool(),
                        "size": len(rpc.node.mempool)}
            if len(route) == 2 and route[0] == "block" \
                    and route[1].endswith(".json"):
                return rpc.getblock(route[1][:-5], 2)
            if len(route) == 3 and route[0] == "block" \
                    and route[1] == "notxdetails" \
                    and route[2].endswith(".json"):
                return rpc.getblock(route[2][:-5], 1)
            if len(route) == 3 and route[0] == "headers" \
                    and route[2].endswith(".json"):
                count = int(route[1])
                entry = rpc.node.chain.index.get(
                    hex_to_hash(route[2][:-5]))
                if entry is None:
                    return None
                out = []
                e = entry
                while e and len(out) < count:
                    out.append(rpc.getblockheader(hash_to_hex(e.hash)))
                    e = e.parent
                return out
            if len(route) == 2 and route[0] == "tx" \
                    and route[1].endswith(".json"):
                return rpc.getrawtransaction(route[1][:-5], True)
            if len(route) == 2 and route[0] == "utxo" \
                    and route[1].endswith(".json"):
                txid_n = route[1][:-5]
                txid, n = txid_n.rsplit("-", 1)
                return rpc.gettxout(txid, int(n))
            if route == ["tokens.json"]:
                return rpc.listtokens()
            if len(route) == 2 and route[0] == "token" \
                    and route[1].endswith(".json"):
                return rpc.gettokeninfo(route[1][:-5])
            return None

        def do_POST(self):
            if not self._authorized():
                return
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                self._reply({"jsonrpc": "2.0", "id": None, "result": None,
                             "error": {"code": RPC_PARSE_ERROR,
                                       "message": "parse error"}})
                return
            method = body.get("method", "")
            params = body.get("params", [])
            if not isinstance(params, (list, tuple)):
                params = [params]
            fn = getattr(rpc, method, None)
            if fn is None or method.startswith("_"):
                err = {"code": RPC_METHOD_NOT_FOUND,
                       "message": "method not found"}
                self._reply({"jsonrpc": "2.0", "id": body.get("id"),
                             "result": None, "error": err})
                return
            try:
                result = fn(*params)
                self._reply({"jsonrpc": "2.0", "id": body.get("id"),
                             "result": result, "error": None})
            except RPCError as e:
                self._reply({"jsonrpc": "2.0", "id": body.get("id"),
                             "result": None,
                             "error": {"code": e.code, "message": str(e)}})
            except _wallet.WalletLocked as e:
                self._reply({"jsonrpc": "2.0", "id": body.get("id"),
                             "result": None,
                             "error": {"code": -13,
                                       "message": str(e)}})
            except TypeError as e:
                self._reply({"jsonrpc": "2.0", "id": body.get("id"),
                             "result": None,
                             "error": {"code": RPC_INVALID_PARAMS,
                                       "message": str(e)}})
            except Exception as e:  # noqa: BLE001
                self._reply({"jsonrpc": "2.0", "id": body.get("id"),
                             "result": None,
                             "error": {"code": RPC_MISC_ERROR,
                                       "message": str(e)}})

        def _reply(self, obj, status: int = 200):
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


def serve(node, host: str, port: int,
          auth: str | None = None) -> ThreadingHTTPServer:
    rpc = RPCMethods(node)
    httpd = ThreadingHTTPServer((host, port), make_handler(rpc, auth))
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def call(host: str, port: int, method: str, params=None,
         auth: str | None = None):
    """Client helper used by alpha-cli / alphaweb."""
    import base64
    import urllib.request
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params or []}).encode()
    headers = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = ("Basic " + base64.b64encode(
            auth.encode()).decode())
    req = urllib.request.Request(f"http://{host}:{port}/", data=body,
                                 headers=headers)
    with urllib.request.urlopen(req, timeout=600) as resp:
        out = json.loads(resp.read())
    if out.get("error"):
        raise RPCError(out["error"]["code"], out["error"]["message"])
    return out.get("result")


def get_cookie(datadir: str) -> str | None:
    """Read a bitcoind-style .cookie file ("user:pass")."""
    try:
        with open(os.path.join(datadir, ".cookie")) as f:
            return f.read().strip()
    except OSError:
        return None


def make_cookie(datadir: str) -> str:
    """Create the cookie file if missing (bitcoind behavior)."""
    import secrets
    path = os.path.join(datadir, ".cookie")
    existing = get_cookie(datadir)
    if existing:
        return existing
    os.makedirs(datadir, exist_ok=True)
    cred = f"__cookie__:{secrets.token_hex(32)}"
    with open(path, "w") as f:
        f.write(cred)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return cred
