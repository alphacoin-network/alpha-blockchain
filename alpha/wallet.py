"""Wallet: key management (WIF), addresses, coin selection, and signing.

Supports the same key/address machinery as Bitcoin:
  * WIF private keys (Base58Check, compressed/uncompressed)
  * P2PKH legacy addresses, P2SH-wrapped P2WPKH, native bech32 P2WPKH
  * largest-first coin selection with change handling
  * ECDSA signing (legacy sighash + BIP143 for segwit inputs)
"""

import base64
import json
import os
from dataclasses import dataclass

from . import constants, crypto, script
from .base58 import b58decode_check, b58encode_check
from .bech32 import encode_segwit_address
from .transaction import (
    SIGHASH_ALL, OutPoint, Transaction, TxIn, TxOut,
)
from .utils import hash160, ser_varstr, sha256d

ADDRTYPE_LEGACY = "legacy"              # P2PKH  ("1...")
ADDRTYPE_P2SH_SEGWIT = "p2sh-segwit"    # P2SH-P2WPKH ("3...")
ADDRTYPE_BECH32 = "bech32"              # P2WPKH ("alpha1...")
ADDRTYPE_TAPROOT = "taproot"            # P2TR   ("alpha1p...")

# Signed-message prefix (Bitcoin uses "Bitcoin Signed Message:\n")
MESSAGE_PREFIX = b"Alpha Signed Message:\n"


def _iv_for(pubkey: bytes) -> bytes:
    """Per-key AES IV, like Bitcoin's use of the pubkey hash."""
    return hash160(pubkey)[:16]


def _p2tr_program_from_pubkey(pub: bytes) -> bytes:
    """P2TR output program (x-only tweaked key) from any pubkey bytes."""
    from . import crypto as _c
    from .transaction import hashlib_tagged
    p = _c.parse_pubkey(pub)
    if p[1] & 1:
        p = _c.point_neg(p)
    t = int.from_bytes(hashlib_tagged("TapTweak", p[0].to_bytes(32, "big")),
                       "big") % _c.ORDER_N
    q = _c.point_add(p, _c.point_mul(t))
    return q[0].to_bytes(32, "big")


def _p2tr_script_from_pubkey(pub: bytes) -> bytes:
    return b"\x51\x20" + _p2tr_program_from_pubkey(pub)


def _scripts_for_pubkey(pub: bytes):
    """All standard scriptPubKeys for a pubkey (all spend types)."""
    h = hash160(pub)
    return (script.script_p2pkh(h), script.script_p2wpkh(h),
            script.script_p2sh(hash160(script.script_p2wpkh(h))),
            _p2tr_script_from_pubkey(pub))


# ---------------------------------------------------------------------------
# WIF
# ---------------------------------------------------------------------------
def wif_encode(priv: int, params, compressed: bool = True) -> str:
    payload = bytes([params.base58_secret_key]) + priv.to_bytes(32, "big")
    if compressed:
        payload += b"\x01"
    return b58encode_check(payload)


def wif_decode(wif: str, params):
    payload = b58decode_check(wif)
    if payload[0] != params.base58_secret_key:
        raise ValueError("wrong WIF network prefix")
    if len(payload) == 34 and payload[-1] == 0x01:
        return int.from_bytes(payload[1:33], "big"), True
    if len(payload) == 33:
        return int.from_bytes(payload[1:33], "big"), False
    raise ValueError("bad WIF payload")


# ---------------------------------------------------------------------------
# Wallet
# ---------------------------------------------------------------------------
@dataclass
class WalletKey:
    priv: int
    compressed: bool = True

    @property
    def pubkey_point(self):
        return crypto.pubkey_from_privkey(self.priv)

    @property
    def pubkey(self) -> bytes:
        return crypto.serialize_pubkey(self.pubkey_point, self.compressed)

    @property
    def pubkey_hash(self) -> bytes:
        return hash160(self.pubkey)

    @property
    def redeem_p2wpkh(self) -> bytes:
        return script.script_p2wpkh(self.pubkey_hash)

    @property
    def script_p2pkh(self) -> bytes:
        return script.script_p2pkh(self.pubkey_hash)

    @property
    def script_p2wpkh(self) -> bytes:
        return script.script_p2wpkh(self.pubkey_hash)

    @property
    def script_p2sh_p2wpkh(self) -> bytes:
        return script.script_p2sh(hash160(self.redeem_p2wpkh))

    def address(self, addrtype: str, params) -> str:
        if addrtype == ADDRTYPE_LEGACY:
            return b58encode_check(
                bytes([params.base58_pubkey_address]) + self.pubkey_hash)
        if addrtype == ADDRTYPE_P2SH_SEGWIT:
            return b58encode_check(
                bytes([params.base58_script_address])
                + hash160(self.redeem_p2wpkh))
        if addrtype == ADDRTYPE_BECH32:
            return encode_segwit_address(params.bech32_hrp, 0,
                                         self.pubkey_hash)
        if addrtype == ADDRTYPE_TAPROOT:
            return encode_segwit_address(
                params.bech32_hrp, 1, _p2tr_program_from_pubkey(self.pubkey))
        raise ValueError(f"unknown address type {addrtype}")

    def scripts(self):
        """All scriptPubKeys this key can spend."""
        return (self.script_p2pkh, self.script_p2wpkh,
                self.script_p2sh_p2wpkh,
                _p2tr_script_from_pubkey(self.pubkey))


class WalletLocked(Exception):
    pass


class Wallet:
    def __init__(self, params=None, path: str | None = None):
        self.params = params or constants.MAINNET
        self.path = path
        self.keys: list[WalletKey] = []          # plaintext keys (unencrypted)
        self.encrypted_keys: list[dict] = []     # {"pubkey","crypted"}
        self.encrypted = False
        self._salt = b""
        self._rounds = 25000
        self._mkey = b""                          # encrypted master key
        self._master = None                       # unlocked master key
        self._unlocked: list[WalletKey] = []      # decrypted keys in memory
        self._unlock_until = 0
        self.hd_seed = None                        # BIP32 seed (if HD wallet)
        self.hd_index = 0                          # next derivation index
        if path and os.path.exists(path):
            self._load()

    # -- encryption state -------------------------------------------------------
    def is_encrypted(self) -> bool:
        return self.encrypted

    def is_locked(self) -> bool:
        if not self.encrypted:
            return False
        return self.unlock_remaining() <= 0

    def unlock_remaining(self) -> int:
        import time as _t
        return max(0, int(self._unlock_until - _t.time())) if self._unlocked else 0

    def _active_keys(self) -> list:
        """Keys usable for spending/signing right now."""
        if not self.encrypted:
            return self.keys
        if self.is_locked():
            raise WalletLocked("wallet is locked (use walletpassphrase)")
        return self._unlocked

    def all_key_records(self) -> list:
        """All known key objects (for balance/address listing)."""
        return self._unlocked if self.encrypted else self.keys

    # -- persistence --------------------------------------------------------------
    def _load(self) -> None:
        with open(self.path) as f:
            data = json.load(f)
        if data.get("encrypted"):
            self.encrypted = True
            self._salt = bytes.fromhex(data["salt"])
            self._rounds = data["rounds"]
            self._mkey = bytes.fromhex(data["mkey"])
            self.encrypted_keys = [
                {"pubkey": bytes.fromhex(e["pubkey"]),
                 "crypted": bytes.fromhex(e["crypted"])}
                for e in data["keys"]]
            return
        if data.get("hd_seed"):
            self.hd_seed = bytes.fromhex(data["hd_seed"])
            self.hd_index = data.get("hd_index", 0)
        for wif in data.get("keys", []):
            priv, comp = wif_decode(wif, self.params)
            self.keys.append(WalletKey(priv, comp))

    def save(self) -> None:
        if not self.path:
            return
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        if self.encrypted:
            data = {
                "version": 1, "encrypted": True,
                "salt": self._salt.hex(), "rounds": self._rounds,
                "mkey": self._mkey.hex(),
                "keys": [{"pubkey": e["pubkey"].hex(),
                          "crypted": e["crypted"].hex()}
                         for e in self.encrypted_keys],
            }
        else:
            data = {"keys": [wif_encode(k.priv, self.params, k.compressed)
                             for k in self.keys]}
            if self.hd_seed is not None:
                data["hd_seed"] = self.hd_seed.hex()
                data["hd_index"] = self.hd_index
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        try:
            os.chmod(tmp, 0o600)   # private keys: owner-only file
        except OSError:
            pass
        os.replace(tmp, self.path)

    # -- encryption ops (Bitcoin: encryptwallet/walletpassphrase/walletlock) --------
    def encrypt(self, passphrase: str) -> None:
        """encryptwallet: encrypts all keys and rewrites the wallet file."""
        from . import aes
        import secrets
        if self.encrypted:
            raise ValueError("wallet already encrypted")
        self._salt = secrets.token_bytes(8)
        kek, iv = aes.derive_key_iv(passphrase.encode(), self._salt,
                                    self._rounds)
        master = secrets.token_bytes(32)
        self._mkey = aes.cbc_encrypt(master, kek, iv)
        enc_keys = []
        for k in self.keys:
            ivk = _iv_for(k.pubkey)
            enc_keys.append({"pubkey": k.pubkey,
                             "crypted": aes.cbc_encrypt(
                                 k.priv.to_bytes(32, "big"), master, ivk)})
        self._master = master
        self._unlocked = self.keys
        self.encrypted_keys = enc_keys
        self.keys = []
        self.encrypted = True
        self._unlock_until = 0  # locked until walletpassphrase
        self._unlocked = []     # encryptwallet leaves it locked (like Core)
        self._master = None
        self.save()

    def unlock(self, passphrase: str, timeout: int = 60) -> None:
        """walletpassphrase: decrypt keys into memory for `timeout` seconds."""
        import time as _t
        from . import aes
        if not self.encrypted:
            raise ValueError("wallet is not encrypted")
        kek, iv = aes.derive_key_iv(passphrase.encode(), self._salt,
                                    self._rounds)
        try:
            master = aes.cbc_decrypt(self._mkey, kek, iv)
            keys = []
            for e in self.encrypted_keys:
                priv = int.from_bytes(
                    aes.cbc_decrypt(e["crypted"], master,
                                    _iv_for(e["pubkey"])), "big")
                k = WalletKey(priv, len(e["pubkey"]) == 33)
                if k.pubkey != e["pubkey"]:
                    raise ValueError("bad passphrase")
                keys.append(k)
        except (ValueError, IndexError):
            raise ValueError("bad passphrase")
        self._master = master
        self._unlocked = keys
        self._unlock_until = _t.time() + timeout

    def lock(self) -> None:
        """walletlock: purge decrypted keys from memory."""
        self._master = None
        self._unlocked = []
        self._unlock_until = 0

    def change_passphrase(self, old: str, new: str) -> None:
        """walletpassphrasechange: re-encrypt the master key."""
        from . import aes
        if not self.encrypted:
            raise ValueError("wallet is not encrypted")
        if self.is_locked():
            self.unlock(old, 60)
        else:
            # verify the old passphrase even while unlocked
            kek, iv = aes.derive_key_iv(old.encode(), self._salt, self._rounds)
            if aes.cbc_decrypt(self._mkey, kek, iv) != self._master:
                raise ValueError("bad passphrase")
        import secrets
        self._salt = secrets.token_bytes(8)
        kek, iv = aes.derive_key_iv(new.encode(), self._salt, self._rounds)
        self._mkey = aes.cbc_encrypt(self._master, kek, iv)
        self.save()

    # -- keys / addresses -----------------------------------------------------
    def init_hd(self, seed: bytes | None = None) -> "HDKey":
        """Initialize BIP32 HD wallet. Returns the master xpub key."""
        from . import bip32
        import secrets
        self.hd_seed = seed or secrets.token_bytes(32)
        self.hd_index = 0
        self.save()
        return bip32.HDKey.from_seed(self.hd_seed)

    def _hd_key(self) -> "HDKey | None":
        from . import bip32
        if self.hd_seed is None:
            return None
        return bip32.HDKey.from_seed(self.hd_seed)

    def new_key(self, compressed: bool = True) -> WalletKey:
        # HD wallet: derive m/0'/0'/i chain (external addresses)
        if self.hd_seed is not None and not self.encrypted:
            node = self._hd_key().derive(f"m/0'/0'/{self.hd_index}")
            self.hd_index += 1
            k = WalletKey(node.priv, compressed)
            self.keys.append(k)
            self.save()
            return k
        if self.encrypted:
            if self.is_locked():
                raise WalletLocked("wallet is locked")
            from . import aes
            k = WalletKey(crypto.generate_privkey(), compressed)
            self.encrypted_keys.append({
                "pubkey": k.pubkey,
                "crypted": aes.cbc_encrypt(
                    k.priv.to_bytes(32, "big"), self._master,
                    _iv_for(k.pubkey))})
            self._unlocked.append(k)
            self.save()
            return k
        k = WalletKey(crypto.generate_privkey(), compressed)
        self.keys.append(k)
        self.save()
        return k

    def import_wif(self, wif: str) -> WalletKey:
        priv, comp = wif_decode(wif, self.params)
        if any(k.priv == priv for k in self.all_key_records()):
            raise ValueError("key already in wallet")
        if self.encrypted:
            if self.is_locked():
                raise WalletLocked("wallet is locked")
            from . import aes
            k = WalletKey(priv, comp)
            self.encrypted_keys.append({
                "pubkey": k.pubkey,
                "crypted": aes.cbc_encrypt(
                    priv.to_bytes(32, "big"), self._master,
                    _iv_for(k.pubkey))})
            self._unlocked.append(k)
            self.save()
            return k
        k = WalletKey(priv, comp)
        self.keys.append(k)
        self.save()
        return k

    def export_wif(self, address: str) -> str:
        k = self._key_for_address(address)
        if k is None:
            raise ValueError("address not in wallet")
        return wif_encode(k.priv, self.params, k.compressed)

    def new_address(self, addrtype: str = ADDRTYPE_BECH32) -> str:
        """Generate a fresh key and return its address (like getnewaddress)."""
        return self.new_key().address(addrtype, self.params)

    def _watched_scripts(self):
        """script -> WalletKey|None map for ALL watched addresses.

        For encrypted+locked wallets the key is None (balance still shows,
        spending raises WalletLocked) -- mirrors bitcoind behavior.
        """
        out = {}
        if self.encrypted:
            unlocked = {k.pubkey: k for k in self._unlocked}
            for e in self.encrypted_keys:
                pub = e["pubkey"]
                for spk in _scripts_for_pubkey(pub):
                    out[spk] = unlocked.get(pub)
        else:
            for k in self.keys:
                for spk in k.scripts():
                    out[spk] = k
        return out

    def addresses(self):
        out = []
        for k in self.all_key_records():
            for t in (ADDRTYPE_LEGACY, ADDRTYPE_P2SH_SEGWIT,
                      ADDRTYPE_BECH32, ADDRTYPE_TAPROOT):
                out.append(k.address(t, self.params))
        if not out and self.encrypted:
            # locked: derive addresses from stored pubkeys
            for e in self.encrypted_keys:
                pub = e["pubkey"]
                h = hash160(pub)
                redeem = script.script_p2wpkh(h)
                out.append(b58encode_check(
                    bytes([self.params.base58_pubkey_address]) + h))
                out.append(b58encode_check(
                    bytes([self.params.base58_script_address])
                    + hash160(redeem)))
                out.append(encode_segwit_address(
                    self.params.bech32_hrp, 0, h))
        return out

    def _key_for_address(self, address: str) -> WalletKey | None:
        for k in self._active_keys():
            for t in (ADDRTYPE_LEGACY, ADDRTYPE_P2SH_SEGWIT,
                      ADDRTYPE_BECH32, ADDRTYPE_TAPROOT):
                if k.address(t, self.params) == address:
                    return k
        # fall back: maybe locked but address is ours
        if self.encrypted:
            for e in self.encrypted_keys:
                pub = e["pubkey"]
                h = hash160(pub)
                if address in (
                        b58encode_check(
                            bytes([self.params.base58_pubkey_address]) + h),
                        b58encode_check(
                            bytes([self.params.base58_script_address])
                            + hash160(script.script_p2wpkh(h))),
                        encode_segwit_address(
                            self.params.bech32_hrp, 0, h)):
                    raise WalletLocked("wallet is locked")
        return None

    def _key_for_script(self, spk: bytes) -> WalletKey | None:
        return self._watched_scripts().get(spk)

    # -- balance / utxos ------------------------------------------------------
    def list_unspent(self, chain, min_conf: int = 0) -> list:
        """All UTXOs owned by this wallet on the active chain."""
        tip_height = chain.height
        watched = self._watched_scripts()
        out = []
        for (txid, n), coin in chain.utxo.items():
            if coin.txout.script_pubkey not in watched:
                continue
            key = watched[coin.txout.script_pubkey]
            conf = tip_height - coin.height + 1 if coin.height >= 0 else 0
            if coin.height < 0:
                conf = 0
            if conf < min_conf:
                continue
            # coinbase outputs need > coinbase_maturity confirmations
            if coin.is_coinbase and conf <= self.params.coinbase_maturity:
                continue
            out.append({
                "txid": txid,
                "vout": n,
                "value": coin.txout.value,
                "script": coin.txout.script_pubkey,
                "key": key,
                "confirmations": conf,
                "coinbase": coin.is_coinbase,
            })
        return out

    def balance(self, chain, min_conf: int = 1) -> int:
        return sum(u["value"] for u in self.list_unspent(chain, min_conf))

    # -- transaction creation --------------------------------------------------
    def create_transaction(self, chain, outputs: list, fee_rate: int = 1,
                           change_addrtype: str = ADDRTYPE_BECH32,
                           first_input_script: bytes | None = None) -> Transaction:
        """outputs: list of (script_pubkey, value) or (address, value).

        Coin selection: largest confirmed UTXOs first. Change returns to a
        fresh wallet output of `change_addrtype`. If `first_input_script` is
        given, the first input is forced to spend one of its outputs (needed
        for token ops where the sender's address carries meaning).
        """
        parsed = []
        total_out = 0
        for dest, value in outputs:
            spk = (dest if isinstance(dest, bytes)
                   else script.script_for_address(dest, self.params))
            if value < 0 or value > constants.MAX_MONEY:
                raise ValueError("bad output value")
            parsed.append(TxOut(value, spk))
            total_out += value

        candidates = self.list_unspent(chain, min_conf=1)
        selected = []
        if first_input_script is not None:
            forced = next((u for u in candidates
                           if u["script"] == first_input_script), None)
            if forced is None:
                raise ValueError("no spendable output at that address")
            selected.append(forced)
            candidates.remove(forced)
        candidates.sort(key=lambda u: u["value"], reverse=True)

        in_sum = sum(u["value"] for u in selected)
        # rough size: overhead + ~148/in legacy or ~68/in segwit + ~34/out
        est_weight = 40 + len(parsed) * 34 * 4
        for u in selected:
            est_weight += (68 if u["script"] != u["key"].script_p2pkh
                           else 148) * 4
        for u in candidates:
            est_fee = (est_weight + 3) // 4 * fee_rate
            if in_sum >= total_out + est_fee:
                break
            selected.append(u)
            in_sum += u["value"]
            est_weight += (68 if u["script"] != u["key"].script_p2pkh
                           else 148) * 4
        est_fee = (est_weight + 3) // 4 * fee_rate
        if in_sum < total_out + est_fee:
            raise ValueError("insufficient funds")
        change = in_sum - total_out - est_fee
        if change > 546:  # dust limit (~P2PKH dust threshold)
            change_key = next((k for k in self.all_key_records()), None)
            if change_key is None:
                raise WalletLocked("no change key available")
            if change_addrtype == ADDRTYPE_TAPROOT:
                change_spk = _p2tr_script_from_pubkey(change_key.pubkey)
            else:
                change_spk = getattr(change_key, {
                    ADDRTYPE_LEGACY: "script_p2pkh",
                    ADDRTYPE_P2SH_SEGWIT: "script_p2sh_p2wpkh",
                    ADDRTYPE_BECH32: "script_p2wpkh",
                }[change_addrtype])
            parsed.append(TxOut(change, change_spk))
        else:
            # dust change goes to the miner as extra fee
            pass

        tx = Transaction(
            version=constants.TX_VERSION,
            vin=[TxIn(prevout=OutPoint(u["txid"], u["vout"]),
                      sequence=constants.SEQUENCE_FINAL)
                 for u in selected],
            vout=parsed,
            locktime=0,
        )
        if any(u["key"] is None for u in selected):
            raise WalletLocked("wallet is locked (use walletpassphrase)")
        self.sign(tx, [u["script"] for u in selected],
                  [u["value"] for u in selected],
                  [u["key"] for u in selected])
        return tx

    def sign(self, tx: Transaction, prev_scripts: list, values: list,
             keys: list) -> None:
        """Sign all inputs of `tx` with the matching wallet keys."""
        all_prevouts = {"amounts": list(values), "spks": list(prev_scripts)}
        for i in range(len(tx.vin)):
            self.sign_input(tx, i, prev_scripts[i], values[i], keys[i],
                            all_prevouts)

    @staticmethod
    def sign_input(tx: Transaction, i: int, spk: bytes, value: int,
                   key: WalletKey,
                   all_prevouts: dict | None = None) -> None:
        """Sign a single input (usable on partially-owned transactions)."""
        txin = tx.vin[i]
        typ, data = script.solver(spk)
        if typ == script.TX_PUBKEYHASH:
            if key.pubkey_hash != data:
                raise ValueError("key does not own this P2PKH output")
            sighash = tx.signature_hash(spk, i, SIGHASH_ALL)
            sig = crypto.ecdsa_sign_der(sighash, key.priv) + b"\x01"
            txin.script_sig = (script.push_data(sig)
                               + script.push_data(key.pubkey))
        elif typ == script.TX_PUBKEY:
            if key.pubkey != data:
                raise ValueError("key does not own this P2PK output")
            sighash = tx.signature_hash(spk, i, SIGHASH_ALL)
            sig = crypto.ecdsa_sign_der(sighash, key.priv) + b"\x01"
            txin.script_sig = script.push_data(sig)
        elif typ == script.TX_WITNESS_V0_KEYHASH:
            if key.pubkey_hash != data:
                raise ValueError("key does not own this P2WPKH output")
            code = script.script_p2pkh(data)
            sighash = tx.signature_hash_v0(code, i, value, SIGHASH_ALL)
            sig = crypto.ecdsa_sign_der(sighash, key.priv) + b"\x01"
            txin.witness = [sig, key.pubkey]
            txin.script_sig = b""
        elif typ == script.TX_WITNESS_V1_TAPROOT:
            from . import schnorr
            tweaked = schnorr.taproot_tweak(key.priv)
            if schnorr.xonly_pubkey(tweaked) != data:
                raise ValueError("key does not own this P2TR output")
            if all_prevouts is None:
                all_prevouts = {"amounts": [value], "spks": [spk]}
            sighash = tx.signature_hash_v1(
                i, all_prevouts["amounts"], all_prevouts["spks"], 0x00)
            txin.witness = [schnorr.schnorr_sign(sighash, tweaked)]
            txin.script_sig = b""
        elif typ == script.TX_SCRIPTHASH:
            # P2SH-wrapped P2WPKH
            redeem = key.redeem_p2wpkh
            if script.script_p2sh(hash160(redeem)) != spk:
                raise ValueError("unsupported P2SH redeem script")
            code = script.script_p2pkh(key.pubkey_hash)
            sighash = tx.signature_hash_v0(code, i, value, SIGHASH_ALL)
            sig = crypto.ecdsa_sign_der(sighash, key.priv) + b"\x01"
            txin.witness = [sig, key.pubkey]
            txin.script_sig = script.push_data(redeem)
        else:
            raise ValueError(f"wallet cannot sign script type {typ}")

    # -- convenience ------------------------------------------------------------
    def send_to_address(self, chain, mempool, address: str, value: int,
                        fee_rate: int = 1) -> Transaction:
        tx = self.create_transaction(chain, [(address, value)], fee_rate)
        if mempool is not None:
            mempool.accept(tx)
        return tx

    # -- token / OP_RETURN transactions -------------------------------------------
    def create_token_op_tx(self, chain, payload: bytes,
                           signer_address: str,
                           recipient_address: str | None = None,
                           value: int = 546, fee_rate: int = 1) -> Transaction:
        """Build an ALP token transaction.

        Output 0 pays `value` sats to the recipient (the token "owner"); the
        ALP payload rides in an OP_RETURN output. The first input is forced
        to come from `signer_address` so the protocol sees that address as
        the sender/issuer.
        """
        signer_spk = script.script_for_address(signer_address, self.params)
        if recipient_address is None:
            recipient_spk = signer_spk
        else:
            recipient_spk = script.script_for_address(recipient_address,
                                                      self.params)
        outputs = [(recipient_spk, value),
                   (script.script_op_return(payload), 0)]
        return self.create_transaction(
            chain, outputs, fee_rate, first_input_script=signer_spk)

    # -- signed messages (Bitcoin format) ------------------------------------------
    def sign_message(self, address: str, message: str) -> str:
        """Bitcoin-compatible compact signed message (base64, 65 bytes)."""
        key = self._key_for_address(address)
        if key is None:
            raise ValueError("address not in wallet")
        z = sha256d(ser_varstr(MESSAGE_PREFIX)
                    + ser_varstr(message.encode("utf-8")))
        r, s = crypto.ecdsa_sign(z, key.priv)
        pub = key.pubkey_point
        recid = next(i for i in range(4)
                     if crypto.ecdsa_recover(z, r, s, i) == pub)
        header = 27 + recid + (4 if key.compressed else 0)
        raw = bytes([header]) + r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return base64.b64encode(raw).decode()


def verify_message(address: str, signature_b64: str, message: str,
                   params) -> bool:
    """Verify a compact signed message against a P2PKH address."""
    try:
        raw = base64.b64decode(signature_b64)
        if len(raw) != 65:
            return False
        header = raw[0]
        if not 27 <= header <= 34:
            return False
        recid = (header - 27) & 3
        compressed = bool((header - 27) & 4)
        r = int.from_bytes(raw[1:33], "big")
        s = int.from_bytes(raw[33:65], "big")
        z = sha256d(ser_varstr(MESSAGE_PREFIX)
                    + ser_varstr(message.encode("utf-8")))
        q = crypto.ecdsa_recover(z, r, s, recid)
        if q is None:
            return False
        pubkey = crypto.serialize_pubkey(q, compressed)
        spk = script.script_p2pkh(hash160(pubkey))
        return script.extract_destination(spk, params) == address
    except (ValueError, IndexError):
        return False
