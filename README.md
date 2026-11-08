# Alpha Blockchain

A faithful, dependency-free reimplementation of **Bitcoin's technology and
logic** in pure Python. The coin (ALPHA) works exactly like Bitcoin (BTC):
same supply, same issuance schedule, same proof-of-work, same UTXO model,
same Script, same wire formats.

No third-party packages — everything (secp256k1 ECDSA, RIPEMD-160, SHA-256d,
Base58Check, Bech32, Script interpreter, P2P protocol) is implemented from
the specs.

## Run it

```bash
# start the daemon (regtest is the easy-difficulty local chain)
python alphad.py --chain regtest --datadir ./data --rpcport 18443 --port 18444

# CLI (like bitcoin-cli)
python alpha_cli.py getnewaddress bech32
python alpha_cli.py generatetoaddress 101 <address>
python alpha_cli.py getbalance
python alpha_cli.py sendtoaddress <address> 1.5
python alpha_cli.py getblockchaininfo

# connect a second node
python alphad.py --chain regtest --datadir ./data2 --rpcport 19443 --port 18445
python alpha_cli.py --rpcport 19443 addnode 127.0.0.1:18444
```

Networks: `--chain main` (Bitcoin-identical economics, difficulty-1 genesis),
`--chain test`, `--chain regtest` (trivial PoW + 150-block halving like
Bitcoin Core regtest, for local testing).

## Bitcoin equivalence

| Feature | Bitcoin | Alpha |
|---|---|---|
| Max supply | 21,000,000 BTC | 21,000,000 ALPHA |
| Smallest unit | 1 satoshi (10⁻⁸) | 1 alphasat (10⁻⁸) |
| Actual total issued | 20,999,999.9769 | identical |
| Block subsidy | 50 → halving every 210,000 blocks | identical |
| Block time | 10 minutes | identical |
| Difficulty retarget | every 2016 blocks, ±4× clamp | identical |
| PoW | SHA-256d(header) ≤ target(nBits) | identical |
| Block header | 80 B: version, prev, merkle, time, bits, nonce | byte-identical |
| Coinbase maturity | 100 blocks | identical |
| Max block weight | 4,000,000 WU | identical |
| Curve / signatures | secp256k1 + ECDSA + DER | identical (pure Python) |
| Nonce generation | RFC 6979 deterministic, low-S | identical |
| Address types | Base58 P2PKH/P2SH, bech32 segwit | identical formats |
| Private keys | WIF Base58Check | identical |
| Script | full interpreter: P2PK, P2PKH, P2SH, multisig, OP_RETURN | identical semantics |
| Timelocks | nLockTime, CLTV (BIP65), CSV (BIP112), RBF flag | identical |
| Sighash | legacy ALL/NONE/SINGLE/ANYONECANPAY + BIP143 | identical (incl. SINGLE bug) |
| SegWit | BIP141: witness serialization, wtxid, commitment, P2WPKH/P2WSH | identical |
| P2P wire | magic + command + checksum framing; version/verack/inv/getdata/tx/block/headers/getheaders/ping/addr | identical format |
| Mempool | script-verify, finality, RBF replacement | same policy |
| Reorgs | most-chainwork wins | identical rule |
| Genesis quirk | coinbase output unspendable | reproduced |

Extras on top of Bitcoin: the **ALP token protocol** (Omni-style assets via
OP_RETURN — anyone can issue/mint/send/burn tokens), **signed messages**
(signmessage/verifymessage), **SPV merkle proofs** (gettxoutproof), a
**bitcoind-style REST API**, and a full **website + block explorer**
(`alphaweb.py`).

Not implemented (yet): Taproot/BIP340-342, HD wallets (BIP32), bloom
filters, compact blocks, pruning, fee estimation, descriptor wallets,
wallet encryption.

## Tokens (ALP protocol)

```bash
python alpha_cli.py createtoken MyToken 8 1000000      # issue -> token_id
python alpha_cli.py listtokens                          # registry
python alpha_cli.py sendtoken <token_id> <addr> 100     # transfer
python alpha_cli.py gettokenbalance <token_id>          # balances
python alpha_cli.py minttoken <token_id> 500            # issuer only
python alpha_cli.py burntoken <token_id> 50
```

Token state is indexed by a deterministic layer over the base chain —
decentralized, anyone can build on it.

## Website + Explorer

```bash
python alphad.py --chain regtest --datadir ./data    # node on :18443
python alphaweb.py --port 8080                        # site on :8080
```

Landing page with 3D ALPHA coin, live network stats, block explorer,
token registry and full API docs.

## Layout

```
alpha/
  constants.py    consensus constants + chain params (main/test/regtest)
  utils.py        serialization, varints, nBits<->target, pure-py RIPEMD-160
  crypto.py       secp256k1 ECDSA, RFC6979, DER, low-S
  base58.py       Base58Check
  bech32.py       Bech32/Bech32m (BIP173/350)
  script.py       Script engine: opcodes, P2SH, witness programs, CLTV/CSV
  transaction.py  UTXO tx model, legacy + segwit serialization, sighash
  block.py        header, merkle trees, witness commitment
  blockchain.py   UTXO set, full validation, retarget, reorgs, genesis
  mempool.py      unconfirmed tx policy + RBF
  miner.py        block template (BIP34 coinbase) + PoW loop
  wallet.py       keys, WIF, addresses, coin selection, signing
  net.py          Bitcoin P2P wire protocol
  node.py         full node (chain + mempool + peers + wallet)
  tokens.py       ALP token protocol + deterministic indexer
  merkleproof.py  partial merkle trees (SPV proofs)
  rpc.py          bitcoind-style JSON-RPC + /rest/ endpoints
alphad.py         daemon entry point
alpha_cli.py      CLI client
alphaweb.py       website + explorer server
website/          full site (index/explorer/tokens/api) + 3D coin logo
tests/            34 tests incl. real Bitcoin known-answer vectors
```

## Tests

```bash
python -m unittest discover -s tests -v
```

Includes the ultimate compatibility check: rebuilding **Bitcoin's real
genesis block** from our primitives and matching its known hash
`000000000019d6...ce26f`, plus Satoshi's address, known WIF/address/bech32
vectors, the exact 20,999,999.9769 total supply, live mining, spends,
reorgs, and P2P sync between two nodes.
