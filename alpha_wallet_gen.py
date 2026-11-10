#!/usr/bin/env python3
"""alpha_wallet_gen — generate an Alpha address + private key (WIF)
   without running a node. For community onboarding / airdrops.

   Usage:  python alpha_wallet_gen.py [--chain main|regtest] [--type bech32|legacy|taproot] [--count N]

   SAVE THE WIF PRIVATE KEY — it IS your coins. Never share it.
"""
import sys, secrets, argparse
sys.path.insert(0, ".")
from alpha import constants
from alpha.wallet import WalletKey, wif_encode, ADDRTYPE_LEGACY, ADDRTYPE_BECH32, ADDRTYPE_TAPROOT

CHAINS = {"main": constants.MAINNET, "test": constants.TESTNET, "regtest": constants.REGTEST}
TYPES = {"legacy": ADDRTYPE_LEGACY, "bech32": ADDRTYPE_BECH32, "taproot": ADDRTYPE_TAPROOT}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--chain", default="main", choices=CHAINS)
    p.add_argument("--type", default="bech32", choices=TYPES)
    p.add_argument("--count", type=int, default=1)
    a = p.parse_args()
    params = CHAINS[a.chain]

    print("=" * 64)
    print("  ALPHA WALLET — new address(es)")
    print("  SAVE the WIF private key safely. Whoever has it owns the coins.")
    print("=" * 64)
    for i in range(a.count):
        k = WalletKey(priv=secrets.randbelow(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140) + 1)
        print(f"\nAddress #{i+1}")
        print(f"  Address     : {k.address(TYPES[a.type], params)}")
        print(f"  Private WIF : {wif_encode(k.priv, params)}")
        print(f"  Pubkey      : {k.pubkey.hex()}")
    print("\n" + "=" * 64)

if __name__ == "__main__":
    main()
