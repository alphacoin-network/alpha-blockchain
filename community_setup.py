#!/usr/bin/env python3
"""community_setup — create the 5-member Alpha community reserve.

Generates:
  * 5 member wallets (each member keeps their own WIF private key)
  * A 3-of-5 multisig reserve address — NO single member can spend alone,
    any 3 of 5 must sign (trustless community fund, like a board)
  * An allocation plan: 25% of total supply (5,250,000 ALPHA) reserved
    for the community, 75% released by Bitcoin-style mining.

Usage:  python community_setup.py [--chain main|regtest]
"""
import sys, json, secrets, argparse
sys.path.insert(0, ".")
from alpha import constants
from alpha.wallet import WalletKey, wif_encode, ADDRTYPE_BECH32
from alpha.base58 import b58encode_check
from alpha.utils import hash160
from alpha import script

CHAINS = {"main": constants.MAINNET, "test": constants.TESTNET,
          "regtest": constants.REGTEST}
TOTAL_SUPPLY = 21_000_000
RESERVE_PCT = 25
MEMBERS = 5
REQUIRED_SIGS = 3

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--chain", default="main", choices=CHAINS)
    a = p.parse_args()
    params = CHAINS[a.chain]
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    members = []
    for i in range(MEMBERS):
        k = WalletKey(priv=secrets.randbelow(N - 1) + 1)
        members.append({
            "member": i + 1,
            "address": k.address(ADDRTYPE_BECH32, params),
            "pubkey": k.pubkey.hex(),
            "wif": wif_encode(k.priv, params),
        })

    redeem = script.script_multisig(
        REQUIRED_SIGS, [bytes.fromhex(m["pubkey"]) for m in members])
    reserve_addr = b58encode_check(
        bytes([params.base58_script_address]) + hash160(redeem))

    reserve_total = TOTAL_SUPPLY * RESERVE_PCT // 100   # 5,250,000
    plan = {
        "network": params.name,
        "total_supply": TOTAL_SUPPLY,
        "reserve_pct": RESERVE_PCT,
        "reserve_alpha": reserve_total,
        "mined_supply": TOTAL_SUPPLY - reserve_total,
        "reserve_address": reserve_addr,
        "reserve_type": f"{REQUIRED_SIGS}-of-{MEMBERS} multisig (P2SH)",
        "redeem_script": redeem.hex(),
        "per_member_equal_share": reserve_total // MEMBERS,
        "members": members,
    }

    out = f"community_{params.name}.json"
    with open(out, "w") as f:
        json.dump(plan, f, indent=2)

    print("=" * 66)
    print(f"  ALPHA COMMUNITY — {MEMBERS} members · {params.name.upper()}")
    print("=" * 66)
    for m in members:
        print(f"\nMember {m['member']}")
        print(f"  Address : {m['address']}")
        print(f"  WIF     : {m['wif']}   <-- MEMBER KEEPS SECRET")
    print(f"""
{'-' * 66}
RESERVE (3-of-5 multisig — any 3 members must approve a spend):
  {reserve_addr}

ALLOCATION
  Total supply      : {TOTAL_SUPPLY:>12,} ALPHA
  Community reserve : {reserve_total:>12,} ALPHA  (25%, held in multisig)
  Mining release    : {TOTAL_SUPPLY - reserve_total:>12,} ALPHA  (75%, Bitcoin schedule)
  Per member share  : {reserve_total // MEMBERS:>12,} ALPHA (when distributed)

Saved to {out} — keep it PRIVATE (contains member WIF keys).
{'=' * 66}""")

if __name__ == "__main__":
    main()
