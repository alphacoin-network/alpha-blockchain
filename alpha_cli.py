#!/usr/bin/env python3
"""alpha-cli -- command line client for alphad (like bitcoin-cli).

Usage:
    python alpha_cli.py --chain regtest getblockcount
    python alpha_cli.py getnewaddress bech32
    python alpha_cli.py sendtoaddress <addr> 1.5
    python alpha_cli.py generatetoaddress 101 <addr>
"""

import argparse
import json
import sys

from alpha import rpc


def main() -> int:
    p = argparse.ArgumentParser(prog="alpha-cli")
    p.add_argument("--chain", default="regtest",
                   choices=["main", "test", "regtest"])
    p.add_argument("--rpcport", type=int, default=None)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--datadir", default=None,
                   help="node datadir for .cookie auth")
    p.add_argument("method", nargs="?", default="help")
    p.add_argument("params", nargs="*")
    args = p.parse_args()

    rpcport = args.rpcport or {
        "main": 8332, "test": 18332, "regtest": 18443,
    }[args.chain]
    datadir = args.datadir or f"./data-{args.chain}"
    auth = rpc.get_cookie(datadir) or rpc.get_cookie("./demo-data")

    if args.method == "help":
        methods = sorted(m for m in dir(rpc.RPCMethods)
                         if not m.startswith("_"))
        print("Available RPC methods:")
        for m in methods:
            print(" ", m)
        return 0

    params = []
    for x in args.params:
        try:
            params.append(json.loads(x))
        except (ValueError, json.JSONDecodeError):
            params.append(x)
    try:
        result = rpc.call(args.host, rpcport, args.method, params,
                          auth=auth)
    except rpc.RPCError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"error connecting to alphad: {e}", file=sys.stderr)
        return 1

    if isinstance(result, (dict, list)):
        print(json.dumps(result, indent=2))
    else:
        print(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
