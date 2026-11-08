#!/usr/bin/env python3
"""alphad -- the Alpha Blockchain daemon (like bitcoind).

Usage:
    python alphad.py --chain regtest --datadir ./data --rpcport 18443
    python alphad.py --connect 127.0.0.1:18444 --connect node2:8333
"""

import argparse
import sys
import time

from alpha import constants, rpc
from alpha.node import Node


def main() -> int:
    p = argparse.ArgumentParser(prog="alphad", description="Alpha daemon")
    p.add_argument("--chain", default="regtest",
                   choices=["main", "test", "regtest"],
                   help="which network to run (default: regtest)")
    p.add_argument("--datadir", default=None,
                   help="data directory (default: ./data-<chain>)")
    p.add_argument("--port", type=int, default=None,
                   help="P2P listen port")
    p.add_argument("--rpcport", type=int, default=None,
                   help="JSON-RPC port")
    p.add_argument("--connect", action="append", default=[],
                   metavar="IP:PORT", help="connect to a peer at startup")
    p.add_argument("--nolisten", action="store_true",
                   help="don't accept inbound P2P connections")
    args = p.parse_args()

    params = constants.NETWORKS[args.chain]
    datadir = args.datadir or f"./data-{params.name}"
    port = args.port or params.default_port
    rpcport = args.rpcport or {
        "main": 8332, "test": 18332, "regtest": 18443,
    }[params.name]

    node = Node(params, datadir, port=port, listen=not args.nolisten)
    auth = rpc.make_cookie(datadir)
    print(f"Alpha node started | chain={params.name} height={node.chain.height} "
          f"| p2p=:{port} rpc=:{rpcport} datadir={datadir}")

    for target in args.connect:
        if ":" in target:
            ip, prt = target.rsplit(":", 1)
            ok = node.connect(ip, int(prt))
        else:
            ok = node.connect(target, params.default_port)
        print(f"connect {target}: {'ok' if ok else 'failed'}")

    rpc.serve(node, "127.0.0.1", rpcport, auth=auth)

    try:
        while not node.stopped:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        node.stop()
        print("stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
