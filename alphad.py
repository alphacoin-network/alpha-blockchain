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
    p.add_argument("--proxy", default=None, metavar="IP:PORT",
                   help="route outbound through SOCKS5 proxy (Tor: 127.0.0.1:9050)")
    p.add_argument("--onion", action="store_true",
                   help="create a Tor hidden service via --torcontrol")
    p.add_argument("--torcontrol", default="127.0.0.1:9051",
                   metavar="IP:PORT", help="Tor control port")
    p.add_argument("--torpassword", default=None,
                   help="Tor control password (if not cookie auth)")
    p.add_argument("--prune", type=int, default=0,
                   help="keep only the last N block bodies (0=off)")
    p.add_argument("--stratum", action="store_true",
                   help="run the stratum mining server (for external miners)")
    p.add_argument("--strataport", type=int, default=8335,
                   help="stratum TCP port (default 8335)")
    args = p.parse_args()

    params = constants.NETWORKS[args.chain]
    datadir = args.datadir or f"./data-{params.name}"
    port = args.port or params.default_port
    rpcport = args.rpcport or {
        "main": 8332, "test": 18332, "regtest": 18443,
    }[params.name]

    proxy = tuple(args.proxy.rsplit(":", 1)) if args.proxy else None
    if proxy:
        proxy = (proxy[0], int(proxy[1]))
    tor_ctl = tuple(args.torcontrol.rsplit(":", 1))
    tor_ctl = (tor_ctl[0], int(tor_ctl[1]))

    node = Node(params, datadir, port=port, listen=not args.nolisten,
                proxy=proxy, onion=args.onion, tor_control=tor_ctl)
    auth = rpc.make_cookie(datadir)
    onion_msg = f" | onion={node.onion_addr}" if node.onion_addr else ""
    print(f"Alpha node started | chain={params.name} height={node.chain.height} "
          f"| p2p=:{port} rpc=:{rpcport} datadir={datadir}{onion_msg}")

    # auto-connect to public seed nodes (like Bitcoin's DNS seeds), plus
    # any explicit --connect peers
    # LAN auto-discovery — find & connect local nodes even with no internet
    node.start_lan_discovery()
    targets = list(args.connect) + [s for s in params.seed_nodes
                                  if s not in args.connect]
    for target in targets:
        if ":" in target:
            ip, prt = target.rsplit(":", 1)
            ok = node.connect(ip, int(prt))
        else:
            ok = node.connect(target, params.default_port)
        print(f"connect {target}: {'ok' if ok else 'failed'}")

    if args.stratum:
        from alpha import stratum
        stratum.serve(node, args.strataport)

    rpc.serve(node, "127.0.0.1", rpcport, auth=auth)

    try:
        prune_every = 0
        reconnect_every = 0
        while not node.stopped:
            time.sleep(1)
            # if we lost all peers, retry seed nodes every ~60s
            reconnect_every += 1
            if reconnect_every >= 60:
                reconnect_every = 0
                if not node.peers:
                    for s in params.seed_nodes:
                        node.connect(s, params.default_port)
            if args.prune:
                prune_every += 1
                if prune_every >= 60:
                    prune_every = 0
                    node.chain.prune(keep_blocks=args.prune)
    except KeyboardInterrupt:
        pass
    finally:
        node.stop()
        print("stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
