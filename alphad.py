#!/usr/bin/env python3
"""alphad -- the Alpha Blockchain daemon (like bitcoind).

Usage:
    python alphad.py --chain regtest --datadir ./data --rpcport 18443
    python alphad.py --connect 127.0.0.1:18444 --connect node2:8333
"""

import argparse
import io
import os
import signal
import sys
import tarfile
import time
import urllib.request

from alpha import constants, rpc
from alpha.node import Node

sys.setrecursionlimit(10000)  # deep catch-up orphan chains / nested parses


BOOTSTRAP_URL = "http://68.178.163.58:8080/bootstrap.tar.gz"


def _install_signal_handlers() -> None:
    """SIGTERM/SIGINT -> KeyboardInterrupt so the finally-block runs
    node.stop() (clean peer/socket/DB shutdown instead of a hard kill)."""
    def _handler(signum, frame):
        raise KeyboardInterrupt
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):
            pass  # not in main thread / unsupported platform


def _fatal(msg: str):
    print(f"FATAL: {msg}", file=sys.stderr)
    sys.exit(1)


def _maybe_bootstrap(datadir: str) -> None:
    """Download the public chain snapshot into a fresh datadir."""
    chain_dir = os.path.join(datadir, "chain")
    blocks = os.path.join(chain_dir, "blocks.dat")
    if os.path.exists(blocks) and os.path.getsize(blocks) > 0:
        return  # already has chain data — normal sync
    try:
        print("downloading chain bootstrap snapshot…")
        with urllib.request.urlopen(BOOTSTRAP_URL, timeout=60) as r:
            blob = r.read()
        os.makedirs(chain_dir, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            # snapshot contains <dir>/chain/blocks.dat (+ txindex.db)
            for member in tf.getmembers():
                parts = member.name.split("/")
                if len(parts) >= 3 and parts[-2] == "chain":
                    member.name = parts[-1]
                    tf.extract(member, chain_dir)
                elif member.name.endswith("txindex.db"):
                    member.name = "txindex.db"
                    tf.extract(member, datadir)
        print("bootstrap loaded — starting near chain tip")
    except Exception as e:
        print(f"bootstrap unavailable ({e}) — syncing from genesis")


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
    p.add_argument("--nobootstrap", action="store_true",
                   help="don't download the chain bootstrap snapshot")
    args = p.parse_args()

    params = constants.NETWORKS[args.chain]
    datadir = args.datadir or f"./data-{params.name}"

    # Fast-sync bootstrap (like Bitcoin's assumeutxo snapshot): if this is a
    # fresh mainnet datadir, download the latest chain snapshot so the node
    # starts near the tip instead of syncing from genesis.
    if params.name == "main" and not args.nobootstrap:
        _maybe_bootstrap(datadir)
    port = args.port or params.default_port
    rpcport = args.rpcport or {
        "main": 8332, "test": 18332, "regtest": 18443,
    }[params.name]

    proxy = tuple(args.proxy.rsplit(":", 1)) if args.proxy else None
    if proxy:
        proxy = (proxy[0], int(proxy[1]))
    tor_ctl = tuple(args.torcontrol.rsplit(":", 1))
    tor_ctl = (tor_ctl[0], int(tor_ctl[1]))

    _install_signal_handlers()

    try:
        node = Node(params, datadir, port=port, listen=not args.nolisten,
                    proxy=proxy, onion=args.onion, tor_control=tor_ctl)
    except PermissionError as e:
        _fatal(f"cannot write to datadir '{datadir}': {e}\n"
               "  → check folder permissions or choose another --datadir")
    except OSError as e:
        if getattr(e, "errno", None) in (98, 10048, 48, 98):  # EADDRINUSE
            _fatal(f"P2P port {port} is already in use — another alphad "
                   "is probably running on this machine.\n"
                   "  → stop it, or start this one with --port <other>")
        _fatal(f"network error while starting node: {e}")
    except Exception as e:  # noqa: BLE001
        _fatal(f"node failed to start: {e}\n"
               "  → if the datadir is corrupt, move it aside and re-sync "
               "(bootstrap snapshot will be downloaded again)")
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
        try:
            stratum.serve(node, args.strataport)
        except OSError as e:
            node.stop()
            _fatal(f"stratum port {args.strataport} is already in use: {e}")

    try:
        rpc.serve(node, "127.0.0.1", rpcport, auth=auth)
    except OSError as e:
        node.stop()
        _fatal(f"RPC port {rpcport} is already in use — another alphad "
               "is probably running. Stop it or use --rpcport <other>: {e}")

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
