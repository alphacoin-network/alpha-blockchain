#!/usr/bin/env python3
"""mine_alpha — CPU miner for the Alpha mainnet (like early Bitcoin mining).

Usage:
    python alphad.py --chain main --datadir ./data-mainnet     # node (auto-connects to seeds)
    python mine_alpha.py                                      # mine forever to your wallet
    python mine_alpha.py --threads 8 --maxtries 20000000      # 8 threads, refresh ~every minute

Each thread grinds a unique coinbase extranonce, so no two threads ever
hash the same work. Rewards go to your payout address.
Requires a running local alphad (default rpc :8332).
"""
import sys, json, time, urllib.request, base64, argparse, os, threading


def rpc_call(host, port, method, params, cookie):
    req = urllib.request.Request(
        f"http://{host}:{port}",
        data=json.dumps({"jsonrpc": "2.0", "id": 1,
                         "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Basic " + base64.b64encode(
                     cookie.encode()).decode()})
    r = json.loads(urllib.request.urlopen(req, timeout=600).read())
    if r["error"]:
        raise RuntimeError(r["error"])
    return r["result"]


def miner_thread(tid, args, addr, cookie, stop_evt, print_lock, stats):
    """One mining thread — unique extranonce => unique template."""
    extranonce = tid
    while not stop_evt.is_set():
        try:
            t0 = time.time()
            rpc_call(args.rpchost, args.rpcport, "generatetoaddress",
                     [1, addr, extranonce, args.maxtries], cookie)
            with print_lock:
                stats["blocks"] += 1
                h = rpc_call(args.rpchost, args.rpcport, "getblockcount",
                             [], cookie)
                print(f"[{time.strftime('%H:%M:%S')}] thread-{tid} mined "
                      f"#{stats['blocks']} | height {h} | "
                      f"{args.maxtries/(time.time()-t0)/1e6:.2f} MH/s")
        except Exception as e:
            # maxtries exhausted or stale template -> next extranonce
            with print_lock:
                print(f"[{time.strftime('%H:%M:%S')}] thread-{tid}: {e}")
        extranonce += args.threads


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpchost", default="127.0.0.1")
    ap.add_argument("--rpcport", type=int, default=8332)
    ap.add_argument("--datadir", default="./data-mainnet")
    ap.add_argument("--address", default=None,
                    help="payout address (default: node wallet)")
    ap.add_argument("--threads", type=int, default=1,
                    help="parallel grinding threads = CPU cores to use")
    ap.add_argument("--maxtries", type=int, default=20_000_000,
                    help="nonce tries per template before refresh")
    ap.add_argument("--blocks", type=int, default=0,
                    help="stop after N blocks total (0 = forever)")
    a = ap.parse_args()

    cookie = open(os.path.join(a.datadir, ".cookie")).read().strip()
    addr = a.address or rpc_call(a.rpchost, a.rpcport, "getnewaddress",
                                 [], cookie)
    print(f"Alpha miner | {a.threads} thread(s) | paying rewards to {addr}")
    print(f"node {a.rpchost}:{a.rpcport} | Ctrl+C to stop")

    stop_evt = threading.Event()
    print_lock = threading.Lock()
    stats = {"blocks": 0}
    threads = [threading.Thread(target=miner_thread,
                                args=(i, a, addr, cookie, stop_evt,
                                      print_lock, stats), daemon=True)
               for i in range(a.threads)]
    for t in threads:
        t.start()

    try:
        while not stop_evt.is_set():
            time.sleep(5)
            if a.blocks and stats["blocks"] >= a.blocks:
                stop_evt.set()
    except KeyboardInterrupt:
        pass
    finally:
        stop_evt.set()
        for t in threads:
            t.join(timeout=2)
        print("\nstopped.")


if __name__ == "__main__":
    main()
