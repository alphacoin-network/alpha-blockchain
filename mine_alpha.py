#!/usr/bin/env python3
"""mine_alpha — solo CPU miner for the Alpha mainnet (like early Bitcoin mining).

Usage:
    python alphad.py --chain main --datadir ./data-mainnet     # node (auto-connects to seeds)
    python mine_alpha.py                                      # mine forever to your wallet
    python mine_alpha.py --address alpha1q... --interval 30   # custom

Requires a running local alphad (default rpc :8332).
"""
import sys, json, time, urllib.request, base64, argparse, os

def rpc_call(host, port, method, params, cookie):
    req = urllib.request.Request(
        f"http://{host}:{port}",
        data=json.dumps({"jsonrpc": "2.0", "id": 1,
                         "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Basic " + base64.b64encode(
                     cookie.encode()).decode()})
    r = json.loads(urllib.request.urlopen(req, timeout=120).read())
    if r["error"]:
        raise RuntimeError(r["error"])
    return r["result"]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpchost", default="127.0.0.1")
    ap.add_argument("--rpcport", type=int, default=8332)
    ap.add_argument("--datadir", default="./data-mainnet")
    ap.add_argument("--address", default=None,
                    help="payout address (default: node wallet)")
    ap.add_argument("--interval", type=int, default=30,
                    help="seconds between blocks (default 30)")
    ap.add_argument("--blocks", type=int, default=0,
                    help="stop after N blocks (0 = forever)")
    a = ap.parse_args()

    cookie = open(os.path.join(a.datadir, ".cookie")).read().strip()
    addr = a.address or rpc_call(a.rpchost, a.rpcport, "getnewaddress", [], cookie)
    print(f"Alpha miner | paying rewards to {addr}")
    print(f"node {a.rpchost}:{a.rpcport} | block every {a.interval}s | Ctrl+C to stop")

    n = 0
    while a.blocks == 0 or n < a.blocks:
        try:
            rpc_call(a.rpchost, a.rpcport, "generatetoaddress", [1, addr], cookie)
            n += 1
            h = rpc_call(a.rpchost, a.rpcport, "getblockcount", [], cookie)
            print(f"[{time.strftime('%H:%M:%S')}] mined #{n} | chain height {h}")
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] {e} — retrying in 60s")
            time.sleep(60)
            continue
        time.sleep(a.interval)

if __name__ == "__main__":
    main()
