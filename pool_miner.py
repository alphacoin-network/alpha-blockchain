#!/usr/bin/env python3
"""pool_miner — CPU mining client for the Alpha pool (getwork/submitwork).

Fetches pool work templates from a local alphad over RPC, grinds nonces
on all CPU threads and submits share candidates. The pool credits each
miner pro-rata; when the pool wins a block the reward (subsidy + fees)
is distributed automatically after coinbase maturity.

Usage:
    python pool_miner.py --datadir ./data --address alpha1q...
    python pool_miner.py --rpchost 127.0.0.1 --rpcport 8332 \
        --datadir ./data --address alpha1q... --threads 4
"""
import argparse
import base64
import hashlib
import json
import os
import sys
import threading
import time
import urllib.request


def dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def rpc_call(host, port, method, params, cookie, timeout=60):
    req = urllib.request.Request(
        f"http://{host}:{port}",
        data=json.dumps({"jsonrpc": "2.0", "id": 1,
                         "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Basic " + base64.b64encode(
                     cookie.encode()).decode()})
    r = json.loads(urllib.request.urlopen(req, timeout=timeout).read())
    if r.get("error"):
        raise RuntimeError(str(r["error"]))
    return r["result"]


class PoolMiner:
    REFRESH_SECS = 20          # getwork rate limit is 1/5s per address

    def __init__(self, args, cookie, addr):
        self.args = args
        self.cookie = cookie
        self.addr = addr
        self.job = None          # {"workid","hdr","pool_tb","block_tb","exp"}
        self.job_lock = threading.Lock()
        self.submit_lock = threading.Lock()
        self.stop = threading.Event()
        self.stats = {"shares": 0, "blocks": 0, "hashes": 0}
        self.stats_lock = threading.Lock()

    # -- work ---------------------------------------------------------
    def refresh_work(self):
        w = rpc_call(self.args.rpchost, self.args.rpcport, "getwork",
                     [self.addr, True], self.cookie)
        hdr = bytearray.fromhex(w["data"]) + b"\x00" * 4
        with self.job_lock:
            self.job = {
                "workid": w["workid"],
                "hdr": hdr,
                "pool_tb": int(w["pool_target"], 16).to_bytes(32, "big"),
                "block_tb": int(w["target"], 16).to_bytes(32, "big"),
                "exp": time.time() + self.REFRESH_SECS,
                "height": w.get("height"),
            }
        print(f"[{time.strftime('%H:%M:%S')}] new work: height "
              f"{w.get('height')} target {w['target'][:16]}…")

    def _current_job(self):
        with self.job_lock:
            return self.job

    # -- mining threads -------------------------------------------------
    def worker(self, tid):
        nonce = tid * 0x10000000    # stagger start, stride below
        pending = []
        while not self.stop.is_set():
            job = self._current_job()
            if job is None or time.time() > job["exp"]:
                time.sleep(0.5)
                continue
            pool_tb = job["pool_tb"]
            block_tb = job["block_tb"]
            wid = job["workid"]
            hdr = bytearray(job["hdr"])   # private copy per batch
            # grind a batch of nonces for this job
            for _ in range(self.args.batch):
                if self.stop.is_set():
                    break
                nonce = (nonce + self.args.threads) & 0xFFFFFFFF
                hdr[76:80] = nonce.to_bytes(4, "little")
                # reversed digest — same convention as submitwork's check
                digest = dsha(bytes(hdr))[::-1]
                with self.stats_lock:
                    self.stats["hashes"] += 1
                if digest <= pool_tb:
                    pending.append(nonce)
                    with self.stats_lock:
                        self.stats["shares"] += 1
                        if digest <= block_tb:
                            self.stats["blocks"] += 1
                            print(f"[{time.strftime('%H:%M:%S')}] thread-{tid}: "
                                  f"BLOCK solution! submitting")
            self._flush(wid, pending)
            pending = []

    def _flush(self, wid, nonces):
        if not nonces:
            return
        try:
            with self.submit_lock:
                out = rpc_call(self.args.rpchost, self.args.rpcport,
                               "submitwork", [wid, nonces], self.cookie,
                               timeout=120)
            acc = out.get("shares_accepted", 0)
            if out.get("stale"):
                with self.job_lock:
                    if self.job and self.job["workid"] == wid:
                        self.job["exp"] = 0     # force refresh
            if acc or out.get("accepted"):
                print(f"[{time.strftime('%H:%M:%S')}] submitted "
                      f"{len(nonces)} share(s) -> accepted {acc}"
                      + (" | BLOCK ACCEPTED" if out.get("accepted") else ""))
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] submitwork error: {e}")

    def refresher(self):
        while not self.stop.is_set():
            self.stop.wait(self.REFRESH_SECS)   # run() already fetched once
            try:
                self.refresh_work()
            except Exception as e:
                print(f"[{time.strftime('%H:%M:%S')}] getwork error: {e} "
                      f"— retrying in 10s")
                self.stop.wait(10)
                continue

    def run(self):
        self.refresh_work()
        threads = [threading.Thread(target=self.worker, args=(i,),
                                    daemon=True)
                   for i in range(self.args.threads)]
        for t in threads:
            t.start()
        threading.Thread(target=self.refresher, daemon=True).start()
        try:
            while not self.stop.is_set():
                self.stop.wait(30)
                h = self.stats["hashes"]
                rate = h / 30 / 1e6
                self.stats["hashes"] = 0
                with self.job_lock:
                    j = self.job
                print(f"[{time.strftime('%H:%M:%S')}] ~{rate:.2f} MH/s | "
                      f"shares {self.stats['shares']} | "
                      f"blocks {self.stats['blocks']} | "
                      f"h={j and j.get('height')}")
        except KeyboardInterrupt:
            pass
        finally:
            self.stop.set()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpchost", default="127.0.0.1")
    ap.add_argument("--rpcport", type=int, default=8332)
    ap.add_argument("--datadir", default="./data-mainnet")
    ap.add_argument("--address", default=None,
                    help="miner address for share credit")
    ap.add_argument("--threads", type=int, default=0,
                    help="0 = ~75% of cores")
    ap.add_argument("--batch", type=int, default=20000,
                    help="nonces grinded per job check per thread")
    a = ap.parse_args()

    try:
        cores = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        cores = os.cpu_count() or 1
    if a.threads <= 0:
        a.threads = max(1, int(cores * 0.75))

    try:
        with open(os.path.join(a.datadir, ".cookie")) as f:
            cookie = f.read().strip()
    except OSError:
        print(f"FATAL: cannot read RPC cookie '{a.datadir}/.cookie' — "
              f"is alphad running with --datadir {a.datadir}?")
        return 1

    try:
        addr = a.address or rpc_call(a.rpchost, a.rpcport, "getnewaddress",
                                     [], cookie, timeout=60)
    except Exception as e:
        print(f"FATAL: cannot reach node {a.rpchost}:{a.rpcport} — {e}")
        return 1

    print(f"Alpha pool miner | {a.threads} thread(s) on {cores} core(s) | "
          f"credit -> {addr}")
    print(f"node {a.rpchost}:{a.rpcport} | Ctrl+C to stop")
    PoolMiner(a, cookie, addr).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
