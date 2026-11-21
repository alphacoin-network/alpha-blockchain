#!/usr/bin/env python3
"""mine_alpha — CPU miner for the Alpha mainnet (like early Bitcoin mining).

Usage:
    python alphad.py --chain main --datadir ./data-mainnet     # node (auto-connects to seeds)
    python mine_alpha.py                                      # mine forever to your wallet
    python mine_alpha.py --threads 8 --maxtries 5000000       # 8 threads, refresh ~every minute

Each thread grinds a unique coinbase extranonce, so no two threads ever
hash the same work. Rewards go to your payout address.
Requires a running local alphad (default rpc :8332).

Hardware: by default ~75% of logical CPU cores are used (--threads 0),
leaving headroom so the OS, alphad and other apps stay responsive —
no overload, overheating or UI lag. A GPU is detected and reported,
but proof-of-work here is CPU-only — the miner automatically sizes
itself to your machine and prints clear progress + error messages.
Pass --threads N to override (e.g. --threads 8 for a dedicated box).
"""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.error
import base64
import argparse
import threading


def detect_hardware():
    """Return (logical_cores, gpu_name_or_None)."""
    try:
        cores = len(os.sched_getaffinity(0))   # respects taskset/cgroup limits
    except (AttributeError, OSError):
        cores = os.cpu_count() or 1
    gpu = None
    # NVIDIA
    if shutil.which("nvidia-smi"):
        try:
            out = subprocess.check_output(
                ["nvidia-smi", "--query-gpu=name",
                 "--format=csv,noheader"],
                timeout=8, stderr=subprocess.DEVNULL).decode().strip()
            if out:
                gpu = out.splitlines()[0].strip()
        except Exception:
            pass
    # AMD ROCm
    if gpu is None and shutil.which("rocm-smi"):
        try:
            out = subprocess.check_output(
                ["rocm-smi", "--showproductname"],
                timeout=8, stderr=subprocess.DEVNULL).decode()
            for line in out.splitlines():
                if "Card series" in line or "GPU" in line:
                    gpu = line.strip()
                    break
        except Exception:
            pass
    return max(1, cores), gpu


def friendly_error(e, host, port):
    """Turn low-level exceptions into a message a normal user understands."""
    if isinstance(e, urllib.error.URLError):
        r = getattr(e, "reason", e)
        if isinstance(r, ConnectionRefusedError) or "refused" in str(r):
            return (f"cannot reach node at {host}:{port} — is alphad "
                    f"running? (python alphad.py --chain main --datadir "
                    f"./data-main)")
        if "timed out" in str(r).lower():
            return ("node took too long to answer — the machine is busy "
                    "or the mining round is very long. Try --maxtries "
                    "5000000 or --timeout 3600")
        return f"network error: {r}"
    if isinstance(e, TimeoutError) or "timed out" in str(e).lower():
        return ("RPC timed out — lower --maxtries (shorter rounds) or "
                "raise --timeout")
    return str(e)


def rpc_call(host, port, method, params, cookie, timeout=600):
    req = urllib.request.Request(
        f"http://{host}:{port}",
        data=json.dumps({"jsonrpc": "2.0", "id": 1,
                         "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Basic " + base64.b64encode(
                     cookie.encode()).decode()})
    r = json.loads(urllib.request.urlopen(req, timeout=timeout).read())
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
                     [1, addr, extranonce, args.maxtries], cookie,
                     timeout=args.timeout)
            dt = time.time() - t0
            with print_lock:
                stats["blocks"] += 1
                h = rpc_call(args.rpchost, args.rpcport, "getblockcount",
                             [], cookie, timeout=args.timeout)
                print(f"[{time.strftime('%H:%M:%S')}] thread-{tid} mined "
                      f"#{stats['blocks']} | height {h} | "
                      f"{args.maxtries/dt/1e6:.2f} MH/s (this round)")
        except Exception as e:
            with print_lock:
                # maxtries exhausted -> next extranonce; real errors ->
                # clear message so users know what to fix
                msg = friendly_error(e, args.rpchost, args.rpcport)
                print(f"[{time.strftime('%H:%M:%S')}] thread-{tid}: {msg}")
                if isinstance(e, urllib.error.URLError) and "refused" \
                        in str(getattr(e, "reason", "")):
                    # node is down — wait longer before hammering it
                    stop_evt.wait(15)
        extranonce += args.threads


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpchost", default="127.0.0.1")
    ap.add_argument("--rpcport", type=int, default=8332)
    ap.add_argument("--datadir", default="./data-mainnet")
    ap.add_argument("--address", default=None,
                    help="payout address (default: node wallet)")
    ap.add_argument("--threads", type=int, default=0,
                    help="0 = auto: use ALL CPU cores (recommended)")
    ap.add_argument("--maxtries", type=int, default=5_000_000,
                    help="nonce tries per template before refresh "
                         "(lower = shorter RPC calls, fewer timeouts)")
    ap.add_argument("--timeout", type=int, default=1800,
                    help="RPC timeout seconds per mining round "
                         "(generatetoaddress grinds on the node)")
    ap.add_argument("--blocks", type=int, default=0,
                    help="stop after N blocks total (0 = forever)")
    a = ap.parse_args()

    cores, gpu = detect_hardware()
    if a.threads <= 0:
        # auto: ~75% of cores — leaves headroom for OS/node/other apps
        # so the machine stays stable (no overload/thermal throttle)
        a.threads = max(1, int(cores * 0.75))
    print(f"hardware: {cores} CPU core(s) -> mining with {a.threads} "
          f"thread(s)"
          + (f", GPU: {gpu}" if gpu else ", no GPU detected"))
    if gpu:
        print("note: proof-of-work mining here is CPU-only — the GPU is "
              "not used for hashing. Using all CPU cores instead.")

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
        print(f"FATAL: {friendly_error(e, a.rpchost, a.rpcport)}")
        return 1
    print(f"Alpha miner | {a.threads} thread(s) on {cores} core(s) | "
          f"paying rewards to {addr}")
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
