#!/usr/bin/env python3
"""stratum_miner — reference stratum mining client for Alpha.

Connects to an alphad stratum server (:8335), authorizes with your ALPHA
payout address, grinds nonces on all CPU threads and submits shares —
the same protocol real mining software uses.

Usage:
    python stratum_miner.py --host 68.178.163.58 --port 8335 \
        --address alpha1q... --threads 8
"""
import argparse
import json
import socket
import struct
import sys
import threading
import time
from hashlib import sha256

from alpha.transaction import Transaction
from alpha.utils import compact_to_target


def dsha(b: bytes) -> bytes:
    return sha256(sha256(b).digest()).digest()


class StratumMiner:
    def __init__(self, host, port, address, threads):
        self.host, self.port, self.address = host, port, address
        self.nthreads = threads
        self.sock = None
        self.job = None              # latest notify
        self.eno2 = 0
        self.submitted = set()       # (jobid, nonce) already tried
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.blocks_found = 0

    # -- wire ------------------------------------------------------------
    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), 10)
        self.sock.settimeout(None)
        self._send({"id": 1, "method": "mining.subscribe",
                    "params": ["stratum_miner/1.0"]})
        self._send({"id": 2, "method": "mining.extranonce.subscribe",
                    "params": []})
        self._send({"id": 3, "method": "mining.authorize",
                    "params": [self.address, "x"]})
        threading.Thread(target=self._reader, daemon=True).start()

    def _send(self, obj):
        self.sock.sendall((json.dumps(obj) + "\n").encode())

    def _reader(self):
        buf = b""
        while not self.stop.is_set():
            try:
                data = self.sock.recv(65536)
            except OSError:
                break
            if not data:
                break
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    self._dispatch(json.loads(line))
                except Exception as e:
                    print("dispatch error:", e)

    def _dispatch(self, msg):
        # notify: [null, jobid, prevhash, coinb1, coinb2, branch[], ver, bits, ntime, clean]
        if isinstance(msg, list) and len(msg) > 8 and msg[0] is None \
                and isinstance(msg[1], str):
            with self.lock:
                self.eno2 = (self.eno2 + 1) & 0xFFFFFFFF
                self.job = {
                    "id": msg[1], "prev": msg[2], "coinb1": msg[3],
                    "coinb2": msg[4], "branch": msg[5], "eno2": self.eno2,
                    "version": int(msg[6], 16), "bits": int(msg[7], 16),
                    "ntime": int(msg[8], 16),
                }
            return
        # replies: dicts
        if isinstance(msg, dict):
            res = msg.get("result")
            if msg.get("id") == 3:
                print("authorize:", "OK" if res else "FAILED")
                if not res:
                    self.stop.set()
            elif msg.get("id") is None and res is True:
                self.blocks_found += 1
                print(f"*** BLOCK FOUND #{self.blocks_found} ***")
            elif msg.get("id") is None and res is False:
                print("share rejected:", msg.get("error"))

    # -- mining -----------------------------------------------------------
    def _header_prefix(self, job):
        """First 76 bytes of the block header for this job."""
        cb = Transaction.deserialize(
            bytes.fromhex(job["coinb1"]) +
            job["eno2"].to_bytes(4, "big") +
            bytes.fromhex(job["coinb2"]))
        # merkle root: coinbase txid + branch (coinbase is always leftmost)
        root = cb.txid()
        for h in job["branch"]:
            sib = bytes.fromhex(h)[::-1]
            root = dsha(root + sib)
        prev = bytes.fromhex(job["prev"])[::-1]
        # 76-byte prefix: version+prevhash+merkle+time+bits (nonce patched later)
        return (struct.pack("<i", job["version"]) + prev + root
                + struct.pack("<II", job["ntime"], job["bits"]))

    def _worker(self, tid):
        target = None
        prefix = None
        jid = None
        n = tid
        while not self.stop.is_set():
            with self.lock:
                job = self.job
            if job is None:
                time.sleep(0.2)
                continue
            if job["id"] != jid:
                jid = job["id"]
                prefix = self._header_prefix(job)
                target = compact_to_target(job["bits"])
                n = tid
            buf = bytearray(prefix + b"\x00\x00\x00\x00")  # 80 bytes total
            while n < 0x100000000 and not self.stop.is_set():
                buf[76] = n & 0xFF
                buf[77] = (n >> 8) & 0xFF
                buf[78] = (n >> 16) & 0xFF
                buf[79] = (n >> 24) & 0xFF
                if int.from_bytes(dsha(bytes(buf)), "little") <= target:
                    self._submit(jid, n)
                    break
                n += self.nthreads
            # nonce space done for this job — wait for next notify
            time.sleep(0.05)

    def _submit(self, jid, nonce):
        with self.lock:
            job = self.job
            if job is None or job["id"] != jid:
                return
            eno2 = job["eno2"].to_bytes(4, "big").hex()
            ntime = "%08x" % job["ntime"]
        self._send({"id": None, "method": "mining.submit",
                    "params": ["w0", jid, eno2, ntime, "%08x" % nonce]})

    def run(self):
        self.connect()
        threads = [threading.Thread(target=self._worker, args=(i,),
                                    daemon=True)
                   for i in range(self.nthreads)]
        for t in threads:
            t.start()
        try:
            while not self.stop.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop.set()
            try:
                self.sock.close()
            except Exception:
                pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8335)
    ap.add_argument("--address", required=True)
    ap.add_argument("--threads", type=int, default=4)
    a = ap.parse_args()
    StratumMiner(a.host, a.port, a.address, a.threads).run()


if __name__ == "__main__":
    main()
