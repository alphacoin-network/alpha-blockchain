"""Stratum mining protocol server — the interface real miners/ASICs use.

Solo-mining mode (no pool accounting): each connection authorizes with an
ALPHA payout address; the node serves block templates as mining.notify jobs
and accepts mined shares via mining.submit — same wire protocol as
Slushpool/ckpool, so standard stratum miners can connect directly.

Wire format: newline-delimited JSON over TCP.
  mining.subscribe / mining.extranonce.subscribe / mining.authorize /
  mining.notify (server->client) / mining.submit
"""

import json
import socket
import threading
import time

from . import constants, miner, script
from .block import Block, BlockHeader, merkle_root
from .transaction import Transaction
from .utils import (BytesReader, compact_to_target, hash_to_hex, now,
                    ser_compact_size)

STRATUM_PORT = 8335


def _display(b: bytes) -> str:
    return hash_to_hex(b)


def _merkle_branch(txids: list) -> list:
    """Sibling-hash path for tx index 0 (coinbase) up to the merkle root."""
    level = list(txids)
    branch = []
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        branch.append(_display(level[1]))
        level = [merkle_root([level[i], level[i + 1]])
                 for i in range(0, len(level), 2)]
    return branch


class StratumSession:
    def __init__(self, conn, addr, node):
        self.conn = conn
        self.addr = addr
        self.node = node
        self.sid = None                # extranonce1 (4 bytes)
        self.payout_spk = None
        self.jobs = {}                 # job_id -> job dict
        self.job_seq = 0
        self.buf = b""
        self.alive = True

    # -- helpers ---------------------------------------------------------
    def send(self, obj):
        try:
            self.conn.sendall((json.dumps(obj) + "\n").encode())
        except OSError:
            self.alive = False

    def reply(self, mid, result):
        self.send({"id": mid, "result": result, "error": None})

    def err(self, mid, code, msg):
        self.send({"id": mid, "result": None,
                   "error": {"code": code, "message": msg}})

    # -- job construction -------------------------------------------------
    def _build_job(self):
        """Create a template for this session's payout address."""
        import secrets as _sec
        params = self.node.params
        tip = self.node.chain.tip
        height = tip.height + 1
        eno1 = int.from_bytes(self.sid, "big")
        # extranonce slot: extra_data = eno1(4B) || zeros(4B); slot sits
        # immediately after the extranonce1 bytes inside the scriptSig push.
        extra = eno1.to_bytes(4, "big") + b"\x00" * 4
        need_w = any(e.tx.has_witness()
                     for e in self.node.mempool.txs.values())
        reserved = _sec.token_bytes(32) if need_w else None
        blk = self.node.get_block_template(self.payout_spk,
                                           extra_data=b"/S/" + extra,
                                           reserved=reserved)
        # fees = coinbase reward - subsidy (vout[0] carries reward+fees)
        subsidy = params.initial_subsidy >> min(
            height // params.halving_interval, constants.MAX_HALVINGS)
        fees = blk.txs[0].vout[0].value - subsidy
        txs = blk.txs[1:]
        cb = blk.txs[0]
        cb_bytes = cb.serialize(include_witness=True)
        # locate the 4-byte extranonce2 slot right after extranonce1
        pos = cb_bytes.find(self.sid)
        if pos < 0:
            raise RuntimeError("extranonce slot not found")
        slot = pos + 4
        coinb1, coinb2 = cb_bytes[:slot].hex(), cb_bytes[slot + 4:].hex()
        txids = [tx.txid() for tx in txs]
        self.job_seq += 1
        jid = f"{self.job_seq:08x}"
        self.jobs[jid] = {
            "coinb1": coinb1, "coinb2": coinb2,
            "txs": txs, "prev": tip.hash, "version": blk.header.version,
            "bits": blk.header.bits, "height": height,
            "txids": txids, "payout_spk": self.payout_spk,
            "height_num": height, "subsidy": subsidy, "fees": fees,
            "reserved": reserved, "need_witness": need_w,
            "ts": max(now(), tip.median_time_past() + 1),
        }
        if len(self.jobs) > 16:
            self.jobs.pop(next(iter(self.jobs)))
        branch = _merkle_branch([cb.txid()] + txids)
        self.send([None, jid, _display(tip.hash), coinb1, coinb2, branch,
                   "%08x" % blk.header.version, "%08x" % blk.header.bits,
                   "%08x" % self.jobs[jid]["ts"], True])
        return jid

    # -- submit -----------------------------------------------------------
    def _submit(self, params):
        try:
            _worker, jid, eno2h, ntimeh, nonceh = params[:5]
        except Exception:
            self.err(None, 20, "invalid params")
            return
        job = self.jobs.get(jid)
        if job is None:
            self.err(None, 21, "unknown job")
            return
        try:
            eno2 = bytes.fromhex(eno2h)
            if len(eno2) != 4:
                raise ValueError("extranonce2 must be 4 bytes")
            cb_bytes = bytes.fromhex(job["coinb1"]) + eno2 + \
                bytes.fromhex(job["coinb2"])
            cb = Transaction.deserialize(cb_bytes)
            root = merkle_root([cb.txid()] + job["txids"])
            hdr = BlockHeader(
                version=job["version"], prev_hash=job["prev"], merkle=root,
                timestamp=int(ntimeh, 16), bits=job["bits"],
                nonce=int(nonceh, 16))
            if not hdr.check_pow(self.node.params.pow_limit_bits):
                self.send({"id": None, "result": False, "error": None})
                return
            block = Block(hdr, [cb] + job["txs"])
            self.node.submit_block(block)
            self.send({"id": None, "result": True, "error": None})
        except Exception as e:
            self.send({"id": None, "result": False,
                       "error": {"code": 22, "message": str(e)[:120]}})

    # -- main loop ----------------------------------------------------------
    def run(self):
        tip_h, mem_n = self.node.chain.height, len(self.node.mempool.txs)
        while self.alive:
            try:
                self.conn.settimeout(0.5)
                data = self.conn.recv(65536)
                if not data:
                    break
                self.buf += data
                while b"\n" in self.buf:
                    line, self.buf = self.buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        req = json.loads(line)
                    except Exception:
                        continue
                    self._handle(req)
            except socket.timeout:
                pass
            except OSError:
                break
            # push fresh work when tip or mempool changed
            h, m = self.node.chain.height, len(self.node.mempool.txs)
            if self.payout_spk and (h != tip_h or m != mem_n):
                tip_h, mem_n = h, m
                self._build_job()

    def _handle(self, req):
        mid, method, params = req.get("id"), req.get("method"), \
            req.get("params") or []
        if method == "mining.subscribe":
            self.sid = __import__("secrets").token_bytes(4)
            self.reply(mid, [None, self.sid.hex(), 4, 4])
        elif method in ("mining.extranonce.subscribe",):
            self.reply(mid, True)
        elif method == "mining.authorize":
            user = params[0] if params else ""
            try:
                self.payout_spk = script.script_for_address(
                    user, self.node.params)
                self.reply(mid, True)
                try:
                    self._build_job()      # first job immediately
                except Exception as e:
                    self.err(mid, 23, f"job build failed: {e}")
            except Exception:
                self.reply(mid, False)
        elif method == "mining.submit":
            self._submit(params)
        elif method == "mining.get_transactions":
            self.reply(mid, [])          # segwit-tx serving not used
        else:
            self.err(mid, 1, "unsupported method")


def serve(node, port: int = STRATUM_PORT):
    """Start the stratum TCP server (call from a thread)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(64)

    def accept_loop():
        while not node.stopped:
            try:
                conn, addr = srv.accept()
            except OSError:
                break
            sess = StratumSession(conn, addr, node)
            threading.Thread(target=sess.run, daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    print(f"stratum mining server listening on :{port}")
