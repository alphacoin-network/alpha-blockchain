"""The full node: blockchain + mempool + wallet + P2P.

Handles Bitcoin's message flow:
  version/verack handshake -> headers sync (getheaders/headers)
  -> inventory relay (inv/getdata/tx/block) -> mempool.
"""

import os
import threading
import time

from . import constants, miner, net
from .block import Block
from .blockchain import Blockchain, ChainError
from .mempool import Mempool, MempoolError
from .tokens import TokenDB
from .transaction import Transaction
from .wallet import Wallet


class Node:
    def __init__(self, params=None, data_dir: str | None = None,
                 port: int | None = None, listen: bool = True):
        self.params = params or constants.MAINNET
        self.port = port or self.params.default_port
        self.data_dir = data_dir
        if data_dir:
            os.makedirs(data_dir, exist_ok=True)
        self.start_time = int(time.time())
        # token layer: index every connected/disconnected block
        self.tokens = TokenDB()
        self.chain = Blockchain(
            self.params,
            os.path.join(data_dir, "chain") if data_dir else None,
            autoload=False)
        self.chain.on_block_connected = (
            lambda b, e, lookup: self.tokens.apply_block(b, e.height, lookup))
        self.chain.on_block_disconnected = (
            lambda e: self.tokens.unapply_block(e.height))
        self.chain.load()   # replay stored blocks (fires the token hook too)
        self.mempool = Mempool(self.chain)
        wallet_path = os.path.join(data_dir, "wallet.json") if data_dir else None
        self.wallet = Wallet(self.params, wallet_path)
        self.peers: list = []
        self.peers_lock = threading.RLock()
        self.stopped = False
        self.server = None
        self._syncing = False
        if listen:
            self.server = net.PeerServer(self, "0.0.0.0", self.port)
            self.server.start()

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def stop(self) -> None:
        self.stopped = True
        if self.server:
            self.server.close()
        with self.peers_lock:
            for p in self.peers:
                p.close()

    def connect(self, ip: str, port: int) -> bool:
        return net.connect_peer(self, ip, port) is not None

    def register_peer(self, peer) -> None:
        with self.peers_lock:
            self.peers.append(peer)

    def on_peer_disconnect(self, peer) -> None:
        with self.peers_lock:
            if peer in self.peers:
                self.peers.remove(peer)

    def broadcast_peers(self, command: str, payload: bytes) -> None:
        with self.peers_lock:
            for p in self.peers:
                p.send(command, payload)

    # ------------------------------------------------------------------
    # message dispatch
    # ------------------------------------------------------------------
    def on_message(self, peer, command: str, payload: bytes) -> None:
        handler = getattr(self, f"_msg_{command}", None)
        if handler is None:
            return
        try:
            handler(peer, payload)
        except (ChainError, MempoolError, ValueError, KeyError, IndexError):
            peer.send("reject", net.pack_reject(command, 0x10, "invalid"))

    def _msg_version(self, peer, payload: bytes) -> None:
        peer.peer_version = net.unpack_version(payload)
        if not peer.handshake_done:
            peer.send("verack")
            if peer.inbound:
                peer.send_version()

    def _msg_verack(self, peer, payload: bytes) -> None:
        if not peer.handshake_done:
            peer.handshake_done = True
            peer.send("sendheaders")
            # headers sync once handshaken
            self.request_headers(peer)

    def _msg_ping(self, peer, payload: bytes) -> None:
        peer.send("pong", payload)

    def _msg_pong(self, peer, payload: bytes) -> None:
        pass

    def _msg_inv(self, peer, payload: bytes) -> None:
        want = []
        for itype, h in net.unpack_inv(payload):
            if itype in (net.MSG_TX, net.MSG_WITNESS_TX):
                if h not in self.mempool.txs:
                    want.append((net.MSG_TX, h))
            elif itype in (net.MSG_BLOCK, net.MSG_WITNESS_BLOCK,
                           net.MSG_FILTERED_BLOCK):
                if h not in self.chain.index:
                    want.append((net.MSG_WITNESS_BLOCK, h))
        peer.getdata(want)

    def _msg_getdata(self, peer, payload: bytes) -> None:
        for itype, h in net.unpack_inv(payload):
            if itype in (net.MSG_TX, net.MSG_WITNESS_TX):
                entry = self.mempool.get(h)
                if entry:
                    peer.send("tx", entry.tx.serialize())
            elif itype in (net.MSG_BLOCK, net.MSG_WITNESS_BLOCK,
                           net.MSG_FILTERED_BLOCK):
                block = self.chain.get_block(h)
                if block:
                    peer.send("block", block.serialize())

    def _msg_tx(self, peer, payload: bytes) -> None:
        tx = Transaction.deserialize(payload)
        self.mempool.accept(tx)
        self.relay_tx(tx, exclude=peer)

    def _msg_block(self, peer, payload: bytes) -> None:
        block = Block.deserialize(payload)
        h = block.hash()
        try:
            entry = self.chain.add_block(block)
        except ChainError as e:
            if "orphan" in str(e):
                self.request_headers(peer)
            raise
        if entry is self.chain.tip:
            self.mempool.remove_for_block(block)
            # relay fresh blocks
            self.broadcast_inv([(net.MSG_BLOCK, h)], exclude=peer)

    def _msg_getheaders(self, peer, payload: bytes) -> None:
        _, locator, stop = net.unpack_getheaders(payload)
        fork = self._locator_fork(locator)
        start = fork.height + 1 if fork else 1
        headers = []
        e_height = start
        while len(headers) < 2000:
            e = self.chain.get_block_index(e_height)
            if e is None or e.hash == stop:
                break
            headers.append(e.header)
            e_height += 1
        peer.send("headers", net.pack_headers(headers))

    def _msg_headers(self, peer, payload: bytes) -> None:
        headers = net.unpack_headers(payload)
        new = False
        for hdr in headers:
            h = hdr.hash()
            if h in self.chain.index:
                continue
            # request the full block via getdata
            peer.getdata([(net.MSG_WITNESS_BLOCK, h)])
            new = True
        if len(headers) == 2000 or new:
            self.request_headers(peer)

    def _msg_getblocks(self, peer, payload: bytes) -> None:
        self._msg_getheaders(peer, payload)  # treat like getheaders

    def _msg_mempool(self, peer, payload: bytes) -> None:
        items = [(net.MSG_TX, t) for t in list(self.mempool.txs)[:50000]]
        peer.send_inv(items)

    def _msg_addr(self, peer, payload: bytes) -> None:
        for ts, services, ip, port in net.unpack_addr(payload):
            if not any(p.addr[0] == ip for p in self.peers):
                net.connect_peer(self, ip, port, timeout=5)

    def _msg_notfound(self, peer, payload: bytes) -> None:
        pass

    def _msg_reject(self, peer, payload: bytes) -> None:
        pass

    def _msg_sendheaders(self, peer, payload: bytes) -> None:
        pass

    # ------------------------------------------------------------------
    # sync / relay helpers
    # ------------------------------------------------------------------
    def _locator_fork(self, locator: list):
        for h in locator:
            entry = self.chain.index.get(h)
            if (entry is not None and entry.height < len(self.chain.active)
                    and self.chain.active[entry.height].hash == h):
                return entry
        return self.chain.active[0] if self.chain.active else None

    def request_headers(self, peer) -> None:
        locator = self.chain.block_locator()
        peer.send("getheaders", net.pack_getheaders(net.PROTOCOL_VERSION,
                                                    locator))

    def broadcast_inv(self, items, exclude=None) -> None:
        with self.peers_lock:
            for p in self.peers:
                if p is not exclude and p.handshake_done:
                    p.send_inv(items)

    def relay_tx(self, tx: Transaction, exclude=None) -> None:
        self.broadcast_inv([(net.MSG_TX, tx.txid())], exclude=exclude)

    def submit_tx(self, tx: Transaction) -> int:
        fee = self.mempool.accept(tx)
        self.relay_tx(tx)
        return fee

    def submit_block(self, block: Block) -> None:
        entry = self.chain.add_block(block)
        self.mempool.remove_for_block(block)
        self.broadcast_inv([(net.MSG_BLOCK, block.hash())])

    # ------------------------------------------------------------------
    # mining
    # ------------------------------------------------------------------
    def generate_block(self, payout_script: bytes) -> Block:
        block = miner.create_block_template(self.chain, self.mempool,
                                            payout_script)
        if not miner.mine_block(block, self.params.pow_limit_bits):
            raise ChainError("failed to find PoW")
        self.submit_block(block)
        return block

    def get_block_template(self, payout_script: bytes) -> Block:
        return miner.create_block_template(self.chain, self.mempool,
                                           payout_script)
