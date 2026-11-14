"""The full node: blockchain + mempool + wallet + P2P.

Handles Bitcoin's message flow:
  version/verack handshake -> headers sync (getheaders/headers)
  -> inventory relay (inv/getdata/tx/block) -> mempool.
"""

import os
import socket
import threading
import time

from . import constants, miner, net
from .txindex import TxIndex
from .ausd import Ausd
from .block import Block
from .blockchain import Blockchain, ChainError
from .mempool import Mempool, MempoolError
from .tokens import TokenDB
from .dex import DexDB
from .amm import AmmDB
from .identity import IdentityDB
from .web3 import Web3DB
from .ai import AiDB
from .enterprise import EntDB
from .escrow import EscrowDB
from .staking import StakeDB
from .transaction import Transaction
from .wallet import Wallet


class Node:
    def __init__(self, params=None, data_dir: str | None = None,
                 port: int | None = None, listen: bool = True,
                 proxy: tuple | None = None, onion: bool = False,
                 tor_control: tuple | None = None):
        self.params = params or constants.MAINNET
        self.port = port or self.params.default_port
        self.data_dir = data_dir
        self.proxy = proxy                    # SOCKS5 (host, port) for outbound
        self.onion_addr = None
        if onion:
            from . import tor
            ctl = tor_control or ("127.0.0.1", tor.CONTROL_PORT)
            try:
                self.onion_addr = tor.create_onion_service(self.port, ctl)
            except Exception as e:
                raise ValueError(f"tor hidden service failed: {e}")
        if data_dir:
            os.makedirs(data_dir, exist_ok=True)
        self.start_time = int(time.time())
        # token + dex layers: index every connected/disconnected block
        self.tokens = TokenDB()
        self.dex = DexDB()
        self.amm = AmmDB()
        self.identity = IdentityDB()
        self.web3 = Web3DB()
        self.ai = AiDB()
        self.enterprise = EntDB()
        self.escrow = EscrowDB()
        self.staking = StakeDB()
        self.txindex = TxIndex(self.params, data_dir)
        self.chain = Blockchain(
            self.params,
            os.path.join(data_dir, "chain") if data_dir else None,
            autoload=False)
        self.chain.on_block_connected = (
            lambda b, e, lookup: (
                self.identity.apply_block(b, e.height, lookup),
                self.tokens.apply_block(b, e.height, lookup, self.identity),
                self.dex.apply_block(b, e.height, self.tokens, lookup),
                self.amm.apply_block(b, e.height, self.tokens, lookup),
                self.web3.apply_block(b, e.height, lookup),
                self.ai.apply_block(b, e.height, lookup),
                self.enterprise.apply_block(b, e.height, lookup),
                self.escrow.apply_block(b, e.height, self.tokens, lookup),
                self.staking.apply_block(b, e.height, lookup),
                self.txindex.apply_block(b, e.height, lookup)))
        self.chain.on_block_disconnected = (
            lambda e: (
                self.staking.unapply_block(e.height),
                self.escrow.unapply_block(e.height, self.tokens),
                self.enterprise.unapply_block(e.height),
                self.ai.unapply_block(e.height),
                self.web3.unapply_block(e.height),
                self.identity.unapply_block(e.height),
                self.amm.unapply_block(e.height, self.tokens),
                self.dex.unapply_block(e.height, self.tokens),
                self.tokens.unapply_block(e.height),
                self.txindex.unapply_block(e.height)))
        self.chain.load()   # replay stored blocks (fires the token hook too)
        self.mempool = Mempool(self.chain)
        wallet_path = os.path.join(data_dir, "wallet.json") if data_dir else None
        self.wallet = Wallet(self.params, wallet_path)
        self.ausd = Ausd(self)
        self.peers: list = []
        self.peers_lock = threading.RLock()
        self.addr_pool: set = set()          # learned (ip,port) peers
        self._pending_compact: dict = {}
        self.stopped = False
        self.server = None
        self._syncing = False
        if listen:
            self.server = net.PeerServer(self, "0.0.0.0", self.port)
            self.server.start()
        threading.Thread(target=self._addr_maintainer, daemon=True).start()
        # seed the addr pool with public seeds so the maintainer has targets
        try:
            import socket as _s
            default_port = getattr(self.params, "port", 8333) or 8333
            for s in getattr(self.params, "seed_nodes", ()):
                parts = s.split(":")
                host = parts[0]
                sp = int(parts[1]) if len(parts) > 1 else default_port
                try:
                    ip = _s.gethostbyname(host)
                    self.addr_pool.add((ip, sp))
                    # same-host nodes: also try loopback (hairpin-safe)
                    if ip != "127.0.0.1":
                        self.addr_pool.add(("127.0.0.1", sp))
                except Exception:
                    pass
        except Exception:
            pass

    def _addr_maintainer(self):
        """Keep outbound connections topped up from the learned addr pool."""
        import random, time
        while not self.stopped:
            time.sleep(45)
            try:
                with self.peers_lock:
                    connected = {p.addr[0] for p in self.peers if p.addr}
                    want = 8 - len(self.peers)
                if want <= 0:
                    continue
                cands = [a for a in self.addr_pool
                         if a[0] not in connected]
                random.shuffle(cands)
                for ip, port in cands[:want]:
                    try:
                        self.connect(ip, port)
                    except Exception:
                        pass
            except Exception:
                pass

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
        return net.connect_peer(self, ip, port,
                                proxy=self.proxy) is not None

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
    # LAN peer discovery — nodes on the same local network find each
    # other via UDP broadcast, no internet/seed needed. UDP port 8334.
    # ------------------------------------------------------------------
    LAN_PORT = 8334

    def start_lan_discovery(self) -> None:
        """Broadcast 'ALPHA|<network>|<p2pport>' beacons on the LAN and
        auto-connect to other nodes we hear — works fully offline."""
        beacon = f"ALPHA|{self.params.name}|{self.port}".encode()

        def _discover():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            try:
                s.bind(("", self.LAN_PORT))
            except OSError:
                s.bind(("", 0))          # port taken — listen on ephemeral
            s.settimeout(2.0)
            last_beacon = 0.0
            while getattr(self, "_lan_on", True):
                # broadcast our presence every ~30s
                if time.time() - last_beacon > 30:
                    try:
                        s.sendto(beacon, ("255.255.255.255", self.LAN_PORT))
                        last_beacon = time.time()
                    except OSError:
                        pass
                try:
                    data, addr = s.recvfrom(128)
                except socket.timeout:
                    continue
                except OSError:
                    break
                parts = data.decode(errors="ignore").split("|")
                if (len(parts) == 3 and parts[0] == "ALPHA"
                        and parts[1] == self.params.name):
                    ip, port = addr[0], int(parts[2])
                    if ip not in self._lan_known():
                        self.connect(ip, port)   # don't re-dial known peers
            s.close()

        self._lan_on = True
        threading.Thread(target=_discover, daemon=True).start()

    def _lan_known(self):
        return {getattr(p, "host", None) for p in self.peers}

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
            peer.send("sendcmpct", net.pack_sendcmpct(announce=False))
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
            elif itype == net.MSG_FILTERED_BLOCK and \
                    getattr(peer, "bloom", None) is not None:
                block = self.chain.get_block(h)
                if block:
                    self._send_filtered_block(peer, block)
            elif itype in (net.MSG_BLOCK, net.MSG_WITNESS_BLOCK):
                block = self.chain.get_block(h)
                if block:
                    peer.send("block", block.serialize())

    def _send_filtered_block(self, peer, block) -> None:
        """BIP37: serve only the txs matching the peer's bloom filter."""
        from .merkleproof import PartialMerkleTree
        matches = set()
        for i, tx in enumerate(block.txs):
            spk_hit = any(peer.bloom.contains(o.script_pubkey)
                          for o in tx.vout)
            sig_hit = any(peer.bloom.contains(tin.prevout.serialize())
                          for tin in tx.vin)
            if spk_hit or sig_hit or tx.is_coinbase():
                matches.add(i)
        pmt = PartialMerkleTree.build([t.txid() for t in block.txs],
                                      matches)
        peer.send("merkleblock", net.pack_merkleblock(block, pmt))
        for i in sorted(matches):
            if not block.txs[i].is_coinbase():
                peer.send("tx", block.txs[i].serialize())

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
            self.addr_pool.add((ip, port))
            if len(self.addr_pool) > 2000:
                self.addr_pool = set(list(self.addr_pool)[-2000:])
            if not any(p.addr[0] == ip for p in self.peers):
                net.connect_peer(self, ip, port, timeout=5)

    def _msg_notfound(self, peer, payload: bytes) -> None:
        pass

    def _msg_reject(self, peer, payload: bytes) -> None:
        pass

    def _msg_sendheaders(self, peer, payload: bytes) -> None:
        pass

    def _msg_addrv2(self, peer, payload: bytes) -> None:
        """BIP155 variable-length network addresses."""
        for services, ip, port, ts, netid in net.unpack_addrv2(payload):
            if netid in (net.ADDRV2_IPV4, net.ADDRV2_IPV6):
                self.addr_pool.add((ip, port))
                if len(self.addr_pool) > 2000:
                    self.addr_pool = set(list(self.addr_pool)[-2000:])
                if not any(p.addr[0] == ip for p in self.peers):
                    net.connect_peer(self, ip, port, timeout=5)

    # -- bloom filters (BIP37) ---------------------------------------------------
    def _msg_filterload(self, peer, payload: bytes) -> None:
        from .utils import BytesReader
        from .filters import BloomFilter
        import struct
        r = BytesReader(payload)
        data = r.read(r.read_varint())
        peer.bloom = BloomFilter.__new__(BloomFilter)
        peer.bloom.data = bytearray(data)
        peer.bloom.n_funcs, peer.bloom.tweak = struct.unpack(
            "<II", r.read(8))
        peer.bloom.TWEAK = BloomFilter.TWEAK

    def _msg_filteradd(self, peer, payload: bytes) -> None:
        if getattr(peer, "bloom", None):
            peer.bloom.insert(payload[1:1 + payload[0]] if payload else b"")
            # actually: payload = varstr; decode
            from .utils import BytesReader
            r = BytesReader(payload)
            peer.bloom.insert(r.read(r.read_varint()))

    def _msg_filterclear(self, peer, payload: bytes) -> None:
        peer.bloom = None

    def _msg_sendcmpct(self, peer, payload: bytes) -> None:
        peer.announce, peer.cmpct_ver = net.unpack_sendcmpct(payload)
        peer.wants_cmpct = peer.announce and peer.cmpct_ver >= 2

    def _msg_getcfilters(self, peer, payload: bytes) -> None:
        """BIP157: send a compact filter for each block in the range."""
        import struct
        from .filters import block_filter
        r = net.BytesReader(payload)
        ftype, start = r.read(1)[0], struct.unpack("<I", r.read(4))[0]
        stop_hash = r.read(32)
        if ftype != 0:
            return                       # only 'basic' supported
        for h in range(start, self.chain.height + 1):
            e = self.chain.get_block_index(h)
            if e is None or e.hash == stop_hash:
                break
            block = self.chain.get_block(e.hash)
            if block is None:
                continue
            filt, _ = block_filter(
                block, int.from_bytes(e.hash[:16], "little"))
            peer.send("cfilter",
                      net.pack_cfilter(0, e.hash, filt))

    # -- compact blocks (BIP152) --------------------------------------------------
    def _msg_cmpctblock(self, peer, payload: bytes) -> None:
        hdr, salt, short, prefilled = net.unpack_cmpctblock(payload)
        bh = hdr.hash()
        if bh in self.chain.index:
            return
        have = {net.siphash(0, 0, t.tx.txid()).to_bytes(8, "little")[:6]: t.tx
                for t in self.mempool.txs.values()}
        prefilled_map = dict(prefilled)
        n_tx = len(short) + len(prefilled_map)
        txs = [None] * n_tx
        for idx, tx in prefilled_map.items():
            if idx < n_tx:
                txs[idx] = tx
        need_idx = []
        pi = 0
        for i in range(n_tx):
            if txs[i] is not None:
                continue
            sid = short[pi] if pi < len(short) else None
            pi += 1
            if sid in have:
                txs[i] = have[sid]
            else:
                need_idx.append(i)
        if need_idx:
            peer.send("getblocktxn", net.pack_getblocktxn(bh, need_idx))
            self._pending_compact[(bh, peer)] = (hdr, txs, need_idx)
            return
        self._submit_compact(hdr, txs)

    def _msg_blocktxn(self, peer, payload: bytes) -> None:
        from .utils import BytesReader
        r = BytesReader(payload)
        bh = r.read(32)
        n = r.read_varint()
        key = (bh, peer)
        if key not in self._pending_compact:
            return
        hdr, txs, need_idx = self._pending_compact.pop(key)
        for i in need_idx:
            txs[i] = Transaction.from_reader(r)
        self._submit_compact(hdr, txs)

    def _msg_getblocktxn(self, peer, payload: bytes) -> None:
        bh, idxs = net.unpack_getblocktxn(payload)
        block = self.chain.get_block(bh)
        if block:
            peer.send("blocktxn", net.pack_blocktxn(
                block, [i for i in idxs if i < len(block.txs)]))

    def _submit_compact(self, hdr, txs) -> None:
        self.submit_block(Block(hdr, txs))

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
    def generate_block(self, payout_script: bytes, extranonce: int = 0,
                       max_tries: int | None = None) -> Block:
        block = miner.create_block_template(self.chain, self.mempool,
                                            payout_script,
                                            extranonce=extranonce)
        if not miner.mine_block(block, self.params.pow_limit_bits,
                                max_tries=max_tries,
                                extranonce_start=extranonce):
            raise ChainError("failed to find PoW")
        self.submit_block(block)
        return block

    def get_block_template(self, payout_script: bytes,
                           extranonce: int = 0,
                           reserved: bytes | None = None,
                           extra_data: bytes | None = None) -> Block:
        return miner.create_block_template(
            self.chain, self.mempool, payout_script,
            extranonce=extranonce, reserved=reserved,
            **({"extra_data": extra_data} if extra_data is not None else {}))
