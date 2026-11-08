"""P2P networking with Bitcoin's exact wire format.

Message framing (24-byte header):
    magic(4) | command(12 ascii, NUL-padded) | length(4) | checksum(4)
payload checksum = sha256d(payload)[:4]

Implemented messages: version, verack, ping, pong, inv, getdata, notfound,
tx, block, headers, getheaders, getblocks, mempool, addr, reject, sendheaders.
"""

import socket
import struct
import threading
import time

from .filters import siphash
from .transaction import Transaction
from .utils import BytesReader

from .block import Block, BlockHeader
from .transaction import Transaction
from .utils import BytesReader, ser_compact_size, ser_varstr, sha256d

PROTOCOL_VERSION = 70015
NODE_NETWORK = 1            # services flag: full node
NODE_WITNESS = 1 << 3       # services flag: segwit-capable
USER_AGENT = b"/Alpha:0.1.0/"

MSG_TX = 1
MSG_BLOCK = 2
MSG_FILTERED_BLOCK = 3
MSG_WITNESS_TX = 0x40000001
MSG_WITNESS_BLOCK = 0x40000002
MSG_CMPCT_BLOCK = 4

NODE_BLOOM = 1 << 2
NODE_COMPACT_FILTERS = 1 << 6

HEADER_LEN = 24
MAX_MESSAGE = 32 * 1024 * 1024


class NetError(Exception):
    pass


# ---------------------------------------------------------------------------
# Address (de)serialization -- Bitcoin's 26-byte CAddress
# ---------------------------------------------------------------------------
def ser_netaddr(services: int, ip: str, port: int, with_time=False,
                timestamp: int = 0) -> bytes:
    out = b""
    if with_time:
        out += struct.pack("<I", timestamp)
    out += struct.pack("<Q", services)
    ip_bytes = ip_to_bytes(ip)
    out += ip_bytes + struct.pack(">H", port)  # port is big-endian!
    return out


def ip_to_bytes(ip: str) -> bytes:
    """IPv4 mapped to ::ffff:a.b.c.d; IPv6 raw (16 bytes)."""
    if ":" in ip:
        return socket.inet_pton(socket.AF_INET6, ip)
    return b"\x00" * 10 + b"\xff\xff" + socket.inet_aton(ip)


def bytes_to_ip(b: bytes) -> str:
    if b[:12] == b"\x00" * 10 + b"\xff\xff":
        return socket.inet_ntoa(b[12:])
    try:
        return socket.inet_ntop(socket.AF_INET6, b)
    except OSError:
        return b.hex()


def deser_netaddr(r: BytesReader, with_time=False):
    ts = r.read_u32() if with_time else 0
    services = r.read_u64()
    ip = bytes_to_ip(r.read(16))
    port = struct.unpack(">H", r.read(2))[0]
    return ts, services, ip, port


# ---------------------------------------------------------------------------
# Message framing
# ---------------------------------------------------------------------------
def pack_message(command: str, payload: bytes, magic: int) -> bytes:
    cmd = command.encode("ascii")[:12].ljust(12, b"\x00")
    header = (struct.pack("<I", magic) + cmd
              + struct.pack("<I", len(payload)) + sha256d(payload)[:4])
    return header + payload


def read_message(sock_file, magic: int):
    """Read one framed message; returns (command, payload)."""
    header = sock_file.read(HEADER_LEN)
    if not header or len(header) < HEADER_LEN:
        return None, None
    m, cmd_raw, length, checksum = struct.unpack("<I12sI4s", header)
    if m != magic:
        raise NetError("bad network magic")
    if length > MAX_MESSAGE:
        raise NetError("message too large")
    payload = sock_file.read(length) if length else b""
    if len(payload) < length:
        raise NetError("truncated payload")
    if sha256d(payload)[:4] != checksum:
        raise NetError("bad checksum")
    return cmd_raw.rstrip(b"\x00").decode("ascii", "replace"), payload


# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------
def pack_version(height: int, their_addr: tuple, our_addr: tuple,
                 nonce: int, relay: bool = True) -> bytes:
    services = NODE_NETWORK | NODE_WITNESS
    out = struct.pack("<i", PROTOCOL_VERSION)
    out += struct.pack("<Q", services)
    out += struct.pack("<q", int(time.time()))
    out += ser_netaddr(services, their_addr[0], their_addr[1])
    out += ser_netaddr(services, our_addr[0], our_addr[1])
    out += struct.pack("<Q", nonce)
    out += ser_varstr(USER_AGENT)
    out += struct.pack("<i", height)
    out += b"\x01" if relay else b"\x00"
    return out


def unpack_version(payload: bytes) -> dict:
    r = BytesReader(payload)
    d = {
        "version": r.read_i32(),
        "services": r.read_u64(),
        "timestamp": r.read_i64(),
    }
    _, _, ip, port = deser_netaddr(r)
    d["addr_recv"] = (ip, port)
    _, _, ip, port = deser_netaddr(r)
    d["addr_from"] = (ip, port)
    d["nonce"] = r.read_u64()
    d["user_agent"] = r.read_varbytes()
    d["start_height"] = r.read_i32() if not r.eof() else 0
    d["relay"] = r.read_u8() != 0 if not r.eof() else True
    return d


def pack_inv(items) -> bytes:
    """items: iterable of (type, 32-byte hash wire order)."""
    items = list(items)
    out = ser_compact_size(len(items))
    for t, h in items:
        out += struct.pack("<I", t) + h
    return out


def unpack_inv(payload: bytes):
    r = BytesReader(payload)
    n = r.read_varint()
    return [(r.read_u32(), r.read(32)) for _ in range(n)]


def pack_headers(headers) -> bytes:
    out = ser_compact_size(len(headers))
    for h in headers:
        out += h.serialize() + b"\x00"   # tx count (always 0 for headers)
    return out


def unpack_headers(payload: bytes):
    r = BytesReader(payload)
    n = r.read_varint()
    out = []
    for _ in range(n):
        h = BlockHeader.parse(r)
        r.read_varint()  # txn_count == 0
        out.append(h)
    return out


def pack_getheaders(protocol: int, locator: list, hash_stop: bytes = b"\x00" * 32) -> bytes:
    out = struct.pack("<i", protocol)
    out += ser_compact_size(len(locator))
    for h in locator:
        out += h
    out += hash_stop
    return out


def unpack_getheaders(payload: bytes):
    r = BytesReader(payload)
    version = r.read_i32()
    n = r.read_varint()
    locator = [r.read(32) for _ in range(n)]
    stop = r.read(32)
    return version, locator, stop


def pack_addr(addrs) -> bytes:
    out = ser_compact_size(len(addrs))
    for services, ip, port, ts in addrs:
        out += ser_netaddr(services, ip, port, with_time=True, timestamp=ts)
    return out


def unpack_addr(payload: bytes):
    r = BytesReader(payload)
    n = r.read_varint()
    return [deser_netaddr(r, with_time=True) for _ in range(n)]


# ---------------------------------------------------------------------------
# addrv2 (BIP155): variable-length network addresses
# ---------------------------------------------------------------------------
ADDRV2_IPV4 = 0x01
ADDRV2_IPV6 = 0x02
ADDRV2_TORV3 = 0x04
ADDRV2_I2P = 0x05


def pack_addrv2(addrs) -> bytes:
    """addrs: [(services, ip, port, ts, netid)] -- netid in ADDDRV2_* codes."""
    import ipaddress
    out = ser_compact_size(len(addrs))
    for services, ip, port, ts, netid in addrs:
        out += struct.pack("<I", ts) + struct.pack("<q", services)
        out += bytes([netid])
        if netid == ADDRV2_IPV4:
            out += bytes([4]) + ipaddress.IPv4Address(ip).packed
        elif netid == ADDRV2_IPV6:
            out += bytes([16]) + ipaddress.IPv6Address(ip).packed
        elif netid == ADDRV2_TORV3:
            out += bytes([32]) + ip  # raw 32-byte onion key
        elif netid == ADDRV2_I2P:
            out += bytes([32]) + ip  # raw 32-byte i2p hash
        out += struct.pack(">H", port)
    return out


def unpack_addrv2(payload: bytes):
    import ipaddress
    r = BytesReader(payload)
    n = r.read_varint()
    out = []
    for _ in range(n):
        ts = r.read_i32(); services = r.read_u64()
        netid = r.read(1)[0]; ln = r.read_varint()
        raw = r.read(ln)
        if netid == ADDRV2_IPV4:
            ip = str(ipaddress.IPv4Address(raw))
        elif netid == ADDRV2_IPV6:
            ip = str(ipaddress.IPv6Address(raw))
        else:
            ip = raw.hex()            # tor/i2p opaque blob
        out.append((services, ip, r.read_u16(), ts, netid))
    return out


# ---------------------------------------------------------------------------
# Compact blocks (BIP152): header + short txids + prefilled txs
# ---------------------------------------------------------------------------
def pack_cmpctblock(block, short_ids: list, prefilled) -> bytes:
    """short_ids: 6-byte ids in tx order; prefilled: [(index, tx), ...]."""
    out = block.header.serialize()
    out += struct.pack("<Q", block.compact_nonce) \
        if hasattr(block, "compact_nonce") else struct.pack("<Q", 0)
    out += ser_compact_size(len(short_ids))
    out += b"".join(short_ids)
    out += ser_compact_size(len(prefilled))
    for idx, tx in prefilled:
        out += ser_compact_size(idx) + tx.serialize(include_witness=True)
    return out


def unpack_cmpctblock(payload: bytes):
    from .block import Block
    r = BytesReader(payload)
    hdr_bytes = payload[:80]
    r.read(80)
    salt = r.read_u64()
    n = r.read_varint()
    short = [r.read(6) for _ in range(n)]
    n2 = r.read_varint()
    prefilled = [(r.read_varint(), Transaction.from_reader(r))
                 for _ in range(n2)]
    from .block import BlockHeader
    return BlockHeader.deserialize(hdr_bytes), salt, short, prefilled


def pack_getblocktxn(block_hash: bytes, indexes: list) -> bytes:
    return block_hash + ser_compact_size(len(indexes)) + b"".join(
        ser_compact_size(i) for i in indexes)


def unpack_getblocktxn(payload: bytes):
    r = BytesReader(payload)
    bh = r.read(32)
    n = r.read_varint()
    return bh, [r.read_varint() for _ in range(n)]


def pack_blocktxn(block, indexes: list) -> bytes:
    out = block.hash()
    out += ser_compact_size(len(indexes))
    for i in indexes:
        out += block.txs[i].serialize(include_witness=True)
    return out


def pack_reject(message: str, code: int, reason: str) -> bytes:
    return (ser_varstr(message.encode()) + bytes([code])
            + ser_varstr(reason.encode()))


# ---------------------------------------------------------------------------
# BIP37: filterload / filteradd / filterclear + merkleblock
# ---------------------------------------------------------------------------
def pack_filterload(bloom_filter) -> bytes:
    return (ser_varstr(bytes(bloom_filter.data))
            + struct.pack("<I", bloom_filter.n_funcs)
            + struct.pack("<I", bloom_filter.tweak)
            + b"\x01")                        # BLOOM_UPDATE_ALL


def pack_filteradd(data: bytes) -> bytes:
    return ser_varstr(data)


def pack_merkleblock(block, pmt) -> bytes:
    return (block.header.serialize() + struct.pack("<I", len(block.txs))
            + pmt.serialize())


def unpack_merkleblock(payload: bytes):
    from .block import BlockHeader
    from .merkleproof import PartialMerkleTree
    r = BytesReader(payload)
    hdr = BlockHeader.parse(r)
    n_tx = r.read_u32()
    hashes = r.read(r.read_varint() * 32)
    flags = r.read(r.read_varint())
    return hdr, n_tx, hashes, flags


# ---------------------------------------------------------------------------
# BIP152: sendcmpct advertise
# ---------------------------------------------------------------------------
def pack_sendcmpct(announce: bool = True, version: int = 2) -> bytes:
    return bytes([1 if announce else 0]) + struct.pack("<Q", version)


def unpack_sendcmpct(payload: bytes):
    return payload[0] != 0, struct.unpack("<Q", payload[1:9])[0]


# ---------------------------------------------------------------------------
# BIP157: getcfilters / cfilter / getcfheaders / cfheaders
# ---------------------------------------------------------------------------
def pack_getcfilters(filter_type: int, start: int, stop_hash: bytes) -> bytes:
    return bytes([filter_type]) + struct.pack("<I", start) + stop_hash


def pack_cfilter(filter_type: int, block_hash: bytes,
                 filter_data: bytes) -> bytes:
    return (bytes([filter_type]) + block_hash + ser_varstr(filter_data))


def unpack_cfilter(payload: bytes):
    r = BytesReader(payload)
    return r.read(1)[0], r.read(32), r.read(r.read_varint())


def pack_cfheaders(filter_type: int, stop_hash: bytes,
                   prev_header: bytes, headers: list) -> bytes:
    return (bytes([filter_type]) + stop_hash + prev_header
            + ser_compact_size(len(headers)) + b"".join(headers))


def pack_getcfheaders(filter_type: int, start: int,
                      stop_hash: bytes) -> bytes:
    return bytes([filter_type]) + struct.pack("<I", start) + stop_hash


# ---------------------------------------------------------------------------
# Peer connection (one per remote node; send + receive threads)
# ---------------------------------------------------------------------------
class Peer(threading.Thread):
    """A single P2P connection. `node` receives message callbacks."""

    def __init__(self, node, sock: socket.socket, addr: tuple,
                 inbound: bool = False):
        super().__init__(daemon=True)
        self.node = node
        self.sock = sock
        self.addr = addr                    # (ip, port)
        self.inbound = inbound
        self.alive = True
        self.handshake_done = False
        self.peer_version = {}
        self.nonce = int.from_bytes(sha256d(
            f"{id(self)}{time.time()}".encode())[:8], "little")
        self.send_lock = threading.Lock()
        self._file = sock.makefile("rb")

    # -- sending ----------------------------------------------------------
    def send(self, command: str, payload: bytes = b"") -> None:
        if not self.alive:
            return
        try:
            msg = pack_message(command, payload, self.node.params.network_magic)
            with self.send_lock:
                self.sock.sendall(msg)
        except OSError:
            self.close()

    def send_version(self) -> None:
        our = ("127.0.0.1", self.node.port)
        self.send("version", pack_version(
            self.node.chain.height, self.addr, our, self.nonce))

    def send_inv(self, items) -> None:
        if items:
            self.send("inv", pack_inv(items))

    def getdata(self, items) -> None:
        if items:
            self.send("getdata", pack_inv(items))

    # -- receiving ---------------------------------------------------------
    def run(self) -> None:
        try:
            if not self.inbound:
                self.send_version()
            self.sock.settimeout(600)
            while self.alive and not self.node.stopped:
                command, payload = read_message(self._file,
                                                self.node.params.network_magic)
                if command is None:
                    break
                self.node.on_message(self, command, payload)
        except (NetError, OSError, ValueError):
            pass
        finally:
            self.close()

    def close(self) -> None:
        if self.alive:
            self.alive = False
            try:
                self.sock.close()
            except OSError:
                pass
            self.node.on_peer_disconnect(self)

    def __repr__(self):
        return f"<Peer {self.addr[0]}:{self.addr[1]}>"


class PeerServer(threading.Thread):
    """Accepts inbound peer connections."""

    def __init__(self, node, host: str, port: int):
        super().__init__(daemon=True)
        self.node = node
        self.host = host
        self.port = port
        self.sock = None

    def run(self) -> None:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(16)
            self.sock.settimeout(2)
            while not self.node.stopped:
                try:
                    conn, addr = self.sock.accept()
                except socket.timeout:
                    continue
                peer = Peer(self.node, conn, addr, inbound=True)
                peer.send_version()
                self.node.register_peer(peer)
                peer.start()
        except OSError:
            pass

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass


def _socks5_connect(proxy: tuple, dest_host: str, dest_port: int,
                    timeout: int) -> socket.socket:
    """SOCKS5 handshake through `proxy` (ip, port) -- used for .onion/.i2p."""
    import struct as _st
    sock = socket.create_connection(proxy, timeout=timeout)
    try:
        sock.sendall(b"\x05\x01\x00")          # ver5, 1 method, no-auth
        r = sock.recv(2)
        if r != b"\x05\x00":
            raise OSError("socks5 auth refused")
        # connect request: atyp=3 (domain name)
        req = (b"\x05\x01\x00\x03" + bytes([len(dest_host)])
               + dest_host.encode() + _st.pack(">H", dest_port))
        sock.sendall(req)
        # response: ver rep rsv atyp | addr | port
        resp = sock.recv(4)
        if len(resp) < 4 or resp[1] != 0:
            raise OSError(
                f"socks5 connect failed: {resp[1] if len(resp)>1 else '?'}")
        atyp = resp[3]
        addrlen = {1: 4, 4: 16}.get(atyp)
        if addrlen is None:
            if atyp == 3:
                ln = sock.recv(1)[0]
                sock.recv(ln + 2)
            else:
                raise OSError("bad socks5 atyp")
        else:
            sock.recv(addrlen + 2)
        return sock
    except OSError:
        sock.close()
        raise


def connect_peer(node, ip: str, port: int, timeout: int = 10,
                 proxy: tuple | None = None) -> Peer | None:
    """Outbound connection with handshake kickoff.

    `proxy` = ("127.0.0.1", 9050) routes through a SOCKS5 proxy (Tor).
    """
    try:
        if proxy:
            sock = _socks5_connect(proxy, ip, port, timeout)
        else:
            sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(None)
        peer = Peer(node, sock, (ip, port), inbound=False)
        node.register_peer(peer)
        peer.start()
        return peer
    except OSError:
        return None
