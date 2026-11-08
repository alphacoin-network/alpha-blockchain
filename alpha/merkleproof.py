"""Partial merkle trees (Bitcoin's CPartialMerkleTree) for SPV proofs.

Used by gettxoutproof / verifytxoutproof -- proves a tx is included in a
block without revealing all its siblings.
"""

from .utils import BytesReader, ser_compact_size, sha256d


class PartialMerkleTree:
    def __init__(self):
        self.n_transactions = 0
        self.hashes: list[bytes] = []
        self.bits: list[bool] = []

    # -- construction ----------------------------------------------------------
    @staticmethod
    def build(txids: list, matches: set) -> "PartialMerkleTree":
        """txids: all block txids (wire order). matches: txids to prove."""
        tree = PartialMerkleTree()
        tree.n_transactions = len(txids)
        tree.bits = []
        tree.hashes = []

        height = 0
        while tree._width(height) > 1:
            height += 1

        def traverse(h, pos):
            start = pos << h
            end = min((pos + 1) << h, tree.n_transactions)
            parent_match = any(
                txids[i] in matches for i in range(start, end))
            tree.bits.append(parent_match)
            if h == 0 or not parent_match:
                tree.hashes.append(tree._hash(h, pos, txids))
            else:
                traverse(h - 1, pos * 2)
                if pos * 2 + 1 < tree._width(h - 1):
                    traverse(h - 1, pos * 2 + 1)

        traverse(height, 0)
        return tree

    def _width(self, height: int) -> int:
        return (self.n_transactions + (1 << height) - 1) >> height

    def _hash(self, height: int, pos: int, txids: list) -> bytes:
        if height == 0:
            return txids[pos]
        left = self._hash(height - 1, pos * 2, txids)
        if pos * 2 + 1 < self._width(height - 1):
            right = self._hash(height - 1, pos * 2 + 1, txids)
        else:
            right = left
        return sha256d(left + right)

    # -- extraction --------------------------------------------------------------
    def extract(self):
        """Returns (matched_txids, merkle_root). Raises on malformed tree."""
        if self.n_transactions == 0:
            raise ValueError("empty tree")
        if self.n_transactions > 0x1000000:
            raise ValueError("tree too large")
        matched = []
        bits_used = [0]
        hashes_used = [0]

        height = 0
        while self._width(height) > 1:
            height += 1

        def traverse(h, pos):
            if bits_used[0] >= len(self.bits):
                raise ValueError("bits overflow")
            parent = self.bits[bits_used[0]]
            bits_used[0] += 1
            if h == 0 or not parent:
                if hashes_used[0] >= len(self.hashes):
                    raise ValueError("hash overflow")
                node_hash = self.hashes[hashes_used[0]]
                hashes_used[0] += 1
                if h == 0 and parent:
                    matched.append(node_hash)
                return node_hash
            left = traverse(h - 1, pos * 2)
            if pos * 2 + 1 < self._width(h - 1):
                right = traverse(h - 1, pos * 2 + 1)
                if right == left:
                    raise ValueError("invalid tree: identical subhashes")
            else:
                right = left
            return sha256d(left + right)

        root = traverse(height, 0)
        if hashes_used[0] != len(self.hashes):
            raise ValueError("unused hashes")
        return matched, root

    # -- serialization -------------------------------------------------------------
    def serialize(self) -> bytes:
        n_bits = len(self.bits)
        bits_bytes = bytearray((n_bits + 7) // 8)
        for i, b in enumerate(self.bits):
            if b:
                bits_bytes[i // 8] |= 1 << (i % 8)
        return (ser_compact_size_uint32(self.n_transactions)
                + ser_compact_size(len(self.hashes))
                + b"".join(self.hashes)
                + ser_compact_size(len(bits_bytes)) + bytes(bits_bytes))

    @staticmethod
    def deserialize(data: bytes) -> "PartialMerkleTree":
        r = BytesReader(data)
        tree = PartialMerkleTree()
        tree.n_transactions = r.read_u32()
        n = r.read_varint()
        tree.hashes = [r.read(32) for _ in range(n)]
        n_bytes = r.read_varint()
        raw = r.read(n_bytes)
        tree.bits = [bool(raw[i // 8] & (1 << (i % 8))) for i in range(n_bytes * 8)]
        return tree


def ser_compact_size_uint32(n: int) -> bytes:
    import struct as _s
    return _s.pack("<I", n)


def txout_proof(block, match_txids: set) -> bytes:
    """Serialize header + partial merkle tree (gettxoutproof format)."""
    tree = PartialMerkleTree.build([tx.txid() for tx in block.txs],
                                   match_txids)
    return block.header.serialize() + tree.serialize()


def verify_proof(data: bytes):
    """Returns (matched_txids, merkle_root, block_header)."""
    from .block import BlockHeader
    r = BytesReader(data)
    header = BlockHeader.parse(r)
    tree = PartialMerkleTree.deserialize(r.data[r.pos:])
    matched, root = tree.extract()
    if root != header.merkle:
        raise ValueError("merkle root mismatch")
    return matched, root, header
