"""Stratum authorization tests — mining.authorize must require the
stratum secret so public ports can't be farmed by anonymous miners."""

import json
import os
import tempfile
import unittest

from alpha import constants, stratum
from alpha.node import Node


class _FakeConn:
    def __init__(self):
        self.sent = []

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, n):
        return b""

    def settimeout(self, t):
        pass

    def close(self):
        pass


def _results(sess):
    out = []
    for chunk in sess.conn.sent:
        for line in chunk.decode().splitlines():
            if line.strip():
                out.append(json.loads(line))
    return out


class TestStratumAuth(unittest.TestCase):
    def _td(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        return td.name

    def _session(self, td, secret="s3cret"):
        node = Node(constants.REGTEST, os.path.join(td, "n"),
                    port=0, listen=False)
        self.addCleanup(node.stop)   # runs before td.cleanup (LIFO)
        conn = _FakeConn()
        return stratum.StratumSession(conn, ("127.0.0.1", 0), node,
                                      secret=secret), node

    def test_secret_file_generated(self):
        td = self._td()
        s1 = stratum._load_secret(td)
        s2 = stratum._load_secret(td)
        self.assertEqual(s1, s2)
        self.assertEqual(len(s1), 64)
        path = os.path.join(td, "stratum.secret")
        self.assertTrue(os.path.exists(path))
        if os.name != "nt":
            self.assertEqual(oct(os.stat(path).st_mode & 0o777),
                             "0o600")

    def test_env_secret_wins(self):
        td = self._td()
        os.environ["ALPHA_STRATUM_SECRET"] = "envsecret"
        try:
            self.assertEqual(stratum._load_secret(td), "envsecret")
        finally:
            del os.environ["ALPHA_STRATUM_SECRET"]

    def test_authorize_rejects_wrong_password(self):
        sess, node = self._session(self._td())
        addr = node.wallet.new_address()
        sess._handle({"id": 1, "method": "mining.subscribe",
                      "params": []})
        sess._handle({"id": 2, "method": "mining.authorize",
                      "params": [addr, "wrong"]})
        res = [m for m in _results(sess) if m.get("id") == 2]
        self.assertEqual(res[0]["result"], False)
        self.assertIsNone(sess.payout_spk)

    def test_authorize_rejects_missing_password(self):
        sess, node = self._session(self._td())
        addr = node.wallet.new_address()
        sess._handle({"id": 1, "method": "mining.authorize",
                      "params": [addr]})
        res = _results(sess)
        self.assertEqual(res[0]["result"], False)

    def test_authorize_accepts_secret(self):
        sess, node = self._session(self._td(), secret="hunter2")
        addr = node.wallet.new_address()
        sess._handle({"id": 1, "method": "mining.authorize",
                      "params": [addr, "hunter2"]})
        res = _results(sess)
        self.assertEqual(res[0]["result"], True)
        self.assertIsNotNone(sess.payout_spk)

    def test_empty_secret_denies_all(self):
        sess, node = self._session(self._td(), secret="")
        addr = node.wallet.new_address()
        sess._handle({"id": 1, "method": "mining.authorize",
                      "params": [addr, "anything"]})
        res = _results(sess)
        self.assertEqual(res[0]["result"], False)


if __name__ == "__main__":
    unittest.main()
