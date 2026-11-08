"""Tor hidden-service support via the Tor control protocol.

Bitcoin Core doesn't run Tor itself -- it talks to a local Tor daemon's
control port (default 127.0.0.1:9051) to create an ephemeral onion service
that forwards connections to our P2P listener. We mirror that.
"""

import os
import socket
import base64

CONTROL_PORT = 9051
DEFAULT_PROXY = ("127.0.0.1", 9050)


class TorError(Exception):
    pass


class TorController:
    """Talk to a running Tor daemon's control port."""

    def __init__(self, host: str = "127.0.0.1", port: int = CONTROL_PORT,
                 password: str | None = None, timeout: int = 10):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self._authenticate(password)

    def _cmd(self, cmd: str) -> str:
        self.sock.sendall(cmd.encode() + b"\r\n")
        return self._read_reply()

    def _read_reply(self) -> str:
        lines = []
        while True:
            line = self.sock.makefile("rb").readline().decode().strip()
            lines.append(line)
            if len(line) < 4 or line[3] == " ":
                break
        if not lines[-1].startswith("250"):
            raise TorError(" ; ".join(lines))
        return "\n".join(lines)

    def _authenticate(self, password: str | None):
        info = self._cmd("PROTOCOLINFO")
        if password:
            self._cmd(f'AUTHENTICATE "{password}"')
            return
        # cookie auth: read cookie path from AUTH METHODS line
        cookie_path = None
        for tok in info.split():
            if tok.startswith("COOKIEFILE="):
                cookie_path = tok.split("=", 1)[1].strip('"')
        if cookie_path:
            cookie = open(cookie_path, "rb").read().hex()
            self._cmd(f"AUTHENTICATE {cookie}")
        else:
            self._cmd("AUTHENTICATE")   # null auth

    def add_onion(self, target_port: int,
                  onion_port: int | None = None,
                  priv_key: str | None = None) -> str:
        """Create an ephemeral v3 hidden service -> returns *.onion.

        port: our P2P listener port; onion_port defaults to it.
        """
        port = onion_port or target_port
        key = "NEW:ED25519-V3" if priv_key is None else priv_key
        reply = self._cmd(
            f"ADD_ONION {key} Port={port},127.0.0.1:{target_port}")
        for tok in reply.split():
            if tok.startswith("ServiceID="):
                return tok.split("=")[1] + ".onion"
        raise TorError("no ServiceID in reply")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def create_onion_service(p2p_port: int,
                         control: tuple = ("127.0.0.1", CONTROL_PORT),
                         password: str | None = None) -> str:
    """High-level: create a .onion pointing at our listener."""
    ctl = TorController(*control, password=password)
    onion = ctl.add_onion(p2p_port)
    ctl.close()
    return onion


def is_onion(addr: str) -> bool:
    return addr.endswith(".onion")


def is_i2p(addr: str) -> bool:
    return addr.endswith(".i2p")
