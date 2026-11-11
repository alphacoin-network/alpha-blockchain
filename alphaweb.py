#!/usr/bin/env python3
"""alphaweb -- the Alpha Blockchain website + explorer server.

Serves the static site in ./website and a JSON API (/api/*) that proxies
to a running alphad node's JSON-RPC.

Usage:
    python alphad.py --chain regtest --datadir ./data     # node on :18443
    python alphaweb.py --port 8080                        # site on :8080
"""

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from alpha import rpc

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "website")


class API:
    def __init__(self, host: str, rpcport: int, auth: str | None = None):
        self.host = host
        self.rpcport = rpcport
        self.auth = auth

    def call(self, method, *params):
        return rpc.call(self.host, self.rpcport, method, list(params),
                        auth=self.auth)

    # -- endpoints ------------------------------------------------------------
    def stats(self):
        info = self.call("getblockchaininfo")
        mem = self.call("getmempoolinfo")
        try:
            hashps = self.call("getnetworkhashps", 120)
        except Exception:
            hashps = 0
        try:
            peers = self.call("getconnectioncount")
        except Exception:
            peers = 0
        try:
            toks = self.call("listtokens")
        except Exception:
            toks = []
        return {
            "chain": info["chain"], "height": info["blocks"],
            "bestblockhash": info["bestblockhash"],
            "difficulty": info["difficulty"],
            "supply": info["supply"], "chainwork": info["chainwork"],
            "mediantime": info["mediantime"],
            "mempool": mem["size"], "hashrate": hashps,
            "connections": peers, "tokens": len(toks),
        }

    def blocks(self, n: int = 20):
        n = min(int(n), 200)
        tip = self.call("getblockcount")
        out = []
        for h in range(tip, max(0, tip - n), -1):
            bh = self.call("getblockhash", h)
            b = self.call("getblock", bh, 1)
            out.append({
                "height": b["height"], "hash": b["hash"], "time": b["time"],
                "nTx": b["nTx"], "size": b["size"], "nonce": b["nonce"],
                "merkleroot": b["merkleroot"], "difficulty": b["difficulty"],
            })
        return out

    def block(self, ident: str):
        if ident.isdigit():
            ident = self.call("getblockhash", int(ident))
        return self.call("getblock", ident, 2)

    def tx(self, txid: str):
        return self.call("getrawtransaction", txid, True)

    def mempool(self):
        return {"txids": self.call("getrawmempool"),
                "info": self.call("getmempoolinfo")}

    def address(self, addr: str):
        scan = self.call("scantxoutset", "start")
        utxos = [u for u in scan["unspents"] if u.get("address") == addr]
        balance = sum(u["amount"] for u in utxos)
        tokbal = []
        try:
            tokbal = self.call("listtokenbalances", addr)
        except Exception:
            pass
        return {"address": addr, "balance": balance,
                "utxo_count": len(utxos), "utxos": utxos[:200],
                "tokens": tokbal}

    def tokens(self):
        return self.call("listtokens")

    def token(self, tid: str):
        info = self.call("gettokeninfo", tid)
        holders = self.call("gettokenholders", tid)
        return {"info": info, "holders": holders}

    def search(self, q: str):
        q = q.strip()
        if q.isdigit():
            return {"type": "block", "id": q}
        if len(q) == 64:
            try:
                int(q, 16)
                try:
                    self.call("getblockheader", q)
                    return {"type": "block", "id": q}
                except Exception:
                    return {"type": "tx", "id": q}
            except ValueError:
                pass
        return {"type": "address", "id": q}


def make_handler(api: API):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = urlparse(self.path).path
            qs = parse_qs(urlparse(self.path).query)
            if path.startswith("/api/"):
                self._api(path, qs)
            else:
                self._static(path)

        def _api(self, path, qs):
            route = path[5:].strip("/")
            try:
                if route == "stats":
                    out = api.stats()
                elif route == "blocks":
                    out = api.blocks(qs.get("n", ["20"])[0])
                elif route.startswith("block/"):
                    out = api.block(route[6:])
                elif route.startswith("tx/"):
                    out = api.tx(route[3:])
                elif route == "mempool":
                    out = api.mempool()
                elif route.startswith("address/"):
                    out = api.address(route[8:])
                elif route == "tokens":
                    out = api.tokens()
                elif route.startswith("token/"):
                    out = api.token(route[6:])
                elif route == "search":
                    out = api.search(qs.get("q", [""])[0])
                elif route == "minework":
                    out = api.call("getwork", qs.get("address", [""])[0])
                elif route == "submitwork":
                    out = api.call("submitwork", qs.get("workid", [""])[0],
                                   int(qs.get("nonce", ["0"])[0]))
                elif route.startswith("utxos/"):
                    # unspent outputs for one address (for the web wallet)
                    addr = route[6:]
                    scan = api.call("scantxoutset", "start")
                    tip = api.call("getblockcount")
                    out = {"address": addr, "height": tip,
                           "utxos": [u for u in scan.get("unspents", [])
                                     if u.get("address") == addr]}
                elif route == "broadcast":
                    out = api.call("sendrawtransaction",
                                   qs.get("hex", [""])[0])
                elif route == "dexorders":
                    out = api.call("dexorders")
                # ---- public read-only protocol APIs ----
                elif route == "pools":
                    out = api.call("ammpools")
                elif route == "nfts":
                    out = api.call("listnfts")
                elif route == "nftorders":
                    out = api.call("nftorders")
                elif route == "domains":
                    out = api.call("listdomains")
                elif route.startswith("domain/"):
                    out = api.call("resolvedomain", route[7:])
                elif route.startswith("identity/"):
                    out = api.call("resolveidentity", route[9:])
                elif route.startswith("kyc/"):
                    out = api.call("kycstatus", route[4:])
                elif route == "feeds":
                    out = api.call("oraclefeeds")
                elif route.startswith("feedhist/"):
                    out = api.call("oraclehistory", route[9:])
                elif route.startswith("feed/"):
                    out = api.call("oraclelatest", route[5:])
                elif route == "agents":
                    out = api.call("listagents")
                elif route == "receipts":
                    out = api.call("paymentreceipts")
                elif route == "loans":
                    out = api.call("listloans")
                elif route == "escrows":
                    out = api.call("listescrows")
                elif route == "invoices":
                    out = api.call("listinvoices")
                elif route == "items":
                    out = api.call("listitems")
                elif route.startswith("item/"):
                    out = api.call("itemhistory", route[5:])
                elif route == "certs":
                    out = api.call("listcertificates")
                elif route.startswith("cert/"):
                    out = api.call("verifycertificate", route[5:])
                elif route == "businesses":
                    out = api.call("listbusinesses")
                elif route.startswith("business/"):
                    out = api.call("businessinfo", route[9:])
                elif route == "retirements":
                    out = api.call("retirementcerts")
                elif route == "games":
                    out = api.call("gamerecords", qs.get("game", [None])[0])
                elif route == "stakes":
                    out = api.call("liststakes")
                elif route == "stakeinfo":
                    out = api.call("stakeinfo")
                else:
                    self._json({"error": "not found"}, 404)
                    return
                self._json(out)
            except rpc.RPCError as e:
                self._json({"error": str(e)}, 404)
            except Exception as e:  # noqa: BLE001
                self._json({"error": str(e)}, 500)

        def _static(self, path):
            if path in ("/", ""):
                path = "/index.html"
            target = os.path.normpath(os.path.join(WEB_DIR, path.lstrip("/")))
            if not target.startswith(os.path.normpath(WEB_DIR)):
                self.send_error(403)
                return
            if not os.path.isfile(target):
                self.send_error(404)
                return
            ctype = {
                ".html": "text/html; charset=utf-8",
                ".css": "text/css",
                ".js": "application/javascript",
                ".svg": "image/svg+xml",
                ".png": "image/png",
                ".json": "application/json",
                ".ico": "image/x-icon",
                ".woff2": "font/woff2",
            }.get(os.path.splitext(target)[1], "application/octet-stream")
            with open(target, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _json(self, obj, status=200):
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


def main():
    p = argparse.ArgumentParser(prog="alphaweb")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--rpcport", type=int, default=18443,
                   help="alphad RPC port")
    p.add_argument("--rpchost", default="127.0.0.1")
    p.add_argument("--datadir", default="./data-regtest",
                   help="node datadir for .cookie auth")
    args = p.parse_args()

    api = API(args.rpchost, args.rpcport, rpc.get_cookie(args.datadir)
              or rpc.get_cookie("./demo-data"))
    httpd = ThreadingHTTPServer((args.host, args.port), make_handler(api))
    httpd.daemon_threads = True
    print(f"Alpha Web running at http://{args.host}:{args.port} "
          f"(node rpc {args.rpchost}:{args.rpcport})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
