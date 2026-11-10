"""End-to-end use-case demo — runs real composed flows on a local node.

Usage:  start a node first (main/test/regtest), then:
    python examples/use_cases.py --rpcport 18443 --datadir ./data-regtest

Demonstrates that the LIVE features compose into real applications.
"""
import json, urllib.request, base64, argparse, sys


def rpc_call(cookie, port, method, *params):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}",
        data=json.dumps({"jsonrpc": "2.0", "id": 1,
                         "method": method, "params": list(params)}).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Basic " + base64.b64encode(
                     cookie.encode()).decode()})
    r = json.loads(urllib.request.urlopen(req).read())
    if r["error"] is not None:
        raise RuntimeError(f"{method}: {r['error']}")
    return r["result"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpcport", type=int, default=18443)
    ap.add_argument("--datadir", default="./data-regtest")
    a = ap.parse_args()
    cookie = open(f"{a.datadir}/.cookie").read().strip()

    def rpc(m, *p):
        return rpc_call(cookie, a.rpcport, m, *p)

    def mine(n=1):
        rpc("generatetoaddress", n, rpc("getnewaddress"))

    # pre-fund a second party so buy/pay flows have a distinct buyer;
    # flush any pending mempool txs first so coin-selection doesn't conflict
    mine()
    buyer = rpc("getnewaddress")
    rpc("sendtoaddress", buyer, 20)
    mine()

    print("=" * 60)
    print("ALPHA USE-CASE DEMO — every step lands on-chain")
    print("=" * 60)

    # ---- 1. Merchant checkout ----------------------------------------------
    print("\n[1] MERCHANT CHECKOUT")
    inv = rpc("createinvoice", 2.5, "Demo order #1")
    print("   invoice:", inv["invoice_id"][:20], "|", inv["uri"])
    mine()
    pay = rpc("payinvoice", inv["invoice_id"])
    print("   paid:", pay["txid"][:20], "|", pay["paid_alpha"], "ALPHA")
    mine()
    st = [i for i in rpc("listinvoices")
          if i["invoice_id"] == inv["invoice_id"]][0]
    print("   status paid =", st["paid"])

    # ---- 2. NFT collectible sale --------------------------------------------
    print("\n[2] NFT MARKETPLACE")
    nft = rpc("mintnft", "Legendary Card", "ipfs://card.png")
    mine()
    order = rpc("nftsell", nft["nft_id"], 1.5)
    mine()
    print("   listed:", order["order_id"][:20], "@", order["price_alpha"])
    # fund a distinct buyer for this purchase
    nbuyer = rpc("getnewaddress")
    rpc("sendtoaddress", nbuyer, 5)
    mine()
    buy = rpc("nftbuy", order["order_id"])
    mine()
    print("   sold for", buy["paid_alpha"], "ALPHA ->", buy["txid"][:20])

    # ---- 3. Identity + KYC ---------------------------------------------------
    print("\n[3] DID + KYC SIGN-IN")
    reg = rpc("registeridentity", "DemoUser")    # auto-funded address
    who = reg["did"].replace("did:alpha:", "")
    mine()
    rpc("issuecredential", who, "kyc", "ab" * 16)   # auto-funded issuer
    mine()
    ch = rpc("alphaidchallenge", who, "demo.app")
    sig = rpc("signmessage", who, ch["message"])
    ok = rpc("verifymessage", who, sig, ch["message"])
    print("   did:", rpc("resolveidentity", who)["did"])
    print("   sign-in verified:", ok,
          "| kyc:", rpc("kycstatus", who)["kyc_verified"])

    # ---- 4. Escrow + loan -----------------------------------------------------
    print("\n[4] ESCROW + LOAN")
    tid = rpc("listtokens")
    if tid:
        tid = tid[0]["token_id"]
        e = rpc("escrowopen", tid, 5, rpc("getnewaddress"),
                rpc("getnewaddress"), 100)
        mine()
        rpc("escrowrelease", e["escrow_id"])
        mine()
        print("   escrow released ->",
              [x["open"] for x in rpc("listescrows")])
        ln = rpc("loanopen", tid, 10, 1.0, 500, 100)
        mine()
        print("   loan offered:", ln["loan_id"][:20],
              "due@", ln["due_height"])

    # ---- 5. Oracle feed -------------------------------------------------------
    print("\n[5] ORACLE")
    feed = rpc("oraclecreate", "DEMO/USD", "demo price")
    mine()
    rpc("oraclepublish", feed["feed_id"], "1.2345", 1720000000)
    mine()
    print("   latest:", rpc("oraclelatest", feed["feed_id"])["value"])

    print("\n" + "=" * 60)
    print("ALL FLOWS COMPLETED ON-CHAIN ✓")
    print("=" * 60)


if __name__ == "__main__":
    sys.exit(main())
