#!/usr/bin/env python3
"""AUSD price oracle — keeps ALPHA/USD rate fresh for mint/redeem pricing.

Sources (priority):
  1. Latest on-chain DEX trade price (when liquidity exists)
  2. ALPHA_USD_PRICE env (admin-set fallback rate)

Run via cron every 15 min on the VPS:
  */15 * * * * set -a; . /etc/alpha-bot.env; set +a; \
    python3 tools/price_oracle.py >> /home/alphabetin/oracle.log 2>&1
"""
import json, os, urllib.request, base64

RPC = os.environ.get("ALPHA_RPC", "http://127.0.0.1:8332")
COOKIE = os.environ.get("ALPHA_COOKIE", "")
FALLBACK = float(os.environ.get("ALPHA_USD_PRICE", "0.05"))  # admin-set USD/ALPHA
API = os.environ.get("ALPHA_API", "https://alphacoin.network")


def rpc(method, *params):
    req = urllib.request.Request(
        RPC, data=json.dumps({"method": method, "params": list(params)}).encode(),
        headers={"content-type": "application/json"})
    if COOKIE:
        req.add_header("Authorization",
                       "Basic " + base64.b64encode(COOKIE.encode()).decode())
    with urllib.request.urlopen(req, timeout=60) as r:
        d = json.load(r)
    if d.get("error"):
        raise RuntimeError(d["error"])
    return d.get("result")


def dex_price():
    """Median ALPHA price (USD) from open DEX sell orders, if any."""
    try:
        orders = json.load(urllib.request.urlopen(
            f"{API}/api/dexorders", timeout=20))
        prices = []
        for o in orders if isinstance(orders, list) else []:
            # order: {token_id, amount, price_alpha, ...} — price in ALPHA
            # we need USD/ALPHA — derive only if order has usd field
            p = o.get("price_usd") or o.get("usd_price")
            if p:
                prices.append(float(p))
        if prices:
            prices.sort()
            return prices[len(prices) // 2]
    except Exception:
        pass
    return None


def main():
    price = dex_price() or FALLBACK
    res = rpc("ausdprice", price)
    print(f"oracle: ALPHA=${price} -> {res}")


if __name__ == "__main__":
    main()
