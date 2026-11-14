#!/usr/bin/env python3
"""Alpha referral payout engine — activity-verified, tiered, capped.

Run periodically (cron) on the VPS next to alphad. Reads the Telegram bot's
SQLite DB, verifies on-chain milestones, and pays rewards from the referral
hot wallet via the node's JSON-RPC.

Env:
  ALPHA_RPC      e.g. http://127.0.0.1:8332
  ALPHA_COOKIE   node .cookie contents (user:pass)
  REF_DB         path to bot SQLite db (default tools/alpha_referrals.db)
  HOT_WALLET_WIF hot wallet WIF — imported into node wallet if absent
  MAX_PAYOUT_PER_RUN  safety cap (default 5000 α)

Stages per referral (verified on-chain):
  1 = wallet activated (address has balance/utxo)
  2 = first real outgoing tx
  3 = 30 days since join

Tiers (by referrer's verified-referral count):
  Genesis 1-500    → 500 α/referral
  Early   501-5000 → 200 α
  Growth  5001+    → 50 α
Program closes when pool balance < payout or 90 days elapsed (START_TS).
"""
import json, os, sqlite3, sys, time, urllib.request

RPC = os.environ.get("ALPHA_RPC", "http://127.0.0.1:8332")
COOKIE = os.environ.get("ALPHA_COOKIE", "")
DB = os.environ.get("REF_DB", os.path.join(os.path.dirname(__file__), "alpha_referrals.db"))
HOT_WIF = os.environ.get("HOT_WALLET_WIF", "")
HOT_ADDR = os.environ.get("HOT_WALLET_ADDR", "alpha1qhpwer8nkj5rykad87mlrte97xg5wej4xz7psk7")
MAX_PER_RUN = float(os.environ.get("MAX_PAYOUT_PER_RUN", "5000"))
PROGRAM_DAYS = 90
TIERS = [(500, 500.0), (5000, 200.0), (10**9, 50.0)]
STAGE_REWARD = {1: 50.0, 2: 150.0, 3: 300.0}   # cumulative design: paid per stage


def rpc(method, *params):
    req = urllib.request.Request(
        RPC, data=json.dumps({"method": method, "params": list(params)}).encode(),
        headers={"content-type": "application/json"})
    if COOKIE:
        import base64
        req.add_header("Authorization",
                       "Basic " + base64.b64encode(COOKIE.encode()).decode())
    with urllib.request.urlopen(req, timeout=120) as r:
        d = json.load(r)
    if d.get("error"):
        raise RuntimeError(d["error"].get("message", d["error"]))
    return d.get("result")


def tier_reward(n):
    for cap, amt in TIERS:
        if n <= cap:
            return amt
    return 50.0


def db():
    c = sqlite3.connect(DB)
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        tg_id INTEGER PRIMARY KEY, code TEXT UNIQUE,
        ref_by TEXT, referrals INTEGER DEFAULT 0,
        rewarded INTEGER DEFAULT 0, joined TEXT,
        wallet TEXT, stage1 INTEGER DEFAULT 0, stage2 INTEGER DEFAULT 0,
        stage3 INTEGER DEFAULT 0, earned REAL DEFAULT 0, paid REAL DEFAULT 0)""")
    c.execute("""CREATE TABLE IF NOT EXISTS payouts(
        id INTEGER PRIMARY KEY AUTOINCREMENT, tg_id INTEGER,
        amount REAL, stage INTEGER, txid TEXT, ts TEXT,
        UNIQUE(tg_id, stage))""")
    return c


def addr_has_activity(addr):
    """Return (balance, sent_count) for an address via public API."""
    try:
        with urllib.request.urlopen(
                f"https://alphacoin.network/api/address/{addr}", timeout=30) as r:
            d = json.load(r)
        sent = sum(1 for t in d.get("transactions", []) if t.get("sent"))
        return d.get("balance", 0), sent
    except Exception:
        return 0, 0


def ensure_hot_key():
    if not HOT_WIF:
        return
    try:
        rpc("importprivkey", HOT_WIF)
    except Exception:
        pass  # already imported


def pay(to_addr, amount):
    txid = rpc("sendtoaddress", to_addr, amount)
    return txid


def main():
    c = db()
    users = c.execute(
        "SELECT tg_id, code, wallet, joined, stage1, stage2, stage3, "
        "earned, paid, ref_by FROM users").fetchall()
    # count VERIFIED referrals per referrer code
    ref_count = {}
    for u in users:
        if u[9]:
            ref_count[u[9]] = ref_count.get(u[9], 0) + 1

    paid_this_run = 0.0
    payouts = 0
    # index users by code for referrer lookup
    by_code = {u[1]: u for u in users}
    for tg_id, code, wallet, joined, s1, s2, s3, earned, paid, ref_by in users:
        if not ref_by or not wallet:
            continue   # only referred users generate rewards for referrer
        ref = by_code.get(ref_by)
        if not ref or not ref[2]:      # referrer must have linked wallet
            continue
        r_tg, r_code, r_wallet = ref[0], ref[1], ref[2]
        bal, sent = addr_has_activity(wallet)
        # stage 1: activated (has balance or any tx)
        new1 = s1 or (1 if (bal > 0 or sent > 0) else 0)
        # stage 2: first real outgoing tx
        new2 = s2 or (1 if sent > 0 else 0)
        # stage 3: 30 days since join
        new3 = s3
        try:
            jt = time.mktime(time.strptime(joined[:19], "%Y-%m-%d %H:%M:%S"))
            if time.time() - jt > 30 * 86400:
                new3 = 1
        except Exception:
            pass
        # friend welcome bonus — 25 α once their wallet activates (stage1)
        if new1 and not c.execute(
                "SELECT 1 FROM payouts WHERE tg_id=? AND stage=?",
                (tg_id, 999999)).fetchone():
            try:
                txid = pay(wallet, 25.0)
                c.execute("INSERT INTO payouts(tg_id,amount,stage,txid,ts)"
                          " VALUES(?,?,?,?,datetime('now'))",
                          (tg_id, 25.0, 999999, txid))
                c.execute("UPDATE users SET earned=earned+25 WHERE tg_id=?",
                          (tg_id,))
                payouts += 1; paid_this_run += 25.0
                print(f"welcome bonus 25 α → friend tg {tg_id} tx {txid}")
            except Exception as e:
                print(f"welcome bonus failed tg {tg_id}: {e}")
        # referrer's tier by their verified referral count
        my_refs = ref_count.get(r_code, 0)
        mult = tier_reward(my_refs) / 500.0  # tier scales the 500-α base
        for stage, flag, reward in [(1, new1, 50), (2, new2, 150), (3, new3, 300)]:
            if flag and not c.execute(
                    "SELECT 1 FROM payouts WHERE tg_id=? AND stage=?",
                    (r_tg, stage * 100000 + tg_id)).fetchone():
                amt = round(reward * mult, 2)
                if amt <= 0 or paid_this_run + amt > MAX_PER_RUN:
                    continue
                try:
                    txid = pay(r_wallet, amt)
                    c.execute("INSERT INTO payouts(tg_id,amount,stage,txid,ts)"
                              " VALUES(?,?,?,?,datetime('now'))",
                              (r_tg, amt, stage * 100000 + tg_id, txid))
                    c.execute("UPDATE users SET earned=earned+? WHERE tg_id=?",
                              (amt, r_tg))
                    paid_this_run += amt
                    payouts += 1
                    print(f"paid {amt} α → referrer tg {r_tg} "
                          f"(friend tg {tg_id}) stage{stage} tx {txid}")
                except Exception as e:
                    print(f"payout failed ref tg {r_tg} stage{stage}: {e}")
        c.execute("UPDATE users SET stage1=?,stage2=?,stage3=? WHERE tg_id=?",
                  (new1, new2, new3, tg_id))
    c.commit()
    print(f"done: {payouts} payouts, {paid_this_run} α this run")


if __name__ == "__main__":
    ensure_hot_key()
    main()
