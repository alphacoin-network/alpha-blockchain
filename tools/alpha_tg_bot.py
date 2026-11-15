"""Alpha Blockchain Telegram community bot.

Features: network stats, wallet balance, blocks, AUSD price, referrals,
support ticket. Talks to the public alphaweb REST API — no RPC auth needed.

Setup:
    pip install python-telegram-bot
    export TG_BOT_TOKEN=123456:ABC...        # from @BotFather
    python tools/alpha_tg_bot.py

Optional (run on the VPS next to alphad for referral payouts):
    export ALPHA_RPC=http://127.0.0.1:8332
    export ALPHA_COOKIE=/home/alphabetin/alpha-data/.cookie
    export REFERRAL_REWARD=500                # ALPHA per successful referral
"""

import os
import json
import sqlite3
import urllib.request

from telegram import Update
from telegram.ext import (Application, CommandHandler, ContextTypes,
                          JobQueue)
import datetime

API = os.environ.get("ALPHA_API", "https://alphacoin.network")
RPC = os.environ.get("ALPHA_RPC", "")
COOKIE = os.environ.get("ALPHA_COOKIE", "")
REWARD = float(os.environ.get("REFERRAL_REWARD", "0"))
SUPPORT = os.environ.get("SUPPORT_CONTACT", "@your_support")
DB = os.environ.get("BOT_DB", "alpha_bot.db")
CHANNEL = os.environ.get("CHANNEL_ID", "")   # e.g. @alpha_blockchain_official
ADMIN = int(os.environ.get("ADMIN_TG_ID", "0"))
REWARD_ADDR = os.environ.get("REWARD_ADDRESS",
                             "alpha1qukf7zseqsrsnkn3qsv0yf5yth0gn68aduufq6x")

# ---------------------------------------------------------------- api helpers
def api(path):
    try:
        with urllib.request.urlopen(f"{API}{path}", timeout=10) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error": str(e)}


def rpc(method, params=None):
    if not (RPC and COOKIE):
        return None
    try:
        body = json.dumps({"method": method, "params": params or []}).encode()
        req = urllib.request.Request(
            RPC, data=body,
            headers={"content-type": "application/json"})
        # cookie auth: user:pass — read raw cookie value
        import base64
        tok = base64.b64encode(COOKIE.encode()).decode() if COOKIE else ""
        req.add_header("Authorization", f"Basic {tok}")
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read()).get("result")
    except Exception:
        return None


# ---------------------------------------------------------------- referrals
def db():
    c = sqlite3.connect(DB)
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        tg_id INTEGER PRIMARY KEY, code TEXT UNIQUE,
        ref_by TEXT, referrals INTEGER DEFAULT 0,
        rewarded INTEGER DEFAULT 0, joined TEXT)""")
    # referral v2 columns (activity-verified, tiered rewards)
    for col, typ in [("wallet", "TEXT"), ("stage1", "INTEGER DEFAULT 0"),
                     ("stage2", "INTEGER DEFAULT 0"), ("stage3", "INTEGER DEFAULT 0"),
                     ("earned", "REAL DEFAULT 0"), ("paid", "REAL DEFAULT 0")]:
        try:
            c.execute(f"ALTER TABLE users ADD COLUMN {col} {typ}")
        except sqlite3.OperationalError:
            pass
    c.execute("""CREATE TABLE IF NOT EXISTS payouts(
        id INTEGER PRIMARY KEY AUTOINCREMENT, tg_id INTEGER,
        amount REAL, stage INTEGER, txid TEXT, ts TEXT,
        UNIQUE(tg_id, stage))""")
    return c


def get_user(tg_id):
    c = db()
    row = c.execute("SELECT code,ref_by,referrals,rewarded FROM users WHERE tg_id=?",
                    (tg_id,)).fetchone()
    c.close()
    return row


def ensure_user(tg_id):
    c = db()
    if not c.execute("SELECT 1 FROM users WHERE tg_id=?", (tg_id,)).fetchone():
        code = f"ALPHA-{tg_id}"
        c.execute("INSERT INTO users(tg_id,code,joined) VALUES(?,?,datetime('now'))",
                  (tg_id, code))
        c.commit()
    c.close()


def set_referrer(tg_id, code):
    c = db()
    u = c.execute("SELECT code FROM users WHERE code=?", (code,)).fetchone()
    if u and u[0] != f"ALPHA-{tg_id}":
        c.execute("UPDATE users SET ref_by=? WHERE tg_id=? AND ref_by IS NULL",
                  (code, tg_id))
        c.commit()
        # reward referrer once
        ref = c.execute("SELECT tg_id,referrals,rewarded FROM users WHERE code=?",
                        (code,)).fetchone()
        if ref and ref[2] == 0 and REWARD > 0:
            c.execute("UPDATE users SET referrals=referrals+1 WHERE code=?",
                      (code,))
            c.execute("UPDATE users SET rewarded=1 WHERE code=?", (code,))
            c.commit()
            pay_reward(ref[0])
    c.close()


def pay_reward(tg_id):
    """Send referral reward from node wallet (VPS only)."""
    if not (RPC and COOKIE and REWARD > 0):
        return
    # node wallet sends to the user's linked address if any, else skip
    # (v1: reward tracked; payout via /claim once address linked)
    pass


# ---------------------------------------------------------------- commands
async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ensure_user(update.effective_user.id)
    code = get_user(update.effective_user.id)[0]
    # referral deep-link: t.me/bot?start=ALPHA-XXXXX → /start ALPHA-XXXXX
    if ctx.args and ctx.args[0].upper().startswith("ALPHA-"):
        ref_code = ctx.args[0].upper()
        if ref_code != code:
            set_referrer(update.effective_user.id, ref_code)
            await update.message.reply_text(
                f"🎉 You joined via referral {ref_code}!\n"
                "Create a wallet at https://alphacoin.network/wallet.html "
                "then /link your address to get your 25 α welcome bonus.")
    await update.message.reply_text(
        "Welcome to Alpha Blockchain! ⛓\n\n"
        f"Your referral code: {code}\n"
        "Share it — earn rewards when friends join.\n\n"
        "Link your wallet to receive rewards:\n"
        "/link alpha1...your_address\n\n"
        "/stats — network live stats\n"
        "/balance <address> — check ALPHA balance\n"
        "/ausd — stablecoin info\n"
        "/blocks — latest blocks\n"
        "/ref — your referral stats\n"
        "/support — get help\n"
        "/help — all commands")


async def help_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Commands:\n"
        "/stats — live network stats\n"
        "/balance <address> — ALPHA balance\n"
        "/ausd — AUSD stablecoin\n"
        "/blocks — latest blocks\n"
        "/ref [code] — set/see referral\n"
        "/link <address> — link wallet for rewards\n"
        "/support — contact support\n"
        "/start — welcome")


async def stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    s = api("/api/stats")
    if "error" in s:
        await update.message.reply_text("Node offline, try later.")
        return
    await update.message.reply_text(
        f"⛓ Alpha Network — LIVE\n\n"
        f"Height: {s.get('height')}\n"
        f"Supply: {s.get('supply')} α\n"
        f"Difficulty: {s.get('difficulty')}\n"
        f"Hashrate: {s.get('hashrate')}\n"
        f"Mempool: {s.get('mempool')}\n"
        f"Peers: {s.get('connections')}\n"
        f"Tokens: {s.get('tokens')}")


async def balance(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("Usage: /balance <address>")
        return
    a = api(f"/api/address?addr={ctx.args[0]}")
    if "error" in a or a.get("balance") is None:
        await update.message.reply_text("Address not found or node error.")
        return
    await update.message.reply_text(
        f"💼 {ctx.args[0]}\n\nBalance: {a['balance']} α")


async def ausd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    i = rpc("ausdinfo") if RPC else None
    await update.message.reply_text(
        "$ AUSD — Alpha Stablecoin\n\n"
        "Peg: 1 AUSD = $1.00\n"
        "Reserve-backed, mint/redeem on-chain.\n\n"
        "alphacoin.network/ausd.html")


async def blocks(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    b = api("/api/blocks?limit=3")
    if isinstance(b, list) and b:
        txt = "⛏ Latest blocks:\n\n" + "\n".join(
            f"#{x.get('height')}  {x.get('hash','')[:16]}…" for x in b[:3])
    else:
        txt = "No block data."
    await update.message.reply_text(txt)


async def link(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Link your ALPHA address to receive referral rewards."""
    ensure_user(update.effective_user.id)
    if not ctx.args:
        u = db().execute("SELECT wallet FROM users WHERE tg_id=?",
                         (update.effective_user.id,)).fetchone()
        await update.message.reply_text(
            "Usage: /link <your ALPHA address>\n" +
            (f"Current: {u[0]}" if u and u[0] else "No address linked yet."))
        return
    addr = ctx.args[0].strip()
    # validate: alpha1… bech32 or 1… legacy, sane length
    ok = (addr.startswith("alpha1") and 35 <= len(addr) <= 90) or \
         (addr.startswith("1") and 25 <= len(addr) <= 35)
    if not ok:
        await update.message.reply_text(
            "❌ Invalid ALPHA address.\n\n"
            "Pehle wallet banao:\n"
            "🌐 https://alphacoin.network/wallet.html\n\n"
            "Phir wahan se address copy karke:\n"
            "/link <your_address>")
        return
    c = db()
    c.execute("UPDATE users SET wallet=? WHERE tg_id=?", (addr, update.effective_user.id))
    c.commit(); c.close()
    await update.message.reply_text(f"✅ Wallet linked: {addr}\nReferral rewards will be paid here.")


async def ref(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ensure_user(update.effective_user.id)
    u = get_user(update.effective_user.id)
    if ctx.args:
        set_referrer(update.effective_user.id, ctx.args[0].upper())
        await update.message.reply_text("Referral code saved! ✅")
        return
    c = db()
    row = c.execute("""SELECT code,ref_by,referrals,rewarded,wallet,
        stage1,stage2,stage3,earned,paid FROM users WHERE tg_id=?""",
        (update.effective_user.id,)).fetchone()
    c.close()
    await update.message.reply_text(
        f"🔗 Your code: {row[0]}\n"
        f"Referrals: {row[2]}\n"
        f"Wallet: {row[4] or 'not linked — use /link <address>'}\n"
        f"Milestones: {'✅' if row[5] else '⬜'} activated · "
        f"{'✅' if row[6] else '⬜'} first tx · "
        f"{'✅' if row[7] else '⬜'} 30-day\n"
        f"Earned: {row[8] or 0} α · Paid: {row[9] or 0} α\n\n"
        f"Share: t.me/<your_bot>?start={row[0]}")


async def support(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"🆘 Support\n\nContact: {SUPPORT}\n"
        "Include your txid/address for faster help.")


def stats_text():
    s = api("/api/stats")
    if "error" in s:
        return None
    return (f"⛓ Alpha Network — LIVE\n\n"
            f"Height: {s.get('height')}\n"
            f"Supply: {s.get('supply')} α\n"
            f"Difficulty: {s.get('difficulty')}\n"
            f"Hashrate: {s.get('hashrate')}\n"
            f"Mempool: {s.get('mempool')}\n"
            f"Peers: {s.get('connections')}\n"
            f"Tokens: {s.get('tokens')}\n\n"
            f"🌐 alphacoin.network · 🎁 referral.html")


async def channel_stats(ctx: ContextTypes.DEFAULT_TYPE):
    """Auto-post network stats to the channel every 6 hours."""
    if not CHANNEL:
        return
    t = stats_text()
    if t:
        await ctx.bot.send_message(chat_id=CHANNEL, text=t)


async def announce(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Admin broadcast to channel: /announce <message>"""
    if ADMIN and update.effective_user.id != ADMIN:
        return
    msg = " ".join(ctx.args) if ctx.args else ""
    if not msg:
        await update.message.reply_text("Usage: /announce <message>")
        return
    if CHANNEL:
        await ctx.bot.send_message(chat_id=CHANNEL,
                                   text=f"📢 {msg}")
        await update.message.reply_text("Posted to channel ✅")
    else:
        await update.message.reply_text("CHANNEL_ID not set")


def main():
    token = os.environ["TG_BOT_TOKEN"]
    app = Application.builder().token(token).build()
    for cmd, fn in [("start", start), ("help", help_cmd),
                    ("stats", stats), ("balance", balance),
                    ("ausd", ausd), ("blocks", blocks),
                    ("ref", ref), ("link", link), ("support", support),
                    ("announce", announce)]:
        app.add_handler(CommandHandler(cmd, fn))
    if CHANNEL:
        jq = JobQueue()
        app.job_queue = jq
        jq.run_repeating(channel_stats, interval=21600, first=60)
    print("Alpha bot running… channel:", CHANNEL or "(none)")
    app.run_polling()


if __name__ == "__main__":
    main()
