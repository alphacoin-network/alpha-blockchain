ALPHA BLOCKCHAIN NODE — Windows
================================

NO installation needed. No Python needed. Just download + run.

QUICK START
-----------
1. Double-click  Start-Alpha-Node.bat
   → a black window opens and syncs the blockchain
   → keep it open to keep your node online
   (first run: Windows may warn "unrecognized app" —
    click "More info" → "Run anyway")

2. That's it — you're part of the network.
   The node auto-connects to public seeds and verifies
   the whole chain by itself.

OPTIONAL
--------
- Commands (new window):  alpha_cli.exe getblockcount
                          alpha_cli.exe getconnectioncount
- Explorer:               https://explorer.alphacoin.network
- Wallet:                 https://wallet.alphacoin.network

NOTES
-----
- ~5 GB disk for the chain (grows slowly over time)
- Works behind home routers/NAT — no port forwarding required
  (open port 8333 in firewall if you want to accept inbound peers)
- Your node NEVER shares keys — wallet stays on your machine
