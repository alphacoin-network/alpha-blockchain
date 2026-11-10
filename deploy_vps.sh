#!/usr/bin/env bash
# Alpha Blockchain — one-command VPS/AWS deployment
# Run on Ubuntu/Debian server:  bash deploy_vps.sh
#
# What it does:
#   1. Installs Python 3 + git
#   2. Clones the repo (or uses current dir)
#   3. Starts alphad mainnet node (mining enabled via RPC)
#   4. Starts alphaweb explorer on port 8080
#   5. Prints commands for continuous mining + firewall rules
set -e

REPO_URL="${REPO_URL:-https://github.com/alphacoin-network/alpha-blockchain.git}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/alpha-blockchain}"
DATADIR="${DATADIR:-$HOME/alpha-data}"
WEB_PORT="${WEB_PORT:-8080}"
P2P_PORT="${P2P_PORT:-8333}"
RPC_PORT="${RPC_PORT:-8332}"

echo "=== Alpha Blockchain deploy ==="
# 1. deps
if ! command -v python3 >/dev/null; then
  sudo apt-get update -y && sudo apt-get install -y python3 git
fi

# 2. code
if [ ! -d "$INSTALL_DIR" ]; then
  git clone "$REPO_URL" "$INSTALL_DIR"
fi
cd "$INSTALL_DIR" && git pull --ff-only || true

# 3. firewall hints (uncomment for ufw)
# sudo ufw allow $P2P_PORT/tcp   # p2p
# sudo ufw allow $WEB_PORT/tcp   # explorer (or proxy via nginx)

# 4. start node (P2P listening so other nodes can sync)
pkill -f "alphad.py" 2>/dev/null || true
mkdir -p "$DATADIR"
nohup python3 alphad.py --chain main --datadir "$DATADIR" \
      --port "$P2P_PORT" --rpcport "$RPC_PORT" \
      > "$DATADIR/alphad.log" 2>&1 &
echo "alphad started (rpc :$RPC_PORT, p2p :$P2P_PORT) — log: $DATADIR/alphad.log"

# 5. start explorer/website
pkill -f "alphaweb.py" 2>/dev/null || true
nohup python3 alphaweb.py --port "$WEB_PORT" \
      > "$DATADIR/alphaweb.log" 2>&1 &
echo "alphaweb started — http://YOUR_SERVER_IP:$WEB_PORT"

echo
echo "=== Mining (CPU) ==="
echo "Mine continuously to your address:"
echo "  python3 - <<'PY'"
echo "  # get address: ./alpha_cli.py getnewaddress --rpcport $RPC_PORT"
echo "PY"
echo "  ./alpha_cli.py generatetoaddress 1000000000 <YOUR_ADDRESS> --rpcport $RPC_PORT"
echo
echo "Check status:  ./alpha_cli.py getblockchaininfo --rpcport $RPC_PORT"
echo "Stop node:     pkill -f alphad.py"
