#!/bin/bash
# Rolling restart on AWS: new code, one node at a time, health-checked.
# alphad-4 stays OFF (load decision) — not touched here.
exec > /home/ubuntu/deploy_restart.log 2>&1
set -x
cd /home/ubuntu/alpha-blockchain
git pull --ff-only

wait_rpc() {
  local port=$1 dd=$2 limit=$3 deadline=$(( $(date +%s) + limit ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if timeout 10 python3 alpha_cli.py --chain main --rpcport "$port" \
         --datadir "/home/ubuntu/$dd" getblockcount >/dev/null 2>&1; then
      return 0
    fi
    sleep 15
  done
  return 1
}

restart_pair() {
  sudo systemctl restart "$1"
  echo "$(date) restarted $1 — waiting for chain load..."
  if wait_rpc "$3" "$4" 21600; then
    echo "$(date) $1 HEALTHY — restarting miner $2"
    sudo systemctl restart "$2"
  else
    echo "$(date) ERROR: $1 NOT healthy after 6h — check journalctl -u $1"
  fi
}

restart_pair alphad-2.service alphamine-2.service 22012 alpha-data-2
restart_pair alphad-3.service alphamine-3.service 22013 alpha-data-3
restart_pair alphad.service   alphamine.service   8332  alpha-data

echo "$(date) DEPLOY DONE"
