#!/bin/bash
# Rolling restart: new code, one node at a time, health-checked.
exec > /home/alphabetin/deploy_restart.log 2>&1
set -x
cd /home/alphabetin/alpha-blockchain

sudo systemctl restart alphaweb.service
echo "$(date) alphaweb restarted"

wait_rpc() {  # rpcport datadir timeout_sec
  local port=$1 dd=$2 limit=$3 deadline=$(( $(date +%s) + limit ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if timeout 10 python3 alpha_cli.py --chain main --rpcport "$port" \
         --datadir "/home/alphabetin/$dd" getblockcount >/dev/null 2>&1; then
      return 0
    fi
    sleep 15
  done
  return 1
}

restart_pair() {  # node_unit miner_unit rpcport datadir
  sudo systemctl restart "$1"
  echo "$(date) restarted $1 — waiting for chain load (can take ~1h)..."
  if wait_rpc "$3" "$4" 18000; then
    echo "$(date) $1 HEALTHY — restarting miner $2"
    sudo systemctl restart "$2"
  else
    echo "$(date) ERROR: $1 NOT healthy after 5h — check journalctl -u $1"
  fi
}

restart_pair alphad-2.service alphamine-2.service 21012 alpha-data-2
restart_pair alphad-3.service alphamine-3.service 21013 alpha-data-3
restart_pair alphad-4.service alphamine-4.service 21014 alpha-data-4
restart_pair alphad-5.service alphamine-5.service 21015 alpha-data-5
restart_pair alphad.service   alphamine.service   8332  alpha-data

echo "$(date) DEPLOY DONE"
