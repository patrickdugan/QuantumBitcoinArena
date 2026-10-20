#!/usr/bin/env bash
# Throwaway Bitcoin Core regtest node for the pqcd harness (foreground).
#   scripts/regtest-node.sh <datadir> [path/to/bitcoind]
# RPC: 127.0.0.1:18643, user pqcd, password pqcd-regtest-only. No P2P.
set -euo pipefail
dir="$1"; bitcoind="${2:-bitcoind}"
mkdir -p "$dir"
cat > "$dir/bitcoin.conf" <<CONF
regtest=1
server=1
txindex=1
fallbackfee=0.0002
[regtest]
rpcuser=pqcd
rpcpassword=pqcd-regtest-only
rpcport=18643
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
port=18644
connect=0
listen=0
CONF
exec "$bitcoind" -datadir="$dir"
