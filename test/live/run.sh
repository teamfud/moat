#!/bin/bash
# Runs the generated linux scripts for real, in privileged containers: apply,
# auto-rollback, keep it, block/unblock the client, undo. Takes ~3 min.
# Windows and pfsense output need ur own VMs.
set -eu
cd "$(dirname "$0")"
export MOAT_DUMP=$(mktemp -d)
(cd ../.. && npx vitest run src/lib/fw/render/dump.test.ts >/dev/null)
for i in debian ubuntu rocky; do docker build -q -t moat-test-$i images/$i >/dev/null; done
docker pull -q alpine:3.20 >/dev/null
L=$(mktemp -d)
./live.sh moat-test-debian pitlane nftables 22 > $L/nft.log 2>&1 &
./live.sh moat-test-debian pitlane iptables 22 > $L/ipt.log 2>&1 &
./live.sh moat-test-ubuntu garage ufw 21 > $L/ufw.log 2>&1 &
# rocky's default zone already blocks these, so open them first to see the rollback reopen them
PRE='firewall-cmd -q --permanent --add-port=9999/tcp --add-port=3306/tcp && firewall-cmd -q --reload' \
  ./live.sh moat-test-rocky scrutineering firewalld 3306 > $L/fwd.log 2>&1 &
wait
cat $L/*.log
docker network rm moat-net >/dev/null 2>&1 || true
! grep -q "✗" $L/*.log
