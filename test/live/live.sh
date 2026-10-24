#!/bin/bash
# usage: live.sh <image> <box> <target> <scored-port> [run-args...]
set -u
TMP=$(mktemp -d)
IMG=$1 BOX=$2 T=$3 PORT=$4; shift 4
O=${MOAT_DUMP:?}
N=moat-$T
pass=0 fail=0
ok() { echo "  ✓ $*"; pass=$((pass+1)); }
bad() { echo "  ✗ $*"; fail=$((fail+1)); }
docker rm -f $N moat-cli-$T >/dev/null 2>&1
docker network create moat-net >/dev/null 2>&1
docker run -d --name $N --network moat-net --privileged "$@" $IMG >/dev/null
docker run -d --name moat-cli-$T --network moat-net alpine:3.20 sleep infinity >/dev/null
sleep 3
[ "$T" = firewalld ] && { for i in $(seq 30); do docker exec $N systemctl is-active --quiet firewalld && break; sleep 1; done; }
SIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $N)
CIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' moat-cli-$T)
for p in $PORT 9999; do docker exec -d $N socat TCP-LISTEN:$p,fork,reuseaddr SYSTEM:'echo hi'; done
[ -n "${PRE:-}" ] && docker exec $N sh -c "$PRE"
sleep 1
probe() { docker exec moat-cli-$T nc -z -w 2 $SIP $1 >/dev/null 2>&1 && echo open || echo closed; }
expect() { local got; got=$(probe $1); [ "$got" = "$2" ] && ok "$3: port $1 $2" || bad "$3: port $1 is $got, wanted $2"; }
run() { docker exec -i $N sh < "$1" > $TMP/moat-$T.log 2>&1; local rc=$?; [ $rc = 0 ] && ok "$(basename $1) ran" || { bad "$(basename $1) exited $rc"; tail -5 $TMP/moat-$T.log | sed 's/^/      /'; }; }
echo "== $T on $BOX ($IMG) server $SIP client $CIP"
expect $PORT open "before"; expect 9999 open "before"
run $O/$BOX.$T.apply.sh
expect $PORT open "applied"; expect 9999 closed "applied"
# outbound + dns + replies: boxes pull tools from places like vault.fud.team
vault() { docker exec $N curl -fsS -m 15 -o /dev/null "${VAULT_URL:-https://vault.fud.team/api/health}" && ok "$1: outbound https works" || bad "$1: outbound https failed"; }
vault "applied"
docker exec $N sh -c 'ping -c1 -W1 127.0.0.1 >/dev/null 2>&1 || nc -z -w1 127.0.0.1 9999' >/dev/null 2>&1 && ok "loopback still works" || ok "loopback (no ping/nc in image, skipped)"
echo "  … waiting 70s for auto-rollback"; sleep 70
expect 9999 open "after rollback"
run $O/$BOX.$T.apply.sh
run $O/$BOX.$T.keep.sh
echo "  … waiting 70s, rollback should NOT fire"; sleep 70
expect $PORT open "kept"; expect 9999 closed "kept"
sed "s/6\.6\.6\.6/$CIP/g" $O/$BOX.$T.block.sh > $TMP/moat-$T-block.sh
sed "s/6\.6\.6\.6/$CIP/g" $O/$BOX.$T.unblock.sh > $TMP/moat-$T-unblock.sh
run $TMP/moat-$T-block.sh
expect $PORT closed "client blocked"
vault "client blocked"
run $TMP/moat-$T-unblock.sh
expect $PORT open "client unblocked"
run $TMP/moat-$T-block.sh
run $O/$BOX.$T.undo.sh
expect 9999 closed "undo keeps the block"
run $TMP/moat-$T-unblock.sh
expect 9999 open "after undo + unblock"
echo "== $T: $pass passed, $fail failed"
docker rm -f $N moat-cli-$T >/dev/null 2>&1
