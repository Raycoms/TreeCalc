#!/bin/sh
#tc qdisc add dev eth0 root netem delay 200ms
#tc qdisc add dev lo root netem delay 200ms
ulimit -n 100000
exec /usr/local/bin/tree