#!/bin/sh
#tc qdisc add dev eth0 root netem delay 200ms
#tc qdisc add dev lo root netem delay 200ms
ulimit -n 100000

configurations=(256 320)
cores=(2 4 6 8 10 12 14 16)
participationrate=(6 20 200)

# Iterate using indices
for x in "${configurations[@]}"; do
    for y in "${cores[@]}"; do
        for z in "${participationrate[@]}"; do
            echo "Running Configuration: $x Cores: $y Participation Rate $z"
            exec /usr/local/bin/tree $x $y $z | grep "final"
        done
    done
done


