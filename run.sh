#!/bin/bash

CARGO_TARGET_DIR="/home/orseti/dev/rust/pct/target"
cargo b --release
ext=$?
if [[ $ext -ne 0 ]]; then
	exit $ext
fi
sudo setcap cap_net_admin=eip $CARGO_TARGET_DIR/release/pct
$CARGO_TARGET_DIR/release/pct &
pid=$!
sudo ip addr add 10.0.0.2/24 dev tun2
sudo ip link set up dev tun2
trap "kill $pid" INT TERM
wait $pid
sudo ip link set up dev tun2
