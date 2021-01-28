#!/bin/bash

CARGO_TARGET_DIR="/home/orseti/dev/rust/pct/target"
cargo b --release
ext=$?
if [[ $ext -ne 0 ]]; then
	exit $ext
fi
sudo setcap cap_net_admin=eip $CARGO_TARGET_DIR/release/pct
RUST_BACKTRACE=1 $CARGO_TARGET_DIR/release/pct &
pid=$!
sudo ip addr add 10.0.0.2/24 dev tap0
sudo ip link set up dev tap0
trap "kill $pid" INT TERM
wait $pid
