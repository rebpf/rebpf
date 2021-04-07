#!/bin/sh
IMAGE=bpf-build
TOP_DIR="$(cargo metadata --format-version=1 | grep -o 'path+file:///[^)]*' | sed -e '$!{N;s/^\(.*\).*\n\1\/.*$/\1\n\1/;D;}' | cut -c13-)"
BUILD_DIR=${PWD#"$TOP_DIR"}
CARGO_CACHE="/tmp/bpf-cargo-"$(whoami)
mkdir $CARGO_CACHE 2>/dev/null
docker run --rm --user=$(id -u) -w /project/$BUILD_DIR \
		--volume="$TOP_DIR":/project --volume="$CARGO_CACHE":/usr/local/cargo/registry \
		$IMAGE /bin/sh ./build.sh
