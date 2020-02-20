#!/bin/bash
PROG_NAME="xdp_basic01"
OUT_DIR="ebpf_output"
LLC_OPTIONS="-march=bpf -filetype=obj"
LLC=llc
OUT_BC=$OUT_DIR"/kern.bc"
OUT_ELF=$OUT_DIR"/"$PROG_NAME".o"

mkdir -p $OUT_DIR
cargo rustc --lib --release -- --emit=llvm-bc
TARGET=$(echo target/release/deps/kern*.bc)
cp $TARGET $OUT_BC
$LLC $OUT_BC $LLC_OPTIONS -o $OUT_ELF 
