#!/bin/bash
BPF_PROG_NAME="kern"
USER_PROG_NAME="user"
OUT_DIR="ebpf_output"
LLC_OPTIONS="-march=bpf -filetype=obj"
LLC=llc-9
OUT_BC=$OUT_DIR"/"$BPF_PROG_NAME".bc"
OUT_ELF=$OUT_DIR"/"$BPF_PROG_NAME".o"

mkdir -p $OUT_DIR
TARGET=$(echo target/release/deps/kern*.bc)
rm -f $TARGET
cargo rustc --lib --release -- --emit=llvm-bc
cp $TARGET $OUT_BC
$LLC $OUT_BC $LLC_OPTIONS -o $OUT_ELF 
cargo build --release
TARGET=$(echo target/release/user)
cp $TARGET $OUT_DIR
