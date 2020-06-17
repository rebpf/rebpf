#!/bin/bash
BPF_PROG_NAME="kern"
USER_PROG_NAME="user"
OUT_DIR="ebpf_output"
LLVM_DIS=llvm-dis-9
LLC_OPTIONS="-march=bpf -filetype=obj"
LLC=llc-9
OUT_BC=$OUT_DIR"/"$BPF_PROG_NAME".bc"
OUT_IR_TEMP=$OUT_DIR"/"$BPF_PROG_NAME"_temp.ll"
OUT_IR=$OUT_DIR"/"$BPF_PROG_NAME".ll"
OUT_ELF=$OUT_DIR"/"$BPF_PROG_NAME".o"
RM_UND=./remove_undefined_functions.sh

mkdir -p $OUT_DIR
TARGET=$(echo target/release/deps/kern*.bc)
rm -f $TARGET
cargo rustc --lib --release -- --emit=llvm-bc
cp $TARGET $OUT_BC
$LLVM_DIS $OUT_BC -o $OUT_IR_TEMP
$RM_UND $OUT_IR_TEMP $OUT_IR
$LLC $OUT_IR $LLC_OPTIONS -o $OUT_ELF 
#llvm-objcopy $OUT_ELF --remove-section=.text
cargo build --release --bin user
TARGET=$(echo target/release/user)
cp $TARGET $OUT_DIR
