#!/bin/sh
BPF_PROG_NAME="kern"
USER_PROG_NAME="user"
OUT_DIR="ebpf_output"
LLC_OPTIONS="-march=bpf -filetype=obj"
LLC=$(which llc-11 2>/dev/null || which llc)
OUT_IR_TEMP=$OUT_DIR"/"$BPF_PROG_NAME"_temp.ll"
OUT_IR=$OUT_DIR"/"$BPF_PROG_NAME".ll"
OUT_ELF=$OUT_DIR"/"$BPF_PROG_NAME".o"
RM_UND=./remove_undefined_functions.sh

mkdir -p $OUT_DIR
TARGET_DIRECTORY="target/release/deps"
TARGET=$(echo $TARGET_DIRECTORY"/kern*.ll")
if [ -d $TARGET_DIRECTORY ]; then
    rm -f $TARGET
fi
cargo rustc --lib --release -- --emit=llvm-ir
cp $TARGET $OUT_IR_TEMP
$RM_UND $OUT_IR_TEMP $OUT_IR
$LLC $OUT_IR $LLC_OPTIONS -o $OUT_ELF 
#llvm-objcopy $OUT_ELF --remove-section=.text
cargo build --release --bin user
TARGET=$(echo target/release/user)
cp $TARGET $OUT_DIR
