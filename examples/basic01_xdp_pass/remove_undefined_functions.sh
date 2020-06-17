#!/bin/bash
INPUT_OBJ=$1
OUTPUT_OBJ=$2
cat $INPUT_OBJ | sed -E "s/(.*)call(.*)slice_index_len_fail(.*)/  ret i32 0/" | sed -E "s/(.*)call(.*)slice_index_order_fail(.*)/  ret i32 0/" | sed -E "s/(.*)call(.*)panic_bounds_check(.*)/  ret i32 0/" | sed -E "s/unreachable//" > $OUTPUT_OBJ
