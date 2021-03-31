#!/bin/bash
INPUT_OBJ=$1
OUTPUT_OBJ=$2
cat $INPUT_OBJ | sed -zE "s/\n([^;\n]*)call([^\n]*)std::panic::Location([^\n]*)\n  unreachable\n/\n  ret i32 0\n/g" > $OUTPUT_OBJ
