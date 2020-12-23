#!/bin/sh
# Author: Ahmad Yasin
# Dec. 2020
#
CC='gcc -g -O2'
set -x

./gen-kernel.py jumpy -n 5 -i JMP -a 14  > jumpy5p14.c
$CC -S jumpy5p14.c
#$CC -o jumpy5p14 jumpy5p14.c
#perf stat -a --topdown -e instructions,BACLEARS.ANY --no-metric-only -C0 -- taskset 0x1 ./jumpy5p14 999999999

./gen-kernel.py -i "addps %xmm1,%xmm2" "vsubps %ymm1,%ymm2,%ymm3" -n10 > sse2avx.c
#$CC -o sse2avx sse2avx.c

./gen-kernel.py -i NOP 'test %rax,%rax' 'jle Lbl_end' -n 1 -a 6 > peak4wide.c
./gen-kernel.py jumpy -i JL -a 6 -n 20000  > jcc20k.c

for x in jumpy5p14 jcc20k sse2avx peak4wide; do
  $CC -o $x $x.c
done
