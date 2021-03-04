#!/bin/sh
# Author: Ahmad Yasin
# Mar. 2021
#
CC='gcc -g -O2'
set -xe

./gen-kernel.py jumpy-seq -n 5 -i JMP -a 14  > jumpy5p14.c
$CC -S jumpy5p14.c
#$CC -o jumpy5p14 jumpy5p14.c
#perf stat -a --topdown -e instructions,BACLEARS.ANY --no-metric-only -C0 -- taskset 0x1 ./jumpy5p14 999999999

./gen-kernel.py -i "addps %xmm1,%xmm2" "vsubps %ymm1,%ymm2,%ymm3" -n10 > sse2avx.c
#$CC -o sse2avx sse2avx.c

./gen-kernel.py -i NOP 'test %rax,%rax' 'jle Lbl_end' -n 1 -a 6 > peak4wide.c
./gen-kernel.py jumpy-seq -i JL -a 6 -n 20000  > jcc20k.c
./gen-kernel.py jumpy-random -a 6 -i JMP -n 1024 > rfetch64k.c
./gen-kernel.py jumpy-random -a 6 -i JMP -n 49152 > rfetch3m.c
./gen-kernel.py -i 'vaddpd %ymm@,%ymm@,%ymm@' -r16 -n1 > fp-add-bw.c
./gen-kernel.py -i 'vaddpd %ymm@-1,%ymm@,%ymm@' -r16 -n1 > fp-add-lat.c

for x in rfetch{64k,3m} jumpy5p14 jcc20k sse2avx peak[45]wide fp-add-{bw,lat}; do
  $CC -o $x $x.c
done
