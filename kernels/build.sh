#!/bin/sh
# Author: Ahmad Yasin
# Jul. 2021
#
CC=${CC:-gcc -g -O2}
GEN=${GEN:-1}
PY=${PY:-python3}

set -xe

if [ $GEN -eq 1 ]; then
$PY ./gen-kernel.py jumpy-seq -n 13 -i JMP -a 15  > jumpy13b15.c
$PY ./gen-kernel.py jumpy-seq -n 13 -i JMP -a 13  > jumpy13b13.c
$CC -S jumpy5p14.c
#$CC -o jumpy5p14 jumpy5p14.c
#perf stat -a --topdown -e instructions,BACLEARS.ANY --no-metric-only -C0 -- taskset 0x1 ./jumpy5p14 999999999

$PY ./gen-kernel.py -i "addps %xmm1,%xmm2" "vsubps %ymm1,%ymm2,%ymm3" -n10 > sse2avx.c
#$CC -o sse2avx sse2avx.c

$PY ./gen-kernel.py -i NOP 'test %rax,%rax' 'jle Lbl_end' -n 1 -a 6 > peak4wide.c
$PY ./gen-kernel.py -i NOP NOP 'test %rax,%rax' 'jle Lbl_end' -n 1 -a 6 > peak5wide.c
$PY ./gen-kernel.py jumpy-seq -i JG -a 6 -n 20000  > jcc20k.c
$PY ./gen-kernel.py jumpy-random -a 6 -i JMP -n 1024 > rfetch64k.c
$PY ./gen-kernel.py jumpy-random -a 6 -i JMP -n 49152 > rfetch3m.c
$PY ./gen-kernel.py -i 'vaddpd %ymm@,%ymm@,%ymm@' -r16 -n1 > fp-add-bw.c
$PY ./gen-kernel.py -i 'vaddpd %ymm@-1,%ymm@,%ymm@' -r16 -n10 > fp-add-lat.c
$PY ./gen-kernel.py -i 'vmulpd %ymm@,%ymm@,%ymm@' -r16 -n1 > fp-mul-bw.c
$PY ./gen-kernel.py -i 'vmulpd %ymm@-1,%ymm@,%ymm@' -r16 -n10 > fp-mul-lat.c
fi

ks="fp-{add,mul}-{bw,lat},jcc20k,jumpy*,memcpy,peak[45]wide,rfetch{64k,3m},sse2avx"
kernels=`bash -c "ls {$ks}.c | sed 's/\.c//'"`
for x in $kernels; do
  $CC -o $x $x.c
done
