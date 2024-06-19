#!/bin/sh
# Author: Ahmad Yasin
# July 2023
# Donot modify! Use build.py

CC=${CC:-gcc -g -O2}
GEN=${GEN:-1}
PY=${PY:-python3}
RF=${RF:-1}

set -xe

if [ $GEN -eq 1 ]; then
$PY ./gen-kernel.py jumpy-seq -n 13 -i JMP -a 15  > jumpy13b15.c
$PY ./gen-kernel.py jumpy-seq -n 13 -i JMP -a 13  > jumpy13b13.c
$PY ./gen-kernel.py jumpy-seq -n 9 -i JMP -a 17  > itlb-miss-stlb-hit.c
$CC -S jumpy5p14.c
#$CC -o jumpy5p14 jumpy5p14.c
#perf stat -a --topdown -e instructions,BACLEARS.ANY --no-metric-only -C0 -- taskset 0x1 ./jumpy5p14 999999999

$PY ./gen-kernel.py -i "addps %xmm1,%xmm2" "vsubps %ymm1,%ymm2,%ymm3" -n10 > sse2avx.c
#$CC -o sse2avx sse2avx.c

$PY ./gen-kernel.py -i NOP 'test %rax,%rax' 'jle Lbl_end' -n 1 -a 6 --init-regs %rax > peak4wide.c
$PY ./gen-kernel.py -i NOP NOP 'test %rax,%rax' 'jle Lbl_end' -n 1 -a 6 --init-regs %rax > peak5wide.c
$PY ./gen-kernel.py -i NOP#3 'test %rax,%rax' 'jle Lbl_end' -n 1 -a 6 --init-regs %rax > peak6wide.c
$PY ./gen-kernel.py jumpy-seq -i NOP JMP -a3 -n30 > dsb-jmp.c
$PY ./gen-kernel.py jumpy-seq -i JG -a 6 -n 20000  > jcc20k.c
$PY ./gen-kernel.py jumpy-random -a 6 -i JMP -n 1024 > rfetch64k.c
if [ $RF -eq 1 ]; then
$PY ./gen-kernel.py jumpy-random -a 5 -i NOP5#30 JMP -n 19661 > rfetch3m.c
$PY ./gen-kernel.py jumpy-random -a 5 -i NOP5#56 JMP -n 10923 > rfetch3m-ic.c
fi
for x in add mul; do
  $PY ./gen-kernel.py -i "v${x}pd %ymm@,%ymm@,%ymm@" -r16 -n1 --reference MGM > fp-$x-bw.c
  $PY ./gen-kernel.py -i "v${x}pd %ymm@-1,%ymm@,%ymm@" -r16 -n10 --reference MGM > fp-$x-lat.c
done
$PY ./gen-kernel.py -i "vdivps %ymm@,%ymm@,%ymm@" -r3 -n1 > fp-divps.c
$PY ./gen-kernel.py -i 'vfmadd132pd %ymm10,%ymm11,%ymm11' 'vfmadd132ps %ymm12,%ymm13,%ymm13' 'vaddpd %xmm0,%xmm0,%xmm0' 'vaddps %xmm1,%xmm1,%xmm1' 'vsubsd %xmm2,%xmm2,%xmm2' 'vsubss %xmm3,%xmm3,%xmm3' -n1 --reference 'ICL-PMU' > fp-arith-mix.c
$PY ./gen-kernel.py -i 'xor %eax,%eax' 'xor %ecx,%ecx' cpuid -n1 > cpuid.c
$PY ./gen-kernel.py -i NOP#2 'mov 0x0(%rsp),%r12' 'test %r12,%r12' 'jg Lbl_end' -n 106 > ld-cmp-jcc-3i.c
$PY ./gen-kernel.py -i NOP#2 'cmpq $0x0,0x0(%rsp)' 'jg Lbl_end' -n 106 > ld-cmp-jcc-2i-imm.c
$PY ./gen-kernel.py -i NOP#2 'cmpq %r12,0x0(%rsp)' 'jg Lbl_end' -n 106 -p 'movq $0x0,%r12' > ld-cmp-jcc-2i-reg.c
$PY ./gen-kernel.py -i 'mov 0x0(%rsp),%r12' 'test %r12,%r12' 'jg Lbl_end' 'inc %rsp' 'dec %rsp' -n 1 > ld-cmp-jcc-3i-inc.c
$PY ./gen-kernel.py -i 'cmpq $0x0,0x0(%rsp)' 'jg Lbl_end' 'inc %rsp' 'dec %rsp' -n 1 > ld-cmp-jcc-2i-imm-inc.c
$PY ./gen-kernel.py -i 'cmpq %r12,0x0(%rsp)' 'jg Lbl_end' 'inc %r12' 'dec %r12' -p 'movq $0x0,%r12' -n 1 > ld-cmp-jcc-2i-reg-inc.c
$PY ./gen-kernel.py -p "mov %rsp,%rdx" "sub \$0x40000,%rdx" -i "cmpl \$0,0x40000(,%rdx,1)" -n 100 > cmp0-mem-index.c
$PY ./gen-kernel.py -i 'vshufps $0xff,%ymm0,%ymm1,%ymm2' 'vshufps $0xff,%ymm3,%ymm4,%ymm5' NOP 'mov (%rsp),%rbx' 'test %rax, %rax' 'jle Lbl_end' 'inc %rcx' --init-regs %rax > vshufps.c
$PY ./gen-kernel.py -i 'vpshufb %ymm0,%ymm1,%ymm2' 'vpshufb %ymm3,%ymm4,%ymm5' NOP 'mov (%rsp),%rbx' 'test %rax, %rax' 'jle Lbl_end' 'inc %rcx' --init-regs %rax > vpshufb.c
$PY ./gen-kernel.py -i 'mov 0x0(%rsp),%r12' 'add %r13,%r12' NOP -n 14 > ld-op-nop.c
$PY ./gen-kernel.py -i 'mov %r13,%r12' 'add %r14,%r12' NOP -n 14 > mov-op-nop.c
$PY ./gen-kernel.py -i 'mov 0x0(%rsp),%r12' NOP 'add %r13,%r12' -n 14 > ld-nop-op.c
$PY ./gen-kernel.py -i 'mov %r13,%r12' NOP 'add %r14,%r12' -n 14 > mov-nop-op.c
fi

ks="cpuid,dsb-jmp,fp-{{add,mul}-{bw,lat},arith-mix,divps},jcc20k,jumpy*,ld-cmp-jcc-{3i,2i-{imm,reg}}{,-inc},{ld,mov}-{op-nop,nop-op},cmp0-mem-index,memcpy,pagefault,peak*,rfetch{64k,3m{,-ic}},sse2avx,itlb-miss-stlb-hit,vshufps,vpshufb,tripcount-mean"
kernels=`bash -c "ls {$ks}.c | sed 's/\.c//'"`
for x in $kernels; do
  $CC -o $x $x.c
done

x=callchain
$CC -O0 -fno-inline $x.c -o $x
$CC -O0 -pthread false-sharing.c -o false-sharing
$CC -march=native -DRDTSC_ONLY tpause.c -o rdtsc
$CC -march=native tpause.c -o tpause # requires newer GCC and binutils
