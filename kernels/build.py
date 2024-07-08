#!/usr/bin/env python3
# Copyright (c) 2020-2024, Intel Corporation
# Authors: Ahmad Yasin, Sinduri Gundu
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

import argparse, os, subprocess, sys

assert sys.version_info.major >=3, "Python version 3.0 or higher is required."

cwd = os.getcwd()
sys.path.append(cwd[:cwd.rfind('kernels')]) #Add directory containing pmu.py to the path
from pmu import goldencove_on, server, cpu_pipeline_width
from common import exe_cmd

parser = argparse.ArgumentParser(
            prog='build.py',
            description='Generates kernel source code and builds them'
            )
parser.add_argument('--CC', default='gcc -g -O2', help='compiler and flags', required=False)
parser.add_argument('--GEN', type=int, default=1, help='1 = generate kernel source code; 0 = skip this step; Default = 1', required=False)
parser.add_argument('--PY', default='python3', help='Python version', required=False)
parser.add_argument('--RF', type=int, default=1, help='1 = generate rfetch kernels; 0 = skip this step; Default = 1', required=False)
args = parser.parse_args()

kernels = []
pipelineWidth = cpu_pipeline_width()

#generate source code with gen-kernel script.
#print command to screen
def gen_kernel(params, filename):
    gen_kernel_command = '{python} ./gen-kernel.py {params}'.format(python=args.PY, params=params)
    exe_cmd(gen_kernel_command, redir_out=' > '+filename+'.c', debug=True)
    kernels.append(filename)

def build_kernel(source, output=None, flags=''):
    if output is None:
        output = source
    build_command = '{CC} {flags} {source}.c -o {output}'.format(CC=args.CC, flags=flags, source=source, output=output)
    exe_cmd(build_command, debug=True)

if args.GEN:
    gen_kernel("jumpy-seq -n 13 -i JMP -a 15", 'jumpy13b15') 
    gen_kernel("jumpy-seq -n 13 -i JMP -a 13", 'jumpy13b13')
    gen_kernel("jumpy-seq -n 9 -i JMP -a 17", 'itlb-miss-stlb-hit')

    subprocess.run('{CC} -S jumpy5p14.c'.format(CC=args.CC), shell=True)
    kernels.append("jumpy5p14")

    gen_kernel("-i 'addps %xmm1,%xmm2' 'vsubps %ymm1,%ymm2,%ymm3' -n10", 'sse2avx')

    gen_kernel("-i NOP#{nopCount} 'test %rax,%rax' 'jle Lbl_end' -n 1 -a 6 --init-regs rax".format(nopCount=(pipelineWidth-3)), 'peak'+str(pipelineWidth)+'wide')
    gen_kernel("jumpy-seq -i NOP JMP -a3 -n30", 'dsb-jmp')
    gen_kernel("jumpy-seq -i JG -a 6 -n 20000", 'jcc20k')
    gen_kernel("jumpy-random -a 6 -i JMP -n 1024", 'rfetch64k')

    if args.RF:
        gen_kernel("jumpy-random -a 5 -i NOP5#30 JMP -n 19661", 'rfetch3m')
        gen_kernel("jumpy-random -a 5 -i NOP5#56 JMP -n 10923", 'rfetch3m-ic')

    for x in ['add', 'mul']:
        gen_kernel("-i 'v{x}pd %ymm@,%ymm@,%ymm@' -r16 -n1 --reference MGM".format(x=x), 'fp-{x}-bw'.format(x=x))
        gen_kernel("-i 'v{x}pd %ymm@-1,%ymm@,%ymm@' -r16 -n10 --reference MGM".format(x=x), 'fp-{x}-lat'.format(x=x))
        if server():
            gen_kernel("-i 'v{x}pd %zmm0,%zmm1,%zmm2' 'v{x}pd %zmm3,%zmm4,%zmm5' NOP 'mov (%rsp),%rbx' -n1".format(x=x), 'fp-{x}-512'.format(x=x))

    gen_kernel("-i 'vdivps %ymm@,%ymm@,%ymm@' -r3 -n1", 'fp-divps')
    gen_kernel("-i 'vfmadd132pd %ymm10,%ymm11,%ymm11' 'vfmadd132ps %ymm12,%ymm13,%ymm13' 'vaddpd %xmm0,%xmm0,%xmm0' 'vaddps %xmm1,%xmm1,%xmm1' 'vsubsd %xmm2,%xmm2,%xmm2' 'vsubss %xmm3,%xmm3,%xmm3' -n1 --reference 'ICL-PMU'", 'fp-arith-mix')
    gen_kernel("-i 'xor %eax,%eax' 'xor %ecx,%ecx' cpuid -n1", 'cpuid')
    
    gen_kernel("-i NOP#2 'mov 0x0(%rsp),%r12' 'test %r12,%r12' 'jg Lbl_end' -n 106", 'ld-cmp-jcc-3i')
    gen_kernel("-i NOP#2 'cmpq $0x0,0x0(%rsp)' 'jg Lbl_end' -n 106", 'ld-cmp-jcc-2i-imm')
    gen_kernel("-i NOP#2 'cmpq %r12,0x0(%rsp)' 'jg Lbl_end' -n 106 -p 'movq $0x0,%r12'", 'ld-cmp-jcc-2i-reg')
    gen_kernel("-i 'mov 0x0(%rsp),%r12' 'test %r12,%r12' 'jg Lbl_end' 'inc %rsp' 'dec %rsp' -n 1", 'ld-cmp-jcc-3i-inc')
    gen_kernel("-i 'cmpq $0x0,0x0(%rsp)' 'jg Lbl_end' 'inc %rsp' 'dec %rsp' -n 1", 'ld-cmp-jcc-2i-imm-inc')
    gen_kernel("-i 'cmpq %r12,0x0(%rsp)' 'jg Lbl_end' 'inc %r12' 'dec %r12' -p 'movq $0x0,%r12' -n 1", 'ld-cmp-jcc-2i-reg-inc')
    gen_kernel("-p 'mov %rsp,%rdx' 'sub $0x40000,%rdx' -i 'cmpl $0,0x40000(,%rdx,1)' -n 100", 'cmp0-mem-index')
    gen_kernel("-i 'vshufps $0xff,%ymm0,%ymm1,%ymm2' 'vshufps $0xff,%ymm3,%ymm4,%ymm5' NOP 'mov (%rsp),%rbx' 'test %rax, %rax' 'jle Lbl_end' 'inc %rcx' --init-regs rax", 'vshufps')
    gen_kernel("-i 'vpshufb %ymm0,%ymm1,%ymm2' 'vpshufb %ymm3,%ymm4,%ymm5' NOP 'mov (%rsp),%rbx' 'test %rax, %rax' 'jle Lbl_end' 'inc %rcx' --init-regs rax", 'vpshufb')
    gen_kernel("-i 'mov 0x0(%rsp),%r12' 'add %r13,%r12' NOP -n 14", 'ld-op-nop')
    gen_kernel("-i 'mov %r13,%r12' 'add %r14,%r12' NOP -n 14", 'mov-op-nop')
    gen_kernel("-i 'mov 0x0(%rsp),%r12' NOP 'add %r13,%r12' -n 14", 'ld-nop-op')
    gen_kernel("-i 'mov %r13,%r12' NOP 'add %r14,%r12' -n 14", 'mov-nop-op')
    gen_kernel("-i 'incq (%rsp,%rdx,1)' 'decq (%rsp,%rdx,1)' -n16", 'incdec-mrn-cancel')
    gen_kernel("-i 'incq (%rsp,1)' 'decq (%rsp,1)' -n16", 'incdec-mrn')
    gen_kernel("-i 'movq (%rsp,%rdx,1), %rcx' 'addq $1, (%rsp,%rdx,1)' -n16" , 'ldst-mrn-cancel')
    gen_kernel("-i 'movq (%rsp,1), %rcx' 'addq $1, (%rsp,1)' -n16", 'ldst-mrn')
    gen_kernel("-i 'movups (%rsp),%xmm1' 'andps %xmm2, %xmm1' NOP -n 14", 'v-ld-op-nop')
    gen_kernel("-i 'movdqa %xmm1,%xmm2' 'andps %xmm3, %xmm2' NOP -n 14", 'v-mov-op-nop')
    gen_kernel("-i 'movups (%rsp),%xmm1' NOP 'andps %xmm2, %xmm1' -n 14", 'v-ld-nop-op')
    gen_kernel("-i 'movdqa %xmm1,%xmm2' NOP 'andps %xmm3, %xmm2' -n 14", 'v-mov-nop-op')
    gen_kernel("-i 'aeskeygenassist $0x7e,(%rsp),%xmm0' 'aeskeygenassist $0x7e,%xmm0,%xmm1' 'cmpxchg16b 0x100(%rsp)' 'comisd 0x100(%rsp),%xmm0' 'comisd %xmm0,%xmm1' 'comiss 0x100(%rsp),%xmm0' 'comiss %xmm0,%xmm1' 'cvtsd2si 0x100(%rsp),%r8' 'cvtsd2si %xmm0,%r8d' 'cvtsi2sd %r8d,%xmm0' 'cvtsi2ss %r8d,%xmm0' 'cvtss2si 0x100(%rsp),%r8' 'cvtss2si %xmm0,%r8d' 'cvtss2si %xmm0,%r8' 'cvttsd2si 0x100(%rsp),%r8' 'cvttsd2si 0x100(%rsp),%r8d' 'cvttsd2si %xmm0,%r8' 'cvttsd2si %xmm0,%r8d' 'cvttss2si 0x100(%rsp),%r8' 'cvttss2si 0x100(%rsp),%r8d' 'cvttss2si %xmm0,%r8d' 'cvttss2si %xmm0,%r8' 'emms' 'extractps $0x7e,%xmm0,%r8d' 'f2xm1' 'fbld 0x100(%rsp)' 'fbstp 0x100(%rsp)' 'fcmovbe %st(4),%st' 'fcmovb %st(2),%st' 'fcmove %st(3),%st' 'fcmovnbe %st(0),%st' 'fcmovnb %st(6),%st' 'fcmovne %st(7),%st' 'fcmovnu %st(1),%st' 'fcmovu %st(5),%st' 'fcos' 'fninit' 'fpatan' 'fprem' 'fprem1' 'fptan' 'fscale' 'fsin' 'fsincos' 'fyl2x' 'fyl2xp1' 'kmovb %r8d,%k4' 'kmovb 0x100(%rsp),%k6' 'kmovd %k7,%r8d' 'kmovd %r8d,%k6' 'kmovd 0x100(%rsp),%k1' 'kmovq %k2,%r8' 'kmovq %r12,%k1' 'kmovq 0x100(%rsp),%k3' 'kmovw %r8d,%k6' 'kmovw 0x100(%rsp),%k1' 'lock cmpxchg16b 0x100(%rsp)' 'movd %r8d,%mm7' 'movd %r8d,%xmm0' 'movd %mm6,%r8d' 'movd %xmm0,%r8d' 'movmskpd %xmm0,%r8d' 'movmskps %xmm0,%r8d' 'movq %mm4,%r8' 'movq %r8,%mm5' 'movq %r8,%xmm0' 'movq %xmm0,%r8' 'pcmpestri $0x7e,0x100(%rsp),%xmm0' 'pcmpestri $0x7e,%xmm0,%xmm0' 'pcmpestri $0x7e,%xmm0,%xmm0' 'pcmpestrm $0x7e,0x100(%rsp),%xmm0' 'pcmpestrm $0x7e,%xmm0,%xmm0' 'pcmpistri $0x7e,0x100(%rsp),%xmm0' 'pcmpistri $0x7e,%xmm0,%xmm0' 'pcmpistrm $0x7e,0x100(%rsp),%xmm0' 'pcmpistrm $0x7e,%xmm0,%xmm0' 'pextrb $0x7e,%xmm0,%r8d' 'pextrd $0x7e,%xmm0,%r8d' 'pextrq $0x7e,%xmm0,%r8' 'pextrw $0x7e,%mm7,%r8d' 'pextrw $0x7e,%xmm0,%r8d' 'pinsrb $0x7e,%r8d,%xmm0' 'pinsrd $0x7e,%r8d,%xmm0' 'pinsrq $0x7e,%r8,%xmm0' 'pinsrw $0x7e,%r8d,%mm6' 'pinsrw $0x7e,%r8d,%xmm0' 'pmovmskb %mm0,%r8d' 'pmovmskb %xmm0,%r8d' 'ptest 0x100(%rsp),%xmm0' 'ptest %xmm0,%xmm0' 'ucomisd %xmm0,%xmm1' 'ucomiss %xmm0,%xmm0' 'ucomiss 0x100(%rsp),%xmm0' 'ucomisd 0x100(%rsp),%xmm0' 'vaeskeygenassist $0x7e,0x100(%rsp),%xmm0' 'vaeskeygenassist $0x7e,%xmm0,%xmm1' 'vcomiss 0x100(%rsp),%xmm0' 'vcomiss %xmm0,%xmm1' 'vcvtsd2si 0x100(%rsp),%r8' 'vcvtsd2si 0x100(%rsp),%r8d' 'vcvtsd2si %xmm0,%r8' 'vcvtsd2si %xmm0,%r8d' 'vcvtsd2usi 0x100(%rsp),%r8' 'vcvtsd2usi %xmm0,%r8d' 'vcvtsi2sd %r8,%xmm0,%xmm1' 'vcvtsi2sd %r8d,%xmm0,%xmm1' 'vcvtsi2ss %r8d,%xmm0,%xmm1' 'vcvtsi2ss %r8d,%xmm0,%xmm1' 'vcvtsi2ss %rsi,%xmm0,%xmm1' 'vcvtss2si 0x100(%rsp),%r8' 'vcvtss2si 0x100(%rsp),%r8d' 'vcvtss2si %xmm0,%r8' 'vcvtss2si %xmm0,%r8d' 'vcvtss2usi 0x100(%rsp),%r8' 'vcvtss2usi 0x100(%rsp),%r8d' 'vcvtss2usi %xmm0,%r8' 'vcvtss2usi %xmm0,%r8d' 'vcvttsd2si 0x100(%rsp),%r8' 'vcvttsd2si 0x100(%rsp),%r8d' 'vcvttsd2si %xmm0,%r8' 'vcvttsd2si %xmm0,%r8d' 'vcvttsd2usi 0x100(%rsp),%r8d' 'vcvttsd2usi %xmm0,%r8' 'vcvttss2si 0x100(%rsp),%r8' 'vcvttss2si 0x100(%rsp),%r8d' 'vcvttss2si %xmm0,%r8' 'vcvttss2si %xmm0,%r8d' 'vcvttss2usi 0x100(%rsp),%r8' 'vcvttss2usi %xmm0,%r8' 'vcvtusi2sd %r8d,%xmm0,%xmm1' 'vcvtusi2ss %r8d,%xmm0,%xmm1' 'vcvtusi2ss %r8,%xmm0,%xmm1' 'vextractps $0x7e,%xmm0,%r8d' 'vmovd %r8d,%xmm0' 'vmovd %xmm0,%r8' 'vmovq %xmm0,%r8' 'vmovmskpd %xmm0,%r8d' 'vmovmskpd %ymm0,%r8d' 'vmovmskps %xmm0,%r8' 'vmovmskps %ymm0,%r8' 'vmovq %r8,%xmm0' 'vpcmpestri $0x7e,0x100(%rsp),%xmm0' 'vpcmpestri $0x7e,%xmm0,%xmm1' 'vpcmpestrm $0x7e,0x100(%rsp),%xmm0' 'vpcmpestrm $0x7e,%xmm0,%xmm1' 'vpcmpistri $0x7e,0x100(%rsp),%xmm0' 'vpcmpistri $0x7e,%xmm0,%xmm0' 'vpcmpistrm $0x7e,0x100(%rsp),%xmm0' 'vpcmpistrm $0x7e,%xmm0,%xmm0' 'vpextrb $0x7e,%xmm0,%r8d' 'vpextrd $0x7e,%xmm0,%r8d' 'vpextrq $0x7e,%xmm0,%r8' 'vpextrw $0x7e,%xmm0,%r8d' 'vpinsrb $0x7e,%r8d,%xmm0,%xmm1' 'vpinsrd $0x7e,%r8d,%xmm0,%xmm1' 'vpinsrq $0x7e,%r8,%xmm0,%xmm1' 'vpinsrw $0x7e,%r8d,%xmm0,%xmm1' 'vpmovmskb %xmm0,%r8d' 'vpmovmskb %ymm0,%r8d' 'vptest 0x100(%rsp),%xmm0' 'vptest 0x100(%rsp),%ymm0' 'vptest %xmm0,%xmm0' 'vptest %ymm0,%ymm0' 'vtestpd 0x100(%rsp),%xmm0' 'vtestpd 0x100(%rsp),%ymm0' 'vtestpd %xmm0,%xmm0' 'vtestpd %ymm0,%ymm0' 'vtestps 0x100(%rsp),%xmm0' 'vtestps 0x100(%rsp),%ymm0' 'vtestps %xmm0,%xmm0' 'vtestps %ymm0,%ymm0' 'vucomisd 0x100(%rsp),%xmm0' 'vucomisd %xmm0,%xmm0' 'vucomiss %xmm0,%xmm1' -n1 ",'v2ii2v')
    kernels.append("memcpy")
    kernels.append("pagefault")
    kernels.append("tripcount-mean")
    kernels.append("store_fwd_block")

#kernels.append('cond_jmp')
print(kernels)

for kernel in kernels:
    build_kernel(kernel)

#Special Builds
build_kernel('callchain', flags='-O0 -fno-inline')
build_kernel('false-sharing', flags='-O0 -pthread')
build_kernel('cond_jmp', flags='-O0')
if goldencove_on():
    build_kernel('tpause', flags='-march=native')# requires newer GCC and binutils
build_kernel('tpause', output='rdtsc', flags='-march=native -DRDTSC_ONLY')

