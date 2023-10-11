#!/usr/bin/env python3
#Author: Ahmad Yasin, Sinduri Gundu
#Date: July 2023

import os
import sys
import argparse
import subprocess
import re
import textwrap

cwd = os.getcwd()
sys.path.append(cwd[:cwd.rfind('kernels')]) #Add directory containing pmu.py to the path
from pmu import goldencove, server, cpu_pipeline_width

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
print(pipelineWidth)

#generate source code with gen-kernel script.
#print command to screen
def run_gen_kernel(params, filename):
    gen_kernel_command = '{python} ./gen-kernel.py {params}'.format(python=args.PY, params=params)
    print(gen_kernel_command)
    with open(filename + '.c', "w") as f:
        run = subprocess.run(gen_kernel_command, shell=True, stdout=f)
    kernels.append(filename)

def build_kernel(source, output=None, flags=''):
    if output is None:
        output = source
    build_command = '{CC} {flags} {source}.c -o {output}'.format(CC=args.CC, flags=flags, source=source, output=output)
    print(build_command)
    try:
        subprocess.run(build_command, shell=True)
    except:
        print(kernel + " build failed")


if args.GEN:
    run_gen_kernel("jumpy-seq -n 13 -i JMP -a 15", 'jumpy13b15')
    run_gen_kernel("jumpy-seq -n 13 -i JMP -a 13", 'jumpy13b13')
    run_gen_kernel("jumpy-seq -n 9 -i JMP -a 17", 'itlb-miss-stlb-hit')

    subprocess.run('{CC} -S jumpy5p14.c'.format(CC=args.CC), shell=True)
    kernels.append("jumpy5p14")

    run_gen_kernel("-i 'addps %xmm1,%xmm2' 'vsubps %ymm1,%ymm2,%ymm3' -n10", 'sse2avx')

    run_gen_kernel("-i NOP#{nopCount} 'test %rax,%rax' 'jle Lbl_end' -n 1 -a 6".format(nopCount=(pipelineWidth-3)), 'peak'+str(pipelineWidth)+'wide')
    run_gen_kernel("jumpy-seq -i NOP JMP -a3 -n30", 'dsb-jmp')
    run_gen_kernel("jumpy-seq -i JG -a 6 -n 20000", 'jcc20k')
    run_gen_kernel("jumpy-random -a 6 -i JMP -n 1024", 'rfetch64k')

    if args.RF:
        run_gen_kernel("jumpy-random -a 5 -i NOP5#30 JMP -n 19661", 'rfetch3m')
        run_gen_kernel("jumpy-random -a 5 -i NOP5#56 JMP -n 10923", 'rfetch3m-ic')

    for x in ['add', 'mul']:
        run_gen_kernel("-i 'v{x}pd %ymm@,%ymm@,%ymm@' -r16 -n1 --reference MGM".format(x=x), 'fp-{x}-bw'.format(x=x))
        run_gen_kernel("-i 'v{x}pd %ymm@-1,%ymm@,%ymm@' -r16 -n10 --reference MGM".format(x=x), 'fp-{x}-lat'.format(x=x))
        if server():
            run_gen_kernel("-i 'v{x}pd %zmm0,%zmm1,%zmm2' 'v{x}pd %zmm3,%zmm4,%zmm5' NOP 'mov (%rsp),%rbx' -n1".format(x=x), 'fp-{x}-512'.format(x=x))

    run_gen_kernel("-i 'vdivps %ymm@,%ymm@,%ymm@' -r3 -n1", 'fp-divps')
    run_gen_kernel("-i 'vfmadd132pd %ymm10,%ymm11,%ymm11' 'vfmadd132ps %ymm12,%ymm13,%ymm13' 'vaddpd %xmm0,%xmm0,%xmm0' 'vaddps %xmm1,%xmm1,%xmm1' 'vsubsd %xmm2,%xmm2,%xmm2' 'vsubss %xmm3,%xmm3,%xmm3' -n1 --reference 'ICL-PMU'", 'fp-arith-mix')
    run_gen_kernel("-i 'xor %eax,%eax' 'xor %ecx,%ecx' cpuid -n1", 'cpuid')
    
    run_gen_kernel("-i NOP#2 'mov 0x0(%rsp),%r12' 'test %r12,%r12' 'jg Lbl_end' -n 106", 'ld-cmp-jcc-3i')
    run_gen_kernel("-i NOP#2 'cmpq $0x0,0x0(%rsp)' 'jg Lbl_end' -n 106", 'ld-cmp-jcc-2i-imm')
    run_gen_kernel("-i NOP#2 'cmpq %r12,0x0(%rsp)' 'jg Lbl_end' -n 106 -p 'movq $0x0,%r12'", 'ld-cmp-jcc-2i-reg')
    run_gen_kernel("-i 'mov 0x0(%rsp),%r12' 'test %r12,%r12' 'jg Lbl_end' 'inc %rsp' 'dec %rsp' -n 1", 'ld-cmp-jcc-3i-inc')
    run_gen_kernel("-i 'cmpq $0x0,0x0(%rsp)' 'jg Lbl_end' 'inc %rsp' 'dec %rsp' -n 1", 'ld-cmp-jcc-2i-imm-inc')
    run_gen_kernel("-i 'cmpq %r12,0x0(%rsp)' 'jg Lbl_end' 'inc %r12' 'dec %r12' -p 'movq $0x0,%r12' -n 1", 'ld-cmp-jcc-2i-reg-inc')
    run_gen_kernel("-p 'mov %rsp,%rdx' 'sub $0x40000,%rdx' -i 'cmpl $0,0x40000(,%rdx,1)' -n 100", 'cmp0-mem-index')


    #run_gen_kernel("-i 'movl 0x0(%rsp),%ecx' 'test %ecx,%ecx' 'jg Lbl_end' -n 1", 'ld-test-jcc-3i')
    #run_gen_kernel("-i 'testq $0x0,0x0(%rsp)' 'jg Lbl_end' -n 1", 'ld-test-jcc-2i-imm')
    #run_gen_kernel("-i 'testq %r12,0x0(%rsp)' 'jg Lbl_end' -n 1 -p 'movq $0x0,%r12'", 'ld-test-jcc-2i-reg')
    run_gen_kernel("-i 'vshufps $0xff,%ymm0,%ymm1,%ymm2' 'vshufps $0xff,%ymm3,%ymm4,%ymm5' NOP 'mov (%rsp),%rbx' 'test %rax, %rax' 'jle Lbl_end' 'inc %rcx'", 'vshufps')
    run_gen_kernel("-i 'vpshufb %ymm0,%ymm1,%ymm2' 'vpshufb %ymm3,%ymm4,%ymm5' NOP 'mov (%rsp),%rbx' 'test %rax, %rax' 'jle Lbl_end' 'inc %rcx'", 'vpshufb')
    
    kernels.append("memcpy")
    kernels.append("pagefault")

#kernels.append('cond_jmp')
print(kernels)

for kernel in kernels:
    build_kernel(kernel)

#Special Builds
build_kernel('callchain', flags='-O0 -fno-inline')
build_kernel('false-sharing', flags='-O0 -pthread')
if goldencove():
    build_kernel('tpause', flags='-march=native')# requires newer GCC and binutils
build_kernel('tpause', output='rdtsc', flags='-march=native -DRDTSC_ONLY')

