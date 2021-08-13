#!/usr/bin/env python
# generate C-language kernels with ability to incorporate x86 Assembly with certain control-flow constructs
# Author: Ahmad Yasin
# edited: Aug. 2021
from __future__ import print_function
__author__ = 'ayasin'
__version__ = 0.7
# TODO:
# - functions/calls support
# - move Paper to a seperate module

import argparse, sys

import jumpy as J

import os
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/..')
import common as C

from x86 import *

Papers = {
  'MGM':  'A Metric-Guided Method for Discovering Impactful Features and Architectural Insights for Skylake-Based Processors. Ahmad Yasin, Jawad Haj-Yahya, Yosi Ben-Asher, Avi Mendelson. TACO 2019 and HiPEAC 2020.',
}
paper=str(0)

ap = argparse.ArgumentParser()
ap.add_argument('-n', '--unroll-factor', type=int, default=3, help='# times to repeat instruction(s), aka unroll-factor')
ap.add_argument('-r', '--registers', type=int, default=0, help="# of registers to traverse via '@' if > 0")
ap.add_argument('--registers-max', type=int, default=16, help="max # of registers in the instruction-set")
ap.add_argument('-i', '--instructions', nargs='+', default=[INST_UNIQ], help='Instructions for the primary loop (Loop). NOP#3 denotes NOP three times e.g.')
ap.add_argument('-l', '--loops', type=int, default=1, help='# of nested loops')
ap.add_argument('-p', '--prolog-instructions', nargs='+', default=[], help='Instructions prior to the Loop')
ap.add_argument('-e', '--epilog-instructions', nargs='+', default=[], help='Instructions post the Loop')
ap.add_argument('-a', '--align' , type=int, default=0, help='align Loop and target of jumps [in power of 2]')
ap.add_argument('-o', '--offset', type=int, default=0, help='offset unrolled Loop bodies [in bytes]')
ap.add_argument('--label-prefix', default='Lbl', help="Starting '@' implies local labels. empty '' implies number-only labels")
ap.add_argument('mode', nargs='?', choices=['basicblock']+J.get_modes(), default='basicblock')
args = ap.parse_args()

def jumpy(): return args.mode in J.jumpy_modes

def error(x):
  C.printf(x)
  sys.exit(' !\n')

if args.label_prefix == '':
  if args.mode == 'jumpy-random': args.mode += '#'
  else: error('empty label-prefix is supported with jumpy-random mode only')

if args.registers > 0:
  if not '@' in ' '.join(args.instructions): error("expect '@' in --instructions")
  if args.registers > args.registers_max:    error("invalid value for --registers! must be < %d"%args.registers_max)
  paper='"Reference: %s"'%Papers['MGM']

if args.loops > 1 and jumpy(): error("nested loops aren't supported with mode=%s"%args.mode)

def itemize(insts):
  if not '#' in ' '.join(insts): return insts
  out=[]
  for i in insts:
    if '#' in i:
      l = i.split('#')
      if len(l)!=2 or not l[1].isdigit(): error('Invalid syntax: %s'%i)
      n=int(l[1])
      out += [l[0] for x in range(n)]
    else: out.append(i)
  #C.annotate(out, 'aft')
  return out

def asm(x, tabs=1, spaces=8+4*(args.loops-1)): print(x86_asm(x, tabs, spaces))

def label(n, declaration=True, local=False):
 lbl = '%s%05d'%(args.label_prefix, n) if isinstance(n, int) else n
 if args.label_prefix.startswith('@'):
   local = True
   lbl = '%s%05d'%(args.label_prefix[1:], n)
 if declaration:
   if local: return '.local %s\\n"\n\t    "%s:'%(lbl, lbl)
   else:     return lbl+':'
 else:
   return ' '+lbl

for x in vars(args).keys():
  if 'instructions' in x:
    setattr(args, x, itemize(getattr(args, x)))

#kernel's Header
print("""// Auto-generated by %s's %s version %s invoked with:
// %s
// Do not modify!
//
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define MSG %s

int main(int argc, const char* argv[])
{
    uint64_t n;
    if (argc<2) {
        printf("%%s: missing <num-iterations> arg!\\n", argv[0]);
        exit(-1);
    }
    if (MSG) printf("%%s\\n", MSG ? MSG : "");
    n= atol(argv[1]);"""%(__author__, sys.argv[0].replace('./',''), str(__version__),
  str(args).replace('Namespace', ''), paper))
for inst in [INST_UNIQ] + args.prolog_instructions: asm(inst, spaces=4)

#kernel's Body
for l in range(args.loops):
  if args.align: asm('.align %d'%(2 ** args.align), tabs=0, spaces=8+4*l)
  print(' '*4*(l+1) + "for (uint64_t %s=0; %s<n; %s++) {"%(('i%d'%l,)*3))
for j in range(args.unroll_factor):
  if args.offset:
     for k in range(j+args.offset-1): asm(INST_1B)
  if jumpy(): asm(label(j), tabs=0)
  for r in range(max(args.registers, 1)):
    for inst in args.instructions:
      if inst in ['JMP', 'JL', 'JG']: inst += label(J.next(args.mode, args.unroll_factor), False)
      if args.registers and '@' in inst:
        for i in range(9):
          inst = inst.replace('@+%d'%(i+1), str((r+i+1) % args.registers_max))
          inst = inst.replace('@-%d'%(i+1), str((r-i-1) % args.registers_max))
        inst = inst.replace('@', str(r))
      asm(inst)
  if jumpy() and args.align: asm('.align %d'%(2 ** args.align), tabs=0)
if jumpy(): asm(label(args.unroll_factor), tabs=0)
for l in range(args.loops, 0, -1):
  print(' '*4*l + "}")

#kernel's Footer
for inst in args.epilog_instructions: asm(inst, spaces=4)
print("""    asm(".align 512; %s_end:");

    return 0;
}"""%args.label_prefix.replace('@', ''))

