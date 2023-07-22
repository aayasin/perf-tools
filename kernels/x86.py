#!/usr/bin/env python
# Copyright (c) 2020-2023, Intel Corporation
# Author: Ahmad Yasin
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# Assembly support specific to x86
__author__ = 'ayasin'
__version__ = 0.23
# TODO:
# - inform compiler on registers used by insts like MOVLG

import re
import common as C

INST_UNIQ='PAUSE'
INST_1B='NOP'
MOVLG='MOVLG'
FP_SUFFIX = "[sdh]([a-z])?"
IMUL      = r"imul.*"
INDIRECT  = r"(jmp|call).*%"
CALL_RET  = '(call|ret)'
COND_BR   = 'j[^m][^ ]*'
TEST_CMP  = r"(test|cmp).?\s"
LOAD      = r"mov.?\s.*\).*,"
BR = '(j|%s|sys%s)' % (CALL_RET, CALL_RET)
M_FUSION_INSTS = ['cmp', 'test', 'add', 'sub', 'inc', 'dec', 'and']

def bytes(x): return '.byte 0x' + ', 0x'.join(x.split(' '))

def long_nop(n):
  assert n > 9 and n < 16
  return bytes('66 '*(n-9) + '2E 0F 1F 84 00 00 00 00 00')

aliases = {MOVLG: 'movabs $0x8877665544332211, %r15',
  'LCP':  'test $0x1122,%cx',
  'RMW':  'addl $1, 0(%rsp)',
  'NOP1': 'nop',
  'NOP2': bytes('66 90'),
  'NOP3': bytes('0F 1F 00'),
  'NOP4': bytes('0F 1F 40 00'), #'nopl   0x0(%rax)',
  'NOP5': bytes('0F 1F 44 00 00'),
  'NOP6': bytes('66 0F 1F 44 00 00'),
  'NOP7': bytes('0F 1F 80 00 00 00 00'),
  'NOP8': bytes('0F 1F 84 00 00 00 00 00'),
  'NOP9': bytes('66 0F 1F 84 00 00 00 00 00'),
#  'NOP10':  'nopw   %cs:0x0(%rax,%rax,1)',
#  'NOP14':  'data16 data16 data16 data16 nopw %cs:0x0(%rax,%rax,1)',
}
for x in range(6): aliases['NOP%d'%(x+10)] = long_nop(x+10)

def x86_pad(n, long_inst=MOVLG):
  size = {MOVLG: 10, 'NOP15': 15}[long_inst]
  xx = ''
  while n > size:
    xx += (aliases[long_inst] + '; ')
    n -= size
  xx += aliases['NOP%d'%n]
  return xx

def x86_inst(x):
  if x.startswith('PAD'):
    assert (':' in x),  "Expect :N in '%s'!"%x
    return x86_pad(int(x.split(':')[1]), 'NOP15')
  if ';' in x: return x # no support for chain of instructions
  for a in aliases.keys():
    if x == a: return aliases[a]
  return x

def x86_asm(x, tabs=1, spaces=8):
  return ' '*spaces + 'asm("' + '\t'*tabs + x86_inst(x) + '");'

# CMP, TEST, AND, ADD and SUB may be macro-fused if they compare reg-reg, reg-imm, reg-mem, mem-reg,
# means no mem-imm fusion
# TEST and AND fuse with all JCCs
# CMP, ADD and SUB fuse with [JC, JB, JAE/JNB], [JE, JZ, JNE, JNZ], [JNA/JBE, JA/JNBE] and
# [JL/JNGE, JGE/JNL, JLE/JNG, JG/JNLE]
# INC and DEC fuse with [JE, JZ, JNE, JNZ] and [JL/JNGE, JGE/JNL, JLE/JNG, JG/JNLE] on reg and not memory
def is_fusion(line1, line2):
  match = re.search(COND_BR, line2)
  if not match: return False
  if not C.any_in(M_FUSION_INSTS, line1): return False
  if C.any_in(['inc', 'dec'], line1) and is_memory(line1): return False
  if is_memory(line1) and '$' in line1: return False
  if C.any_in(['test', 'add'], line1): return True
  JCC_GROUP1 = ['je', 'jz', 'jne', 'jnz', 'jl', 'jnge', 'jge', 'jnl', 'jle', 'jng', 'jg', 'jnle']
  JCC_GROUP2 = ['jc', 'jb', 'jae', 'jnb', 'jna', 'jbe', 'ja', 'jnbe']
  jcc = match.group(0)
  if jcc in JCC_GROUP1: return True
  if jcc in JCC_GROUP2 and C.any_in(['cmp', 'add', 'sub'], line1): return True
  return False

def is_memory(line): return '(' in line and 'lea' not in line

def is_mem_imm(line): return is_memory(line) and '$' in line
