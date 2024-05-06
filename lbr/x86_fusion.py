#!/usr/bin/env python
# Copyright (c) 2024, Intel Corporation
# Author: Amiri Khalil
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# Assembly support specific to x86 Intel macro-fusion cases
__author__ = 'akhalil'
__version__ = 0.01

from lbr.x86 import *
import re
import common as C

# CMP, TEST, AND, ADD and SUB may be macro-fused if they compare reg-reg, reg-imm, reg-mem, mem-reg,
# means no mem-imm fusion
# TEST and AND fuse with all JCCs
# CMP, ADD and SUB fuse with [JC, JB, JAE/JNB], [JE, JZ, JNE, JNZ], [JNA/JBE, JA/JNBE] and
# [JL/JNGE, JGE/JNL, JLE/JNG, JG/JNLE]
# INC and DEC fuse with [JE, JZ, JNE, JNZ] and [JL/JNGE, JGE/JNL, JLE/JNG, JG/JNLE] on reg and not memory
M_FUSION_INSTS = ['cmp', 'test', 'add', 'sub', 'inc', 'dec', 'and']
def is_jcc_fusion(line1, line2):
  match = re.search(COND_BR, line2)
  if not match: return False
  inst = get('inst', line1)
  if not C.any_in(M_FUSION_INSTS, inst): return False
  if C.any_in(['inc', 'dec'], inst) and is_memory(line1): return False
  if is_memory(line1) and is_imm(line1): return False
  if C.any_in(['test', 'add'], inst): return True
  JCC_GROUP1 = ['je', 'jz', 'jne', 'jnz', 'jl', 'jnge', 'jge', 'jnl', 'jle', 'jng', 'jg', 'jnle']
  JCC_GROUP2 = ['jc', 'jb', 'jae', 'jnb', 'jna', 'jbe', 'ja', 'jnbe']
  jcc = match.group(0)
  if jcc in JCC_GROUP1: return True
  if jcc in JCC_GROUP2 and C.any_in(['cmp', 'add', 'sub'], inst): return True
  return False

# checks for int fusion if int arg True and for int/vec if int arg is False
def is_fusion_mov(inst, int=True):
  suff = ('ddup',)
  if int: suff = suff + ('pd', 'ps')
  l = ['dir', 'nt']
  if int: l.append('dq')
  return inst.startswith('mov') and not re.search(MOVS_ZX, inst) and not \
    inst.endswith(suff) and not C.any_in(l, inst)

def is_mov_op_fusion(line1, line2):
  if 'lock' in line1 or 'lock' in line2: return False
  # MOV reg-reg
  if not is_fusion_mov(get('inst', line1)): return False
  if is_memory(line1) or is_imm(line1): return False
  inst = get('inst', line2)
  if not C.any_in(['add', 'sub', 'and', 'or', 'xor', 'imul', 'inc', 'dec', 'not',
                   'neg', 'btc', 'btr', 'bts', 'shl', 'sal', 'sar', 'shr', 'rol', 'ror', 'shrd'], inst):
    return False
  # 32 or 64 bit dest
  dest_reg = get('dst', line1)
  if dest_reg not in REGS_32 and dest_reg not in REGS_64: return False
  if is_memory(line2): return False  # no mem in OP
  if not dest_reg == get('dst', line2): return False  # same dest
  if len(get('srcs', line2)) > 1: return False  # no three operand OPs
  # no reg-reg shift or rotate
  if not is_imm(line2) and C.any_in(['shl', 'sal', 'sar', 'shr', 'rol', 'ror', 'shrd'], inst): return False
  # no 64-bit fusion in imul
  if 'imul' in inst and dest_reg in REGS_64: return False
  return True

def is_ld_op_fusion(line1, line2):
  if 'lock' in line1 or 'lock' in line2: return False
  if not is_fusion_mov(get('inst', line1)) or not re.search(LOAD, line1): return False
  if not C.any_in(['add', 'sub', 'and', 'or', 'xor', 'imul'], get('inst', line2)): return False
  if '(%rip' in line1: return False  # not RIP relative
  if re.search(MEM_IDX, line1): return False  # no index register
  # 32 or 64 bit dest
  dest_reg = get('dst', line1)
  if dest_reg not in REGS_32 and dest_reg not in REGS_64: return False
  if is_memory(line2) or is_imm(line2): return False  # reg-reg OP
  srcs = get('srcs', line2)
  if len(srcs) > 1: return False  # no three operand OPs
  assert len(srcs) == 1
  op_src, op_dest = srcs[0], get('dst', line2)
  if not dest_reg == op_dest: return False  # same dest
  if op_src == op_dest: return False  # different OP regs
  # no 64-bit fusion in imul
  if 'imul' in line2 and op_dest in REGS_64: return False
  return True

SUFF1, SUFF2 = ['b', 'w', 'd', 'q'], ['ps', 'pd']
#MOVDQA/MOVDQU/MOVAPS/MOVAPD/MOVUPS/MOVUPD
HEADS_MOV = ['mov' + x for x in (['dqa', 'dqu'] + [y + x for x in SUFF2 for y in ['a', 'u']])]
#MOVUPS/MOVUPD/MOVDQU
HEADS_LD = ['mov' + x for x in (['dqu'] + ['u' + x for x in SUFF2])]
OPS_BASIC = ['and', 'or', 'xor']
#OPs that apply for all heads
#[AND/OR/XOR]PS
OPS_ALL = [x + 'ps' for x in OPS_BASIC]
#OPs that apply for all MOV heads and LD head 0
#[AND/OR/XOR]PD, PSADBW, PMULLW, PMADDWD, PADD[USB/SB/B/W/USW/SW/D/Q], PCMPEQ[B/W/D], P[AND/XOR/OR/MINUB/MAXUB/MINSW/MAXSW/AVGB/AVGW]
OPS_MOV = [x + 'pd' for x in OPS_BASIC] + \
          ['p' + x for x in (OPS_BASIC + ['sadbw', 'mullw', 'maddwd'] + [y + z for z in ['ub', 'sw'] for y in ['min', 'max']] +
                             ['add' + y for y in (SUFF1 + ['usb', 'sb', 'usw', 'sw'])] +
                             ['cmpeq' + y for y in ['b', 'w', 'd']] + ['avg' + y for y in ['b', 'w']])]
OPS_LD1 = OPS_MOV
#OPs that apply for all MOV heads
#PMUL[LW/HUW/UDQ], [ADD/SUB/MIN/MAX/MUL][PS/PD/SS/SD], [DIV/ANDN][PS/PD], ADDSUB[PS/PD], PUNPCK[LBW/LWD/LDQ/HBW/HWD/HDQ/LQDQ/HQDQ],
#PACK[USWB/SSWB/SSDW], UNPCK[L/H][PS/PD], PSUB[USB/SB/B/W/USW/SW/D/Q], PCMPGT[B/W/D], PANDN, CMPLEPS, [CMP/SHUF]PS
OPS_MOV += ['p' + x for x in (['mul' + y for y in ['lw', 'huw', 'udq']] +
                              ['unpck' + y for y in ['lbw', 'lwd', 'ldq', 'hbw', 'hwd', 'hdq', 'lqdq', 'hqdq']] +
                              ['sub' + y for y in (['usb', 'sb', 'usw', 'sw'] + SUFF1)] + ['cmpgt' + y for y in ['b', 'w', 'd']] +
                              ['andn'])] + \
           [x + y for y in (SUFF2 + ['ss', 'sd']) for x in ['add', 'sub', 'min', 'max', 'mul']] + \
           [x + y for y in SUFF2 for x in ['div', 'andn', 'addsub']] + ['pack' + x for x in ['uswb', 'sswb', 'ssdw']] + \
           ['unpck' + x for x in [y + z for z in SUFF2 for y in ['l', 'h']]] + [x + 'ps' for x in ['cmple', 'cmp', 'shuf']]
#OPs that apply for MOV heads 0, 1, 3 and 5
#BLEND[PS/PD]/PBLENDW
OPS_MOV2 = ['pblendw'] + ['blend' + x for x in SUFF2]
#OPs that apply for MOV heads 2 and 4 and LD heads 1 and 2
#PMULHRSW, PCMPEQQ, P[MIN/MAX][SB/SD/UW/UD], ANDN
OPS_MOV3 = ['andn'] + ['p' + x for x in (['mulhrsw', 'cmpeqq'] + [y + z for z in ['sb', 'sd', 'uw', 'ud'] for y in ['min', 'max']])]
OPS_LD2 = OPS_MOV3
#OPs that apply for MOV heads 2 and 4
#PMADDUBSW, PMULDQ, PACKUSDW, PCMPGTQ, CMPLE[PD/SS/SD], CMP[SS/SD]/SHUFPD
OPS_MOV3 += ['p' + x for x in (['maddubsw', 'muldq', 'cmpgtq'])] + ['packusdw', 'shufpd'] + \
            ['cmple' + x for x in ['pd', 'ss', 'sd']] + ['cmp' + x for x in ['ss', 'sd']]
#OPs that apply for MOV heads 2 and 4 only with immediate
#PS[RLW/RLD/RLQ/LLW/LLD/LLQ/RAW/RAD]
OPS_MOV3_IMM = ['ps' + x for x in ['rlw', 'rld', 'rlq', 'llw', 'lld', 'llq', 'raw', 'rad']]

def is_vec_mov_op_fusion(line1, line2):
  def check(l, d): return is_memory(l) or not d or not 'xmm' in d
  if 'lock' in line1 or 'lock' in line2: return False
  inst1 = get('inst', line1)
  if not inst1 in HEADS_MOV: return False
  dst1, dst2 = get('dst', line1), get('dst', line2)
  # no memory
  if check(line1, dst1) or check(line2, dst2): return False
  if dst1 != dst2: return False  # same dest reg
  inst2 = get('inst', line2)
  if inst2 in OPS_ALL or inst2 in OPS_MOV: return True
  head_i = HEADS_MOV.index(inst1)
  if head_i == 2 or head_i == 4:
    if inst2 in OPS_MOV3: return True
    if inst2 in OPS_MOV3_IMM and is_imm(line2): return True
    return False
  # head_i is one of 0, 1, 3, 5
  return inst2 in OPS_MOV2

def is_vec_ld_op_fusion(line1, line2):
  def check(d): return not d or not 'xmm' in d
  if 'lock' in line1 or 'lock' in line2: return False
  inst1 = get('inst', line1)
  if inst1.endswith('x'): inst1 = inst1[:-1]  # removing potential extension suffix
  if not inst1 in HEADS_LD: return False
  if is_memory(line2): return False
  if '(%rip' in line1: return False  # not RIP relative
  if re.search(MEM_IDX, line1): return False  # no index register
  dst1, dst2 = get('dst', line1), get('dst', line2)
  if check(dst1) or check(dst2): return False
  if dst1 != dst2: return False  # same dest reg
  src = get('srcs', line2)
  if len(src) > 1: return False  # no three operand OPs
  assert len(src) == 1
  if src[0] == dst2: return False  # different OP regs
  inst2 = get('inst', line2)
  if inst2 in OPS_ALL: return True
  if HEADS_LD.index(inst1) == 0: return inst2 in OPS_LD1
  return inst2 in OPS_LD2
