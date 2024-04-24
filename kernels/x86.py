#!/usr/bin/env python
# Copyright (c) 2020-2024, Intel Corporation
# Author: Ahmad Yasin
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# Assembly support specific to x86
__author__ = 'ayasin'
__version__ = 0.53
# TODO:
# - inform compiler on registers used by insts like MOVLG

import re
import common as C

INST_UNIQ='PAUSE'
INST_1B='NOP'
MOVLG='MOVLG'
FP_SUFFIX = "[sdh]([a-z])?"

# instruction mnemonics
BIT_TEST  = 'bt[^crs]'
CALL_RET  = '(call|ret)'
CISC_CMP  = r'(cmp[^x]|test).*\(' # CMP or TEST with memory (CISC)
CMOV      = r"cmov"
COMI      = r"v?u?comi",
COND_BR   = 'j[^m][^ ]*'
EXTRACT   = 'xtr' # covers legacy, AVX* and x87 flavors
IMUL      = r"imul.*"
INDIRECT  = r"(jmp|call).*%"
JMP_RET   = r"(jmp|ret)"
JUMP      = '(j|%s|sys%s|(bnd|notrack) jmp)' % (CALL_RET, CALL_RET)
LEA_S     = r"lea.?\s+.*\(.*,.*,\s*[0-9]\)"
LOAD      = r"v?mov[a-z0-9]*\s+[^,]*\("
LOAD_ANY  = r"[a-z0-9]+\s+[^,]*\("  # use is_mem_load()
MOV       = r"v?mov"
MOV_X     = r"%s(s|z)x" % MOV
STORE     = r"\s+\S+\s+[^\(\),]+,"  # use is_mem_store()
TEST_CMP  = r"(test|cmp).?\s"

MEM_IDX = r"\((%[a-z0-9]+)?,%[a-z0-9]+,?(1|2|4|8)?\)"

def inst_patch(i='JMP'):
  assert i == 'JMP'
  r = ';'.join(['s/%s jmp/%s-jmp/' % (x, x) for x in ('bnd', 'notrack')])
  return "sed '%s'" % r

def is_imm(line): return '$' in line
def is_memory(line): return '(' in line and 'lea' not in line and 'nop' not in line
def is_mem_imm(line): return is_memory(line) and is_imm(line)
def is_mem_load(line): return is_memory(line) and (is_type(LOAD_ANY, line) or C.any_in(('broadcast', 'insert', 'gather'), line)) 
def is_type(t, l): return re.match(r"\s+\S+\s+%s" % t, l) is not None 
def is_mem_store(line): return is_memory(line) and is_type(STORE, line) and C.any_in(('mov', EXTRACT, 'scatter'), line)
def is_mem_rmw(line): return is_memory(line) and is_type(STORE, line) and not C.any_in(('mov', EXTRACT, 'scatter'), line)
def is_test_load(line): return is_type(CISC_CMP, line) or is_type(BIT_TEST, line)

def get_mem_inst(line):
  assert '(' in line, line
  if 'lock' in line:        return 'lock'
  elif 'prefetch' in line:  return 'prefetch'
  elif is_test_load(line):  return 'load'
  elif is_mem_store(line):  return 'store'
  else: return 'load' if is_mem_load(line) else 'rmw'

MEM_INSTS_BASIC = ['load', 'store', 'rmw']
MEM_INSTS = MEM_INSTS_BASIC + ['lock', 'prefetch']
def mem_type(line=None):
  if not line: return ['%s-%s' % (t, a) for t in ('stack', 'global', 'heap') for a in MEM_INSTS_BASIC]
  a = get_mem_inst(line)
  assert a in MEM_INSTS, 'inst=%s for line:\n%s' % (a, line)
  if a not in MEM_INSTS_BASIC: return None
  if re.search('%[re]sp', line): return 'stack-' + a
  if re.search('%[re]ip', line): return 'global-' + a
  return 'heap-' + a

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

# get inst name, srcs or dst
# what = 'inst'/'srcs'/'dst'
def get(what, line):
  def patch_line(l):
    if 'ilen:' in l: l = l.split('ilen:')[0]
    if '#' in l: l = l.split('#')[0]
    return l
  patch = lambda x: x if is_memory(x) or is_imm(x) else x.replace('%', '')
  res = C.str2list(patch_line(line))
  if len(res) < 3: return res[-1] if what == 'inst' else None
  if what == 'dst': return patch(res[-1])
  if what == 'srcs':
    if len(res) == 3:
      return None if res[-1].startswith('0x') else [patch(res[-1])]
    return [patch(x)[:-1] for x in res if x.endswith(',')]
  check = res[2]
  if is_memory(check) or is_imm(check) or check.startswith('%') or check.startswith('0x'): return res[1]
  return ' '.join(res[1:3])

# 64-bit, 32-bit & 16-bit sub regs for 32/64 bit regs
def sub_regs(reg):
  subs = [reg, reg, None]
  if reg in REGS_64:
    subs[1] = reg + 'd' if '1' in reg else reg.replace('r', 'e')
    subs[2] = reg + 'w' if '1' in reg else reg.replace('r', '')
  else:
    subs[0] = reg.replace('d', '') if '1' in reg else reg.replace('e', 'r')
    subs[2] = reg.replace('d', 'w') if '1' in reg else reg.replace('e', '')
  return subs
def is_sub_reg(sub_reg, orig): return sub_reg in sub_regs(orig)

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

REGS_32 = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp'] + \
          ['r' + str(n) + 'd' for n in range(8, 16)]
REGS_64 = [x.replace('e', 'r') for x in REGS_32 if x.startswith('e')] + \
          [x.replace('d', '') for x in REGS_32 if x.startswith('r')]

def is_mov_op_fusion(line1, line2):
  if 'lock' in line1 or 'lock' in line2: return False
  # MOV reg-reg
  inst = get('inst', line1)
  if re.search(CMOV, inst) or re.search(MOV_X, inst) or 'vmov' in inst or 'mov' not in inst: return False
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
  inst = get('inst', line1)
  if not re.search(LOAD, line1) or re.search(CMOV, inst) or 'vmov' in inst: return False
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
#VMOVDQA/VMOVDQU/VMOVAPS/VMOVAPD/VMOVUPS/VMOVUPD
HEADS_MOV = ['mov' + x for x in (['dqa', 'dqu'] + [y + x for x in SUFF2 for y in ['a', 'u']])]
#VMOVUPS/VMOVUPD/VMOVDQU
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
