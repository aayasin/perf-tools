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
__version__ = 0.56
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
COMI      = r"v?u?comi"
COND_BR   = 'j[^m][^ ]*'
EXTRACT   = 'xtr' # covers legacy, AVX* and x87 flavors
IMUL      = r"imul.*"
INDIRECT  = r"(jmp|call).*%"
JUMP      = '(j|%s|sys%s|(bnd|notrack) jmp)' % (CALL_RET, CALL_RET)
LEA_S     = r"lea.?\s+.*\(.*,.*,\s*[0-9]\)"
LOAD      = r"v?mov[a-z0-9]*\s+[^,]*\("
LOAD_ANY  = r"[a-z0-9]+\s+[^,]*\("  # use is_mem_load()
MOV       = r"v?mov"
MOVS_ZX   = r"%s(s|zx)" % MOV
STORE     = r"\s+\S+\s+[^\(\),]+,"  # use is_mem_store()
TEST_CMP  = r"(test|cmp).?\s" 

MEM_IDX   = r"\((%[a-z0-9]+)?,%[a-z0-9]+,?(1|2|4|8)?\)"

def inst_patch(i='JMP'):
  assert i == 'JMP'
  r = ';'.join(['s/%s jmp/%s-jmp/' % (x, x) for x in ('bnd', 'notrack')] + ['s/ret/ret DUMMY_OPERAND/'])
  return "sed '%s'" % r

def is_type(t, l): return re.match(r"\s+\S+\s+%s" % t, l) is not None
def is_branch(l, subtype=JUMP): return is_type(subtype, l)
def is_jmp_ret(line): return C.any_in(['jmp', 'ret'], get('inst', line))
def is_call_ret(line): return C.any_in(['call', 'ret'], get('inst', line))
def is_imm(line): return '$' in line
def is_memory(line): return '(' in line and 'lea' not in line and 'nop' not in line
def is_mem_imm(line): return is_memory(line) and is_imm(line)
def is_mem_load(line): return is_memory(line) and (is_type(LOAD_ANY, line) or C.any_in(('broadcast', 'insert', 'gather'), line)) 
def is_mem_store(line): return is_memory(line) and is_type(STORE, line) and C.any_in(('mov', EXTRACT, 'scatter'), line)
def is_mem_rmw(line): return is_memory(line) and is_type(STORE, line) and not C.any_in(('mov', EXTRACT, 'scatter'), line)
def is_test_load(line): return is_type(CISC_CMP, line) or is_type(BIT_TEST, line)
def is_mem_idx(line): return re.search(MEM_IDX, line)

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

REGS_32 = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp'] + \
          ['r' + str(n) + 'd' for n in range(8, 16)]
REGS_64 = [x.replace('e', 'r') for x in REGS_32 if x.startswith('e')] + \
          [x.replace('d', '') for x in REGS_32 if x.startswith('r')]

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

cvt_suff  = ['sd2si', 'si2sd', 'si2ss', 'ss2si', 'tss2si']
suff      = ['b', 'd', 'q', 'w']
V2II2V    = [x + y for y in ['', 'x'] for x in ['aeskeygenassist', 'lock cmpxchg16b']] + \
            ['comis' + x for x in ['d', 'dq', 's', 'sl']] + \
            ['cvt' + x for x in (['sd2siq', 'ss2sil', 'tsd2siq', 'tss2sil'] + cvt_suff)] + \
            ['fcmov' + x for x in ['b', 'be', 'e', 'nb', 'nbe', 'ne', 'nu', 'u']] + \
            ['fld' + x for x in ['cw', 'env']] + ['fn' + x for x in ['init', 'stcw', 'stenv', 'stsw']] + \
            ['fp' + x for x in ['atan', 'rem', 'rem1', 'tan']] + ['fsin' + x for x in ['', 'cos']] + \
            ['fyl2x' + x for x in ['', 'p1']] + ['kmov' + x for x in (suff + ['bb', 'dl', 'qq', 'ww'])] + \
            ['mov' + x for x in ['d', 'mskpd', 'mskps', 'q']] + \
            ['pcmp' + x + 'str' + y for y in ['i', 'ix', 'm', 'mx'] for x in ['e', 'i']] + \
            [x + y for y in suff for x in ['pextr', 'pinsr']] + ['ucomis' + x for x in ['d', 's']] + \
            ['vcomis' + x for x in ['d','h','s']] + \
            ['vcvt' + x for x in (['sd2usi', 'sh2si', 'sh2usi', 'si2sh', 'ss2usi', 'tsd2si', 'tsd2usi', 'tsh2si',
                                   'tsh2usi', 'tss2usi', 'usi2sd', 'usi2sh', 'usi2ss'] + cvt_suff)] + \
            ['vgather' + x for x in ['dps', 'qpd']] + ['vmov' + x for x in ['d', 'mskpd', 'mskps', 'q', 'w']] + \
            ['vpcmp' + x + 'str' + y for y in ['i', 'm'] for x in ['e', 'i']] + \
            [y + x for x in suff for y in ['vpinsr', 'vpextr']] + \
            ['vpgather' + x for x in ['dd','dq','qd']] + ['vpscatter' + x for x in ['dd', 'qd', 'qq']] + \
            ['vscatter' + x for x in ['dpd', 'dps', 'qpd']] + ['vtest' + x for x in ['pd', 'ps']] + \
            ['vucomis' + x for x in ['d', 'h', 's']] + [y + x for x in ['', '64', 's'] for y in ['xrstor', 'xsave']] + \
            ['emms', 'enqcmd', 'extractps', 'f2xm1', 'fbld', 'fbstp', 'fcos', 'frstor', 'fscale', 'ldmxcsr', 'maskmovq', \
             'pmovmskb', 'ptest', 'rep', 'stmxcsr', 'sttilecfg', 'vextractps', 'vldmxcsr', 'vpmovmskb', 'vptest', 'vstmxcsr']

def rem_xed_sfx(line):
  inst = get('inst', line)
  if ('xmm' in line and inst.endswith('x')) or ('ymm' in line and inst.endswith('y')) or \
          (('zmm' in line or is_memory(line)) and inst.endswith('z')) or (inst.endswith('sl') and not inst.endswith('lsl')):
      return line.replace(inst, inst[:-1])
  return line
