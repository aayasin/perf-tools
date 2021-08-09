#!/usr/bin/env python
# Assembly support specific to x86
# Author: Ahmad Yasin
# edited: Aug. 2021
__author__ = 'ayasin'
__version__ = 0.2
# TODO:
# - .

INST_UNIQ='PAUSE'
INST_1B='NOP'
MOVLG='MOVLG'

def bytes(x): return '.byte 0x' + ', 0x'.join(x.split(' '))

def long_nop(n):
  assert n > 9 and n < 16
  return bytes('66 '*(n-9) + '2E 0F 1F 84 00 00 00 00 00')

aliases = {MOVLG: 'movabs $0x8877665544332211, %r8',
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

