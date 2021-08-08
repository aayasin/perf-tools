#!/usr/bin/env python
# Assembly support specific to x86
# Author: Ahmad Yasin
# edited: Aug. 2021
from __future__ import print_function
__author__ = 'ayasin'
__version__ = 0.1
# TODO:
# - .

INST_UNIQ='PAUSE'
INST_1B='NOP'

def bytes(x): return '.byte 0x' + ', 0x'.join(x.split(' '))

def long_nop(n):
  assert n > 9 and n < 16
  return bytes('66 '*(n-9) + '2E 0F 1F 84 00 00 00 00 00')

aliases = {'MOVLG': 'movabs $0x8877665544332211, %r8',
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

def x86_padd(x):
  assert (':' in x),  "Expect :N in '%s'!"%x
  n = int(x.split(':')[1])
  xx = ''
  while ( n > 15):
    xx += (aliases['NOP15'] + '; ')
    n -= 15
  xx += aliases['NOP' if n == 1 else 'NOP%d'%n]
  return xx

def x86_inst(x):
  if x.startswith('PAD'): return x86_padd(x)
  for a in aliases.keys():
    if x == a: return aliases[a]
  return x

