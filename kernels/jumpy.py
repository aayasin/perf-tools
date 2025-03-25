#!/usr/bin/env python3
# Copyright (c) 2020-2024, Intel Corporation
# Author: Ahmad Yasin
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT # ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# Generator for jumpy-* code patterns
#
from __future__ import print_function
__author__ = 'ayasin'

import random

import os, sys
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/..')
import common as C

debug=0
def step(x='.'): C.printf(x)

jumpy_modes = ['jumpy-seq', 'jumpy-random']

flags = None
def init(mode, n, args):
  global flags
  flags = C.args_parse({'prefetch': 0, 'prefetch-inst': 'prefetcht2',
      'rate': 1, 'numbers-labels': 0}, args)
  flags['mode'] = mode
  flags['n'] = n
  return {x: flags[x] for x in ('prefetch-inst', 'rate')} if flags['prefetch'] else None

def print_list(l):
  x=0
  print('list: ', end=' ')
  for i in range(flags['n']):
    print('%s ->'%str(l[x]), end=' ')
    x=l[x]
  print('.')

def jumpy_idx(mode, n, prefetch):
  if mode == 'jumpy-seq':
    jumpy_idx.counter += 1
    return jumpy_idx.counter
  elif mode.startswith('jumpy-random'):
    if jumpy_idx.counter == 0:
      if n < 4: C.error('jumpy-random: cannot converge with --num<4')
      done = False
      visited_l = [0] * n
      patch_list = [None] * n if flags['numbers-labels'] else None
      if debug>1: print(visited_l)
      step('// jump-random: trials ')
      xx=n
      trial=1
      while not done:
        jumpy_idx.list = random.sample(range(n), n)
        while jumpy_idx.list[0] in [n-1, 1]:
          if debug>3: print('list[0]=%d:'%jumpy_idx.list[0], jumpy_idx.list)
          step()
          jumpy_idx.list = random.sample(range(n), n)
          trial += 1
        visited_l = [0] * n
        lookahead = None
        if flags['prefetch']:
          jumpy_idx.pf_list = [0] * n
          lookahead = [jumpy_idx.list[jumpy_idx.list[0]]] * flags['prefetch']
          for i in range(flags['prefetch'] - 1):
            lookahead[i+1] = jumpy_idx.list[lookahead[i]]
        done = True
        if debug>2: print('while:', jumpy_idx.list)
        x=0
        r=0
        while r < n:
          if visited_l[x]:
            done = False
            if debug>3: print('cycle of r=%d!'%r)
            break
          visited_l[x]=1
          xx = x
          if lookahead:
            if debug>1: print('lookahead:', lookahead)
            jumpy_idx.pf_list[x] = lookahead[-1]
            lookahead.append(jumpy_idx.list[lookahead[-1]])
            lookahead.pop(0)
          x = jumpy_idx.list[x]
          if patch_list:
            patch_list[xx] = str(x) + ('f' if x>xx else 'b')
          r += 1
        if debug>1 and done: print('done: xx=%d, r=%d!'%(xx, r))
      jumpy_idx.list[xx] = n
      if debug:
        print("final:", jumpy_idx.list, jumpy_idx.pf_list, patch_list)
        for l in (jumpy_idx.list, jumpy_idx.pf_list): print_list(l)
      if patch_list:
        patch_list[xx] = str(n)+'f'
        jumpy_idx.list = patch_list
      step('\n')
      jumpy_idx.counter = -1
    return jumpy_idx.pf_list.pop(0) if prefetch else jumpy_idx.list.pop(0)
  else: C.error("jumpy_idx(): unsupported mode '%s'!"%mode)
jumpy_idx.counter = 0
jumpy_idx.list = None
jumpy_idx.pf_counter = 0
jumpy_idx.pf_list = None

def next(prefetch=False):
  assert flags, "init() was not called"
  return jumpy_idx(flags['mode'], flags['n'], prefetch)

