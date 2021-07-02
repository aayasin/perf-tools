#!/usr/bin/env python
# Author: Ahmad Yasin
# edited: Jul. 2021
from __future__ import print_function
__author__ = 'ayasin'

import random

import os, sys
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/..')
import common as C

debug=0
def step(x='.'): C.printf(x)

jumpy_modes = ['jumpy-seq', 'jumpy-random', 'jumpy-random#']

def get_modes(): return jumpy_modes[0:2]

def jumpy_idx(mode, n):
  if mode == 'jumpy-seq':
    jumpy_idx.counter += 1
    return jumpy_idx.counter
  elif mode.startswith('jumpy-random'):
    if jumpy_idx.counter == 0:
      if n < 4: C.error('jumpy-random: cannot converge with --num<4')
      done = False
      visited_l = [0] * n
      patch_list = [None] * n if mode.endswith('#') else None
      if debug: print(visited_l)
      step('// jump-random: trials ')
      xx=n
      trial=1
      while not done:
        jumpy_idx.list = random.sample(range(n), n)
        while jumpy_idx.list[0] in [n-1, 1]:
          if debug: print('list[0]=%d:'%jumpy_idx.list[0], jumpy_idx.list)
          step()
          jumpy_idx.list = random.sample(range(n), n)
          trial += 1
        visited_l = [0] * n
        done = True
        if debug: print('while:', jumpy_idx.list)
        x=0
        r=0
        while r < n:
          if visited_l[x]:
            done = False
            if debug: print('cycle of r=%d!'%r)
            break
          visited_l[x]=1
          xx = x
          x = jumpy_idx.list[x]
          if patch_list:
            patch_list[xx] = str(x) + ('f' if x>xx else 'b')
          r += 1
        if debug and done: print('done: xx=%d, r=%d!'%(xx, r))
      jumpy_idx.list[xx] = n
      if debug: print("final:", jumpy_idx.list, patch_list)
      if patch_list:
        patch_list[xx] = str(n)+'f'
        jumpy_idx.list = patch_list
      step('\n')
      jumpy_idx.counter = -1
    return jumpy_idx.list.pop(0)
  else: C.error("jumpy_idx(): unsupported mode '%s'!"%mode)
jumpy_idx.counter = 0
jumpy_idx.list = None

def next(mode, n):
  return jumpy_idx(mode, n)

