#!/usr/bin/env python3
# Copyright (c) 2020-2024, Intel Corporation
# Author: Amiri Khalil
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# A module for handling lbr related stats
# A stat is any of: counter, metric
#
from __future__ import print_function
__author__ = 'akhalil'

from lbr.lbr import print_stat
import lbr.x86 as x86, lbr.x86_fusion as x86_f
import re, os
import common as C

def inst_fusions(hitcounts, info):
  stats_data = {'LD-OP':      0,
                'MOV-OP':     0,
                'VEC LD-OP':  0,
                'VEC MOV-OP': 0}
  hotness = lambda s: C.str2list(s)[0]
  def is_mov(l):
    l = l.replace(hotness(l), '')  # remove hotness
    return x86_f.is_fusion_mov(x86.get('inst', l), int=False) and not x86.is_mem_store(l)
  def calc_stats():
    block = hotness_key = None
    int_cands_log = hitcounts.replace("hitcounts", "int-fusion-candidates")
    vec_cands_log = int_cands_log.replace('int', 'vec')
    def find_cand(lines):
      patch = lambda s: s.replace(s.split()[0], '')
      if len(lines) < 3: return None  # need 3 insts at least
      mov_line = patch(lines[0])
      dest_reg = x86.get('dst', mov_line)
      dest_subs = x86.sub_regs(dest_reg)
      # dest reg in 2nd line -> no candidate
      # a. if dest reg is dest in 2nd line and fusion occurs -> not candidate
      # b. if dest reg is dest in 2nd line and no fusion ->
      # no candidate and disables next OPs to be candidates because dest reg got modified
      # c. if dest reg is src in 2nd line -> dest reg value is used before OP, cancels candidate
      if C.any_in(dest_subs, lines[1]): return None
      to_check = lines[2:]
      for i, line in enumerate(to_check):
        line = patch(line)
        if x86.get('dst', line) == dest_reg:  # same dest reg
          # jcc macro-fusion disables candidate
          if i < len(to_check) - 1 and x86_f.is_jcc_fusion(line, patch(to_check[i+1])): return None
          ld_fusion, mov_fusion = x86_f.is_ld_op_fusion(mov_line, line), x86_f.is_mov_op_fusion(mov_line, line)
          vld_fusion, vmov_fusion = x86_f.is_vec_ld_op_fusion(mov_line, line), x86_f.is_vec_mov_op_fusion(mov_line, line)
          int_fusion, vec_fusion = ld_fusion or mov_fusion, vld_fusion or vmov_fusion
          if not int_fusion and not vec_fusion: return None
          # check if dest reg was used as src before OP or any OP src was ever modified
          srcs = x86.get('srcs', line)
          for x in range(1, i + 2):
            if int_fusion and re.search(x86.CMOV, x86.get('inst', lines[x])): return None  # CMOV will use wrongly modified RFLAGS
            line_dst = x86.get('dst', lines[x])
            for src in srcs:
              if not x86.is_imm(src) and x86.is_sub_reg(line_dst, src): return None  # OP src was modified before OP
            if C.any_in(dest_subs, lines[x]): return None  # dest reg used before OP
          # candidate found
          key = 'LD' if ld_fusion else 'MOV' if mov_fusion else 'VEC LD' if vld_fusion else 'VEC MOV'
          stats_data[key + '-OP'] += int(hotness(lines[0]))
          # append candidate block to log
          header, tail = lines[0][:25] + "\n", lines[i+2][:25] + "zz - block end\n"  # headers to differentiate blocks
          block_list = [header] + lines[0:i+3] + [tail]
          C.fappend(''.join(block_list), int_cands_log if int_fusion else vec_cands_log, end='')
      return None
    if os.path.exists(int_cands_log): os.remove(int_cands_log)
    if os.path.exists(vec_cands_log): os.remove(vec_cands_log)
    # for each hotness block, create a list of the lines then check
    with open(hitcounts, "r") as hits:
      for line in hits:
        def restart(): return [[line], hotness(line)] if is_mov(line) else [None, None]
        # check blocks starting with not store MOV
        if not is_mov(line) and not block: continue
        if not block:  # new block first line found
          block, hotness_key = restart()
          continue
        # append lines from the same basic block (by hotness)
        if hotness(line) == hotness_key: block.append(line)
        else:  # basic block end, check candidates
          for i, block_line in enumerate(block):
            if is_mov(block_line): find_cand(block[i:])
          hotness_key, block = restart()  # restart for next block
  assert C.exe_one_line(C.grep(' ALL instructions:', info)), 'invalid %s' % info
  total = int(C.exe_one_line(C.grep(' ALL instructions:', info)).split(':')[1].strip())
  calc_stats()
  for stat, value in stats_data.items():
    print_stat('%s fusible-candidate' % stat, value, ratio_of=('ALL', total), log=info)
