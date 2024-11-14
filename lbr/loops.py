#!/usr/bin/env python
# Copyright (c) 2020-2024, Intel Corporation
# Author: Ahmad Yasin
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# A module for processing loops in LBR streams
#
from __future__ import print_function
__author__ = 'ayasin'

import common as C
from common import inc
import lbr.common_lbr as LC
import lbr.x86_fusion as x86_f, lbr.x86 as x86
import re, sys, os

use_cands = os.getenv('LBR_USE_CANDS')

loops, contigous_loops = {}, []
total_cycles = 0

def is_loop_by_ip(ip):  return ip in loops
def is_loop(line):    return is_loop_by_ip(LC.line2info(line).ip())
# FIXME: this does not work for non-contigious loops!
def is_in_loop(ip, loop): return ip and loop <= ip <= loops[loop]['back']
def get_loop(ip):     return loops[ip] if ip in loops else None
def loop_by_line(line, body=False):
  ip = LC.line2info(line).ip()
  if not ip: return False
  for loop_ipc in loops:
    if (body and loop_ipc < ip < loops[loop_ipc]['back']) or \
            (not body and loop_ipc <= ip <= loops[loop_ipc]['back']):
      return loop_ipc
  return None
def is_loop_exit(loop_ip, loop_back, ip, next_line=None):
  if not next_line:  # last taken line in sample
    return ip != loop_back
  next_ip = LC.line_ip(next_line)
  return not is_in_loop(next_ip, loop_ip)

def tripcount(ip, loop_ipc, state):
  if state == 'new' and loop_ipc in loops:
    if 'tripcount' not in loops[loop_ipc]: loops[loop_ipc]['tripcount'] = {}
    state = 'valid'
  elif type(state) is int:
    if ip == loop_ipc: state += 1
    elif not is_in_loop(ip, loop_ipc):
      inc(loops[loop_ipc]['tripcount'], str(state))
      state = 'done'
  elif state == 'valid':
    if ip == loop_ipc:
      state = 1
  return state

# tripcount-mean stat calculation for loops with tripcount-mode 32+
# supports only loops with size attribute
# no support for non-contiguous loops
# calculation doesn't consider indirect jumps entrances to loops
def tripcount_mean(loop, loop_ipc):
  if not isinstance(loop['size'], int): return None
  if 'non-contiguous' in loop['attributes']: return None
  hotness = lambda l: int(C.str2list(l)[0])
  hex_ipc, size = '0%x' % loop_ipc, loop['size']
  loop_body = C.exe_output(C.grep(hex_ipc, LC.hitcounts, '-B1 -A%s' % size), sep='\n').split('\n')
  before = 0
  hex_ipc = hex_ipc[1:]
  head = 0 if hex_ipc in loop_body[0] else 1
  loop_hotness = hotness(loop_body[head])
  if head == 1 and not x86.is_jmp_ret(loop_body[0]):  # JCC before loop is not considered a special case
    before += hotness(loop_body[0])  # entrance by inst before loop
  addresses = hex_ipc
  for i in range(head + 1, head + size):
    line = loop_body[i].replace(str(hotness(loop_body[i])), '')
    addresses += '|' + LC.line2info(line).ip_hex()
  # entrance by JMP to loop code
  # JCC that may jump to loop is not included
  entrances = C.exe_output(C.grep(r'jmp*\s+0x(%s)' % addresses, LC.hitcounts, '-E'), sep='\n')
  if entrances != '':
    for line in entrances.split('\n'): before += hotness(line)
  if before == 0:
    C.warn('used default tripcount-mean calculation for loop at %s' % LC.hex_ip(loop_ipc))
    return None
  if not '0x%x' % loop['back'] in loop_body[-1]:  # hotness after exiting loop code
    after = hotness(loop_body[-1])
    avg = float(before + after) / 2
  else: avg = float(before)
  return round(loop_hotness / avg, 2)

jump_to_mid_loop = {}
def detect_jump_to_mid_loop(ip, xip):
  if xip in jump_to_mid_loop:
    jump_to_mid_loop[xip] += 1
    return
  for l in contigous_loops:
    if ip != l and is_in_loop(ip, l) and not is_in_loop(xip, l):
      jump_to_mid_loop[xip] = 1
      break

def loop_stats(line, loop_ipc, tc_state):
  def mark(regex, tag):
    global loop_stats_atts, loop_stats_id
    if re.findall(regex, line):
      if not loop_stats_atts or tag not in loop_stats_atts:
        loop_stats_atts = ';'.join((loop_stats_atts, tag)) if loop_stats_atts else tag
      return 1
    return 0
  global loop_stats_id, loop_stats_atts
  if not line: # update loop attributes & exit
    if len(loop_stats_atts) > len(loops[loop_stats_id]['attributes']):
      loops[loop_stats_id]['attributes'] = loop_stats_atts
      if LC.debug and int(LC.debug, 16) == loop_stats_id: print(loop_stats_atts, LC.stat['total'])
      loop_stats_atts = ''
      loop_stats_id = None
    return
  # loop-body stats, FIXME: on the 1st encoutered loop in a new sample for now
  # TODO: improve perf of loop_stats invocation
  #if (stats.loops() == 'No' or
  #  (stats.loops() == 'One' and line_ip(line) != loop_ipc and tc_state == 'new')):
  #  #not (is_loop(line) or (type(tcstate) == int)))):
  #  return tc_state
  #elif tc_state == 'new' and is_loop(line):
  info = LC.line2info(line)
  if LC.stats.loop() and tc_state == 'new' and is_loop(line):
    loop_stats_id = info.ip()
    loop_stats_atts = ''
  if loop_stats_id:
    if not is_in_loop(info.ip(), loop_stats_id): # just exited a loop
      loop_stats(None, 0, 0)
    else:
      mark(x86.INDIRECT, 'indirect')
      mark(x86.IMUL, 'scalar-int')
      if info.inst().startswith('vp'): pass
      else: mark(r"[^k]s%s\s[\sa-z0-9,\(\)%%]+mm" % x86.FP_SUFFIX, 'scalar-fp')
      for i in range(LC.vec_size):
        if mark(r"[^aku]p%s\s+.*%s" % (x86.FP_SUFFIX, LC.vec_reg(i)), LC.vec_len(i, 'fp')): continue
        mark(LC.VEC(i), LC.vec_len(i))
  return tripcount(info.ip(), loop_ipc, tc_state)
loop_stats_id = None
loop_stats_atts = ''

bwd_br_tgts = []
loop_cands = []
functions_in_loops, inter_loops = set(), set()
inter_loops_dict = dict()
def detect_loop(ip, lines, loop_ipc, lbr_takens, srcline,
                MOLD=4e4):  # Max Outer Loop Distance
  global bwd_br_tgts, loop_cands, contigous_loops, functions_in_loops, inter_loops, inter_loops_dict  # unlike nonlocal, global works in python2 too!
  def find_block_ip(x=len(lines) - 2):
    while x >= 0:
      if LC.is_taken(lines[x]):
        n = LC.next_line(lines, x)
        if n is None: return 0, -1
        return LC.line2info(n).ip(), x
      x -= 1
    return 0, -1
  def has_ip(at):
    while at > 0:
      if LC.line2info(lines[at]).ip() == ip: return True
      at -= 1
    return False
  def has_call(at):
    res = False
    while at > 0:
      if 'call' in lines[at]: res = True
      if LC.line2info(lines[at]).ip() == ip: return res
      at -= 1
    return False
  prev_l = LC.prev_line(lines)
  prev_i = LC.line2info(prev_l)
  def iter_update():
    # inc(loop['BK'], hex(line_ip(lines[-1])))
    assert ip == loop_ipc
    if 'IPC' not in loop: loop['IPC'] = {}
    if len(lbr_takens) == 1 or lbr_takens[-2] != loops[ip]['back']: LC.paths_inc('entry', loop, lbr_takens)
    if not LC.has_timing(prev_l): return
    cycles, takens = 0, []
    begin, at = find_block_ip()
    info_at = LC.line2info(lines[at])
    while begin:
      inner_loop, inner_func = False, 0
      if begin == ip:
        if cycles == 0: inc(loop['IPC'], LC.line_timing(prev_l)[1])  # IPC is supported for loops execution w/ no takens
        if 'Conds' in loop and 'Cond_polarity' in loop:
          for c in loop['Cond_polarity'].keys(): loop['Cond_polarity'][c]['tk' if c in takens else 'nt'] += 1
        cycles += LC.line_timing(prev_l)[0]
        LC.glob['loop_cycles'] += cycles
        LC.glob['loop_iters'] += 1
        break
      else:
        # last taken is inner loop back
        for l in loops[ip]['inner-loops']:
          if info_at.ip() == loops[LC.str2int(l, lines)]['back']:
            inner_loop = True
            break
        # last taken is call/ret (function)
        if 'call' in lines[at]: inner_func += 1
        elif 'ret' in lines[at]: inner_func -= 1
        if LC.has_timing(lines[at]):
          if not inner_loop and inner_func >= 0: cycles += LC.line_timing(lines[at])[0]
          takens += [lines[at]]
          begin, at = find_block_ip(at - 1)
        else:
          break
  def ilen_on(): return 'ilen:' in prev_l
  def indirect_jmp_enter(): return 'jmp' in prev_l and LC.is_type(x86.INDIRECT, prev_l)

  if ip in loops:
    loop = loops[ip]
    loop['hotness'] += 1
    if srcline and not 'srcline' in loop: loop['srcline'] = srcline
    if prev_i.is_taken():
      if indirect_jmp_enter() and 'entered_by_indirect' not in loop['attributes']:
        loop['attributes'] += ';entered_by_indirect'
      if ip == loop_ipc and prev_i.ip() == loop['back']: iter_update()
    elif not loop['entry-block']:
      loop['entry-block'] = find_block_ip()[0]
    # Try to fill size & attributes for already detected loops
    if not loop['size'] and not loop['outer'] and len(lines) > 2 and prev_i.ip() == loop['back']:
      size, cnt, conds, op_jcc_mf, mov_op_mf, ld_op_mf, erratum = 1, {}, [], 0, 0, 0, 0 if ilen_on() else None
      types = ['lea', 'cmov'] + x86.MEM_INSTS + LC.user_loop_imix
      for i in types: cnt[i] = 0
      x = len(lines) - 2
      while x >= 1:
        info_x = LC.line2info(lines[x])
        if info_x.is_label():
          x -= 1
          continue
        size += 1
        inst_ip = info_x.ip()
        if info_x.is_taken():
          break  # do not fill loop size/etc unless all in-body branches are non-taken
        if info_x.is_cond_br(): conds += [inst_ip]
        next_l = LC.next_line(lines, x)
        if x86_f.is_jcc_fusion(lines[x], next_l):
          op_jcc_mf += 1
        elif x == len(lines) - 2 or not x86_f.is_jcc_fusion(next_l, LC.next_line(lines, x, step=2)):
          if x86_f.is_ld_op_fusion(lines[x], next_l): ld_op_mf += 1
          elif x86_f.is_mov_op_fusion(lines[x], next_l): mov_op_mf += 1
        if x86_f.is_vec_ld_op_fusion(lines[x], next_l): ld_op_mf += 1
        elif x86_f.is_vec_mov_op_fusion(lines[x], next_l): mov_op_mf += 1
        # erratum feature disabled if erratum is None, otherwise erratum counts feature cases
        if erratum is not None and LC.is_jcc_erratum(next_l, lines[x]): erratum += 1
        t = info_x.inst_type()
        if t and t in types: cnt[t] += 1
        if inst_ip == ip:
          loop['size'], loop['Conds'], loop['op-jcc-mf'], loop['mov-op-mf'], loop['ld-op-mf'] = \
              (size, len(conds), op_jcc_mf, mov_op_mf, ld_op_mf)
          if erratum is not None: loop['jcc-erratum'] = erratum
          for i in types: loop[i] = cnt[i]
          # not using rmw in imix-ID helps correlating loops despite register spills (occured in certain compilation of 548.exchange2)
          loop['imix-ID'] = C.num2char(loop['load']) + C.num2char(loop['store']) + C.num2char(loop['Conds']) + C.num2char(loop['lea'])
          if len(conds):
            loop['Cond_polarity'] = {}
            for c in conds: loop['Cond_polarity'][c] = {'tk': 0, 'nt': 0}
          break
        elif inst_ip and (inst_ip < ip or inst_ip > loop['back']):
          break
        x -= 1
    # interleaving loops
    k = str(ip)
    prev_ip = LC.line_ip(prev_l)
    if k in inter_loops_dict:
      flag, loop1, loop2 = inter_loops_dict[k]
      if flag is True: return
      if not (is_in_loop(prev_ip, loop1) or is_in_loop(prev_ip, loop2)):
        inter_loops_dict[k][0] = None
      elif flag is None:
        inter_loops_dict[k][0] = prev_ip
      elif prev_ip != flag:
        inter_loops_dict[k][0] = True
        inter_loops.add((loop1, loop2))
    return

  # only simple loops, of these attributes, are supported:
  # * loop-body is entirely observed in a single sample
  # * a tripcount > 1 is observed
  if prev_i.is_taken():
    xip = prev_i.ip()
    if ilen_on(): detect_jump_to_mid_loop(ip, xip)
    if xip <= ip:
      pass  # not a backward jump
    elif prev_i.is_call_ret():
      pass  # requires --xed
    elif (xip - ip) >= MOLD:
      LC.warn(0x200, "too large distance in:\t%s" % prev_l.split('#')[0].strip())
    elif (use_cands and ip in loop_cands) or (not use_cands and ip in bwd_br_tgts):
      if use_cands:
        loop_cands.remove(ip)
      else:
        bwd_br_tgts.remove(ip)
      inner, outer = 0, 0
      ins, outs = set(), set()
      for l in loops:
        if ip > l and xip < loops[l]['back']:
          inner += 1
          outs.add(LC.hex_ip(l))
          loops[l]['outer'] = 1
          loops[l]['inner-loops'].add(LC.hex_ip(ip))
        if ip < l and xip > loops[l]['back']:
          outer = 1
          ins.add(LC.hex_ip(l))
          loops[l]['inner'] += 1
          loops[l]['outer-loops'].add(LC.hex_ip(ip))
        # interleaving loops
        if l < ip < loops[l]['back'] < xip or ip < l < xip < loops[l]['back']:
          # [prev ip before shared block, loop1 ip, loop2 ip]
          inter_loops_dict[str(ip)] = [xip, l, ip]
      # TODO: entry-block seems redundant with addition of entry-paths histo
      loops[ip] = {'back': xip, 'hotness': 1, 'size': None, 'imix-ID': None,
                   'attributes': ';entered_by_indirect' if indirect_jmp_enter() else '',
                   'entry-block': 0 if xip > ip else find_block_ip()[0],  # 'BK': {hex(xip): 1, },
                   'inner': inner, 'outer': outer, 'inner-loops': ins, 'outer-loops': outs
                   }
      if srcline: loops[ip]['srcline'] = srcline.replace(':', ';')
      ilen = prev_i.ilen()
      if ilen:
        loops[ip]['sizeIB'] = int(xip) - ip + ilen  # size In Bytes
        if (ip + loops[ip]['sizeIB'] - ilen) == int(xip): contigous_loops += [ip]
      if has_call(len(lines) - 2): functions_in_loops.add(ip)
      return
    elif use_cands and len(lines) > 2 and ip in bwd_br_tgts and has_ip(len(lines) - 2):
      bwd_br_tgts.remove(ip)
      loop_cands += [ip]
    elif ip not in bwd_br_tgts and (use_cands or has_ip(len(lines) - 2)):
      bwd_br_tgts += [ip]

def print_loop_hist(loop_ipc, name, weighted=False, sortfunc=None):
  loop = loops[loop_ipc]
  if name not in loop: return None
  d = LC.print_hist((loop[name], name, loop, loop_ipc, sortfunc, weighted), tripcount_mean_func=tripcount_mean)
  if not type(d) is dict: return d
  tot = d['total']
  del d['total']
  del d['type']
  for x in d.keys(): loop['%s-%s' % (name, x)] = d[x]
  print('')
  return tot

def find_print_loop(ip, sloops):
  num = 1
  for l in reversed(sloops):
    if l[0] == ip:
      print_loop(l[0], num, detailed=True)
      print('\n'*2)
      return
    num += 1

def print_loop(ip, num=0, print_to=sys.stdout, detailed=False):
  if not isinstance(ip, int): ip = int(ip, 16) #should use (int, long) but fails on python3
  def printl(s, end=''): return print(s, file=print_to, end=end)
  if ip not in loops:
    printl('No loop was detected at %s!' % LC.hex_ip(ip), '\n')
    return
  loop = loops[ip].copy()
  def set2str(s, top=0 if detailed else 3):
    new = loop[s]
    if top and len(new) > top:
      n = len(new) - top
      new = set()
      while top > 0:
        new.add(loop[s].pop())
        top -= 1
      new.add('.. %d more'%n)
    loop[s] = C.chop(str(sorted(new, reverse=True)), (")", 'set('))
  fixl = ['hotness']
  if 'srcline' in loop: fixl.append('srcline')
  if LC.glob['loop_cycles']: fixl.append('FL-cycles%')
  fixl += ['size', 'imix-ID']
  loop['hotness'] = '%6d' % loop['hotness']
  loop['size'] = str(loop['size']) if loop['size'] else '-'
  printl('%soop#%d: [ip: %s, ' % ('L' if detailed else 'l', num, LC.hex_ip(ip)))
  for x in fixl: printl('%s: %s, ' % (x, loop[x]))
  if not LC.stats.loop(): del loop['attributes']
  elif not len(loop['attributes']): loop['attributes'] = '-'
  elif ';' in loop['attributes']: loop['attributes'] = ';'.join(sorted(loop['attributes'].split(';')))
  dell = ['hotness', 'srcline', 'FL-cycles%', 'size', 'imix-ID', 'back', 'entry-block', 'IPC', 'tripcount']
  for x in LC.paths_range: dell += ['entry-paths-%d' % x]
  #if 'taken' in loop and loop['taken'] <= loop['Conds']: dell += ['taken']
  if 'takens' in loop:
    for i in range(len(loop['takens'])):
      loop['takens'][i] = LC.hex_ip(loop['takens'][i])
  if not (LC.verbose & 0x20): dell += ['Cond_polarity', 'cyc/iter'] # No support for >1 Cond. cyc/iter needs debug (e.g. 548-xm3-basln)
  for x in ('back', 'entry-block'): printl('%s: %s, ' % (x, LC.hex_ip(loop[x])))
  for x, y in (('inn', 'out'), ('out', 'inn')):
    if loop[x + 'er'] > 0: set2str(y + 'er-loops')
    else: dell += [y + 'er-loops']
  for x in dell:
    if x in loop: del loop[x]
  printl(C.chop(str(loop), "'{}\"") + ']', '\n')
