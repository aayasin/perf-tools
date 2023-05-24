#!/usr/bin/env python
# Copyright (c) 2020-2023, Intel Corporation
# Author: Ahmad Yasin
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# A module for processing LBR streams
#
from __future__ import print_function
__author__ = 'ayasin'
__version__= 2.12 # see version line of do.py

import common as C, pmu
from common import inc
import os, re, sys
import llvm_mca_lbr
from kernels import x86
try:
  from numpy import average
  numpy_imported = True
except ImportError:
  numpy_imported = False

MEM_INSTS = ['load', 'store', 'lock', 'prefetch']
def INT_VEC(i): return r"\s%sp.*%s" % ('(v)?' if i == 0 else 'v', vec_reg(i))

hitcounts = C.envfile('PTOOLS_HITS')
llvm_log = C.envfile('LLVM_LOG')
debug = os.getenv('LBR_DBG')
verbose = C.env2int('LBR_VERBOSE', base=16) # nibble 0: stats, 1: extra info, 2: warnings
use_cands = os.getenv('LBR_USE_CANDS')
user_imix = C.env2list('LBR_IMIX', ['vpmovmskb', 'imul'])
user_loop_imix = C.env2list('LBR_LOOP_IMIX', ['zcnt'])

def hex(ip): return '0x%x' % ip if ip > 0 else '-'
def hist_fmt(d): return '%s%s' % (str(d).replace("'", ""), '' if 'num-buckets' in d and d['num-buckets'] == 1 else '\n')
def ratio(a, b): return C.ratio(a, b) if b else '-'
def read_line(): return sys.stdin.readline()
def paths_range(): return range(3, C.env2int('LBR_PATH_HISTORY', 3))

def warn(mask, x): return C.warn(x) if edge_en and (verbose & mask) else None

if debug: C.dump_stack_on_error = 1
def exit(x, sample, label, n=0, msg=str(debug)):
  if x: C.annotate(x, label)
  print_sample(sample, n)
  C.error(msg) if x else sys.exit(0)

def str2int(ip, plist):
  try:
    return int(ip, 16)
  except ValueError:
    print_sample(plist[1])
    assert 0, "expect address in '%s' of '%s'" % (ip, plist[0])

def skip_sample(s):
  line = read_line()
  while not re.match(r"^$", line):
    line = read_line()
    assert line, 'was input truncated? sample:\n%s'%s
  return 0

def header_ip_str(line):
  x = is_header(line)
  assert x, "Not a head of sample: " + line
  if header_ip_str.first:
    if '[' in x.group(1): header_ip_str.position += 1
    header_ip_str.first = False
  return x.group(4) #C.str2list(line)[header_ip_str.position]
header_ip_str.first = True
header_ip_str.position = 5
def header_ip(line): return str2int(header_ip_str(line), (line, None))

def header_cost(line):
  x = is_header(line)
  assert x, "Not a head of sample: " + line
  return str2int(C.str2list(line.split(':')[2])[2], (line, None))

def line_ip_hex(line):
  x = re.match(r"\s+(\S+)\s+(\S+)", line)
  # assert x, "expect <address> at left of '%s'" % line
  return x.group(1).lstrip("0")

def line_ip(line, sample=None):
  try:
    return str2int(line_ip_hex(line), (line, sample))
  except:
    exit(line, sample, 'line_ip()', msg="expect <address> at left of '%s'" % line.strip())

def line_timing(line):
  x = re.match(r"[^#]+# (\S+) (\d+) cycles \[\d+\] ([0-9\.]+) IPC", line)
  # note: this ignores timing of 1st LBR entry (has cycles but not IPC)
  assert x, 'Could not match IPC in:\n%s' % line
  ipc = round(float(x.group(3)), 1)
  cycles = int(x.group(2))
  return cycles, ipc

def num_valid_sample(): return stat['total'] - stat['bad'] - stat['bogus']

vec_size = 3 if pmu.cpu_has_feature('avx512vl') else 2
def vec_reg(i): return '%%%smm' % chr(ord('x') + i)
def vec_len(i, t='int'): return 'vec%d-%s' % (128 * (2 ** i), t)
def line_inst(line):
  pInsts = ['cmov', 'pause', 'pdep', 'pext', 'popcnt', 'pop', 'push', 'vzeroupper'] + user_loop_imix
  allInsts = ['nop', 'lea', 'cisc-test'] + MEM_INSTS + pInsts
  if not line: return allInsts
  if 'nop' in line: return 'nop'
  elif '(' in line:  # load/store take priority in CISC insts
    if 'lea' in line: return 'lea'
    elif 'lock' in line: return 'lock'
    elif 'prefetch' in line: return 'prefetch'
    elif is_type(CISC_CMP, line) or 'gather' in line: return 'load'
    elif re.match(r"\s+\S+\s+[^\(\),]+,", line) or 'scatter' in line: return 'store'
    else: return 'load'
  else:
    for x in pInsts: # skip non-vector p/v-prefixed insts
      if x in line: return x
    r = re.match(r"\s+\S+\s+(\S+)", line)
    if not r: pass
    elif re.match(r"^(and|or|xor|not)", r.group(1)): return 'logic'
    elif re.match(r"^[pv]", r.group(1)):
      for i in range(vec_size):
        if re.findall(INT_VEC(i), line): return vec_len(i)
      warn(0x100, 'vec-int: ' + ' '.join(line.split()[1:]))
      return 'vecX-int'
  return None

def tripcount(ip, loop_ipc, state):
  if state == 'new' and loop_ipc in loops:
    if not 'tripcount' in loops[loop_ipc]: loops[loop_ipc]['tripcount'] = {}
    state = 'valid'
  elif type(state) == int:
    if ip == loop_ipc: state += 1
    elif not is_in_loop(ip, loop_ipc):
      inc(loops[loop_ipc]['tripcount'], str(state))
      state = 'done'
  elif state == 'valid':
    if ip == loop_ipc:
      state = 1
  return state

def loop_stats(line, loop_ipc, tc_state):
  def mark(regex, tag):
    if re.findall(regex, line):
      if not loop_stats.atts or not tag in loop_stats.atts:
        loop_stats.atts = ';'.join((loop_stats.atts, tag)) if loop_stats.atts else tag
      return 1
    return 0
  if not line: # update loop attributes & exit
    if len(loop_stats.atts) > len(loops[loop_stats.id]['attributes']):
      loops[loop_stats.id]['attributes'] = loop_stats.atts
      if debug and int(debug, 16) == loop_stats.id: print(loop_stats.atts, stat['total'])
      loop_stats.atts = ''
      loop_stats.id = None
    return
  # loop-body stats, FIXME: on the 1st encoutered loop in a new sample for now
  # TODO: improve perf of loop_stats invocation
  #if (glob['loop_stats_en'] == 'No' or
  #  (glob['loop_stats_en'] == 'One' and line_ip(line) != loop_ipc and tc_state == 'new')):
  #  #not (is_loop(line) or (type(tcstate) == int)))):
  #  return tc_state
  #elif tc_state == 'new' and is_loop(line):
  if glob['loop_stats_en'] and tc_state == 'new' and is_loop(line):
    loop_stats.id = line_ip(line)
    loop_stats.atts = ''
  if loop_stats.id:
    if not is_in_loop(line_ip(line), loop_stats.id): # just exited a loop
      loop_stats(None, 0, 0)
    else:
      mark(x86.INDIRECT, 'indirect')
      mark(x86.IMUL, 'scalar-int')
      mark(r"[^k]s%s\s[\sa-z0-9,\(\)%%]+mm" % x86.FP_SUFFIX, 'scalar-fp')
      for i in range(vec_size):
        if mark(r"[^aku]p%s\s+.*%s" % (x86.FP_SUFFIX, vec_reg(i)), vec_len(i, 'fp')): continue
        mark(INT_VEC(i), vec_len(i))
  return tripcount(line_ip(line), loop_ipc, tc_state)
loop_stats.id = None
loop_stats.atts = ''

bwd_br_tgts = [] # better make it local to read_sample..
loop_cands = []
def detect_loop(ip, lines, loop_ipc, lbr_takens, srcline,
                MOLD=4e4): #Max Outer Loop Distance
  global bwd_br_tgts, loop_cands # unlike nonlocal, global works in python2 too!
  def find_block_ip(x = len(lines)-2):
    while x>=0:
      if is_taken(lines[x]):
        return line_ip(lines[x+1]), x
      x -= 1
    return 0, -1
  def has_ip(at):
    while at > 0:
      if is_callret(lines[at]): return False
      if line_ip(lines[at]) == ip: return True
      at -= 1
    return False
  def iter_update():
    #inc(loop['BK'], hex(line_ip(lines[-1])))
    if ip != loop_ipc: return
    if not 'IPC' in loop: loop['IPC'] = {}
    if not has_timing(lines[-1]): return
    cycles, takens = 0, []
    begin, at = find_block_ip()
    while begin:
      if begin == ip:
        if cycles == 0: inc(loop['IPC'], line_timing(lines[-1])[1]) # IPC is supported for loops execution w/ no takens
        if 'Conds' in loop and 'Cond_polarity' in loop:
          for c in loop['Cond_polarity'].keys(): loop['Cond_polarity'][c]['tk' if c in takens else 'nt'] += 1
        cycles += line_timing(lines[-1])[0]
        glob['loop_cycles'] += cycles
        glob['loop_iters'] += 1
        break
      else:
        if has_timing(lines[at]):
          cycles += line_timing(lines[at])[0]
          takens += [ lines[at] ]
          begin, at = find_block_ip(at-1)
        else: break

  if ip in loops:
    loop = loops[ip]
    loop['hotness'] += 1
    if is_taken(lines[-1]):
      iter_update()
      if ip == loop_ipc:
        for x in paths_range():
          if not 'paths-%d'%x in loop: loop['paths-%d'%x] = {}
          inc(loop['paths-%d'%x], ';'.join([hex(a) for a in lbr_takens[-x:]]))
    # Try to fill size & attributes for already detected loops
    if not loop['size'] and not loop['outer'] and len(lines)>2 and line_ip(lines[-1]) == loop['back']:
      size, cnt, conds, fusion = 1, {}, [], 0
      types = ['taken', 'lea', 'cmov'] + MEM_INSTS + user_loop_imix
      for i in types: cnt[i] = 0
      x = len(lines)-2
      while x >= 1:
        size += 1
        if is_taken(lines[x]): cnt['taken'] += 1
        if is_type(x86.COND_BR, lines[x]): conds += [line_ip(lines[x])]
        if x86.is_fusion(lines[x], lines[x + 1]): fusion += 1
        t = line_inst(lines[x])
        if t and t in types: cnt[t] += 1
        inst_ip = line_ip(lines[x])
        if inst_ip == ip:
          loop['size'], loop['Conds'], loop['macro-fusion'] = size, len(conds), fusion
          for i in types: loop[i] = cnt[i]
          if len(conds):
            loop['Cond_polarity'] = {}
            for c in conds: loop['Cond_polarity'][c] = {'tk': 0, 'nt': 0}
          if debug and int(debug, 16) == ip: print(size, stat['total'])
          break
        elif inst_ip < ip or inst_ip > loop['back']:
          break
        x -= 1
    if not loop['entry-block'] and not is_taken(lines[-1]):
      loop['entry-block'] = find_block_ip()[0]
    return
  
  # only simple loops, of these attributes, are supported:
  # * are entirely observed in a single sample (e.g. tripcount < 32)
  # * a tripcount > 1 is observed
  # * no function calls
  if is_taken(lines[-1]):
    xip = line_ip(lines[-1])
    if xip <= ip: pass # not a backward jump
    elif (use_cands and ip in loop_cands) or (not use_cands and ip in bwd_br_tgts):
      if use_cands: loop_cands.remove(ip)
      else: bwd_br_tgts.remove(ip)
      inner, outer = 0, 0
      ins, outs = set(), set()
      for l in loops:
        if ip > l and xip < loops[l]['back']:
          inner += 1
          outs.add(hex(l))
          loops[l]['outer'] = 1
          loops[l]['inner-loops'].add(hex(ip))
        if ip < l and xip > loops[l]['back']:
          outer = 1
          ins.add(hex(l))
          loops[l]['inner'] += 1
          loops[l]['outer-loops'].add(hex(ip))
      loops[ip] = {'back': xip, 'hotness': 1, 'size': None, 'attributes': '',
        'entry-block': 0 if xip > ip else find_block_ip()[0], #'BK': {hex(xip): 1, },
        'inner': inner, 'outer': outer, 'inner-loops': ins, 'outer-loops': outs
      }
      if srcline: loops[ip]['srcline'] = srcline.replace(':', ';')
      return
    elif use_cands and len(lines) > 2 and ip in bwd_br_tgts and has_ip(len(lines)-2):
      bwd_br_tgts.remove(ip)
      loop_cands += [ip]
    elif is_callret(lines[-1]): pass # requires --xed
    elif (xip - ip) >= MOLD: warn(0x200, "too large distance in:\t%s" % lines[-1].split('#')[0].strip())
    elif not ip in bwd_br_tgts and (use_cands or has_ip(len(lines)-2)):
      bwd_br_tgts += [ip]

edge_en = 0
LBR_Event = pmu.lbr_event()[:-4]
lbr_events = []
loops = {}
stat = {x: 0 for x in ('bad', 'bogus', 'total', 'total_cycles')}
for x in ('IPs', 'events', 'takens'): stat[x] = {}
stat['size'] = {'min': 0, 'max': 0, 'avg': 0, 'sum': 0}

CISC_CMP= '_cisc-cmp'
def inst2pred(i):
  i2p = {'st-stack':  'mov\S+\s+[^\(\),]+, [0-9a-fx]+\(%.sp\)',
    'add-sub':        '(add|sub).*',
    'inc-dec':        '(inc|dec).*',
    CISC_CMP:         '(cmp[^x]|test).*\(',
    '_risc-cmp':      '(cmp[^x]|test)[^\(]*',
  }
  if i is None: return sorted(list(i2p.keys()))
  return i2p[i] if i in i2p else i

# determine what is counted globally
def is_imix(t):
  # TODO: cover FP vector too
  IMIX_LIST = MEM_INSTS + ['logic']
  if not t: return IMIX_LIST + [vec_len(x) for x in range(vec_size)] + ['vecX-int']
  return t in IMIX_LIST or t.startswith('vec')
Insts = inst2pred(None) + ['cmov', 'lea', 'jmp', 'call', 'ret', 'push', 'pop', 'vzeroupper'] + user_imix
Insts_global = Insts + is_imix(None) + ['all']
Insts_all = ['cond_backward', 'cond_forward', 'cond_non-taken', 'cond_fusible',
             'cond_non-fusible', 'cond_taken-not-first', 'cond_LD-CMP-JCC fusible',
             'cond_CISC_CMP_IMM-JCC non-fusible'] + Insts_global

glob = {x: 0 for x in ['loop_cycles', 'loop_iters'] + Insts_all}
hsts = {}
footprint = set()
pages = set()
indirects = set()

IPTB  = 'inst-per-taken-br--IpTB'
FUNCP = 'Params_of_func'
FUNCR = 'Regs_by_func'
def count_of(t, lines, x, hist):
  r = 0
  while x < len(lines):
    if is_type(t, lines[x]): r += 1
    x += 1
  inc(hsts[hist], r)
  return r

def edge_en_init(indirect_en):
  for x in ('IPC', IPTB, FUNCR, FUNCP): hsts[x] = {}
  if indirect_en:
    for x in ('', '-misp'): hsts['indirect-x2g%s' % x] = {}
  if os.getenv('LBR_INDIRECTS'):
    for x in os.getenv('LBR_INDIRECTS').split(','):
      indirects.add(int(x, 16))
      hsts['indirect_%s_targets' % x] = {}
      hsts['indirect_%s_paths' % x] = {}
  if pmu.dsb_msb() and not pmu.cpu('smt-on'): hsts['dsb-heatmap'] = {}

def read_sample(ip_filter=None, skip_bad=True, min_lines=0, labels=False, ret_latency=False,
                loop_ipc=0, lp_stats_en=False, event=LBR_Event, indirect_en=True, mispred_ip=None):
  def invalid(bad, msg):
    stat[bad] += 1
    if not loop_ipc: C.warn('%s sample encountered (%s)' % (bad, msg))
  global lbr_events, bwd_br_tgts, edge_en
  valid, lines, bwd_br_tgts = 0, [], []
  assert(not labels, "labels argument must be False!")
  glob['size_stats_en'] = skip_bad and not labels and not loop_ipc
  glob['loop_stats_en'] = lp_stats_en
  glob['ip_filter'] = ip_filter
  edge_en = C.any_in((LBR_Event, 'instructions:ppp'), event) and not ip_filter and not loop_ipc # config good for edge-profile
  if stat['total'] == 0:
    if edge_en: edge_en_init(indirect_en)
    if ret_latency: header_ip_str.position = 8
    if debug: C.printf('LBR_DBG=%s\n' % debug)
    if loop_ipc:
      read_sample.tick *= 10
      read_sample.stop = None
  
  while not valid:
    valid, lines, bwd_br_tgts = 1, [], []
    insts, takens, xip, timestamp, srcline = 0, [], None, None, None
    tc_state = 'new'
    def update_size_stats():
      size = len(lines) - 1
      if not glob['size_stats_en'] or size<0: return
      if stat['size']['sum'] == 0:
        stat['size']['min'] = stat['size']['max'] = size
      else:
        if stat['size']['min'] > size: stat['size']['min'] = size
        if stat['size']['max'] < size: stat['size']['max'] = size
      stat['size']['sum'] += size
      inc(stat['takens'], len(takens))
    stat['total'] += 1
    if stat['total'] % read_sample.tick == 0: C.printf('.')
    while True:
      line = read_line()
      # input ended
      if not line:
        if len(lines): invalid('bogus', 'input truncated')
        if stat['total'] == stat['bogus']:
          print_all()
          C.error('No LBR data in profile')
        if not loop_ipc: C.printf(' .\n')
        return lines if len(lines) > min_lines and not skip_bad else None
      header = is_header(line)
      if header:
        # first sample here (of a given event)
        ev = header.group(3)[:-1]
        if not ev in lbr_events:
          lbr_events += [ev]
          x = 'events= %s @ %s' % (str(lbr_events), header.group(1).split(' ')[-1])
          def f2s(x): return C.flag2str(' ', C.env2str(x, prefix=True))
          if len(lbr_events) == 1: x += ' primary= %s edge=%d%s%s' % (event, edge_en, f2s('LBR_STOP'), f2s('LBR_IMIX'))
          if ip_filter: x += ' ip_filter= %s' % str(ip_filter)
          if loop_ipc: x += ' loop= %s%s' % (hex(loop_ipc), C.flag2str(' history= ', C.env2int('LBR_PATH_HISTORY')))
          if verbose: x += ' verbose= %s' % hex(verbose)
          if not header.group(2).isdigit(): C.printf(line)
          C.printf(x+'\n')
        inc(stat['events'], ev)
        if debug: timestamp = header.group(1).split()[-1]
      # a new sample started
      # perf  3433 1515065.348598:    1000003 EVENT.NAME:      7fd272e3b217 __regcomp+0x57 (/lib/x86_64-linux-gnu/libc-2.23.so)
        if ip_filter:
          if not C.any_in(ip_filter, line):
            valid = skip_sample(line)
            break
          inc(stat['IPs'], header_ip_str(line))
      # a sample ended
      if re.match(r"^$", line):
        if not skip_bad and (not min_lines or len(lines) > min_lines): break
        len_m1 = 0
        if len(lines): len_m1 = len(lines)-1
        if len_m1 == 0 or\
           min_lines and (len_m1 < min_lines) or\
           header_ip(lines[0]) != line_ip(lines[len_m1]):
          valid = 0
          invalid('bogus', 'too short')
          # apparently there is a perf-script bug (seen with perf tool 6.1)
          update_size_stats()
          if debug and debug == timestamp:
            exit((line.strip(), len(lines)), lines, 'a bogus sample ended')
        elif len_m1 and type(tc_state) == int and is_in_loop(line_ip(lines[-1]), loop_ipc):
          if tc_state == 31 or (verbose & 0x10):
            inc(loops[loop_ipc]['tripcount'], '%d+' % (tc_state + 1))
            if loop_stats.id: loop_stats(None, 0, 0)
          # else: note a truncated tripcount, i.e. unknown in 1..31, is not accounted for by default.
        if mispred_ip and valid < 2: valid = 0
        if debug and debug == timestamp:
          exit((line.strip(), len(lines)), lines, 'sample-of-interest ended')
        break
      elif header and len(lines): # sample had no LBR data; new one started
        # exchange2_r_0.j 57729 3736595.069891:    1000003 r20c4:pp:            41f47a brute_force_mp_brute_+0x43aa (/home/admin1/ayasin/perf-tools/exchange2_r_0.jmpi4)
        # exchange2_r_0.j 57729 3736595.069892:    1000003 r20c4:pp:            41fad4 brute_force_mp_brute_+0x4a04 (/home/admin1/ayasin/perf-tools/exchange2_r_0.jmpi4)
        lines = []
        invalid('bogus', 'header-only') # for this one
        stat['total'] += 1 # for new one
      # invalid sample is about to end
      tag = 'not reaching sample'
      if skip_bad and tag in line:
        valid = 0
        invalid('bad', tag)
        assert re.match(r"^$", read_line())
        break
      # a line with a label
      if not labels and is_label(line):
        srcline = get_srcline(line.strip())
        continue
      # e.g. "        00007ffff7afc6ca        <bad>" then "mismatch of LBR data and executable"
      tag = 'mismatch of LBR data'
      if tag in line:
        valid = skip_sample(lines[0])
        invalid('bad', tag)
        break
      # e.g. "        prev_nonnote_           addb  %al, (%rax)"
      # TODO: replace with this line when labels is True
      #if skip_bad and len(lines) and not is_label(line) and not line.strip().startswith('0'):
      if skip_bad and len(lines) and not line.strip().startswith('0'):
        if debug and debug == timestamp:
          exit(line, lines, "bad line")
        valid = skip_sample(lines[0])
        invalid('bogus', 'instruction address missing')
        break
      ip = None if header or is_label(line) or 'not reaching sample' in line else line_ip(line, lines)
      new_line = is_line_start(ip, xip)
      if edge_en and new_line:
        footprint.add(ip >> 6)
        pages.add(ip >> 12)
      if len(lines) and not is_label(line):
        if edge_en:
          glob['all'] += 1
          # An instruction may be counted individually and/or per imix class
          for x in Insts:
            if is_type(x, line): glob[x] += 1
          t = line_inst(line)
          if t and is_imix(t): glob[t] += 1
        if len(lines) == 1:
          if is_taken(line): takens += [ip]
          # Expect a taken branch in first entry, but for some reason Linux/perf sometimes return <32 entry LBR
          #else: print('##', num_valid_sample())
        else: # a 2nd instruction
          insts += 1
          if is_taken(line):
            takens += [ip]
            if edge_en:
              inc(hsts[IPTB], insts); insts = 0
              if 'IPC' in line: inc(hsts['IPC'], line_timing(line)[1])
              if (verbose & 0x1): #FUNCR
                x = get_taken_idx(lines, -1)
                if x >= 0:
                  if is_type('call', line): count_of('st-stack', lines, x+1, FUNCP)
                  if is_type('call', lines[x]): count_of('push', lines, x+1, FUNCR)
          if edge_en and is_type(x86.COND_BR, lines[-1]) and is_taken(lines[-1]):
            glob['cond_%sward' % ('for' if ip > xip else 'back')] += 1
          # checks all lines but first
          if edge_en and is_type(x86.COND_BR, line):
            if is_taken(line): glob['cond_taken-not-first'] += 1
            else: glob['cond_non-taken'] += 1
            if x86.is_fusion(lines[-1], line):
              glob['cond_fusible'] += 1
              if len(lines) > 2 and is_type(x86.TEST_CMP, lines[-1]) and is_type(x86.LOAD, lines[-2]):
                glob['cond_LD-CMP-JCC fusible'] += 1
            else:
              glob['cond_non-fusible'] += 1
              if is_type(x86.TEST_CMP, lines[-1]) and x86.is_mem_imm(lines[-1]):
                glob['cond_CISC_CMP_IMM-JCC non-fusible'] += 1
          if 'dsb-heatmap' in hsts and (is_taken(lines[-1]) or new_line):
            inc(hsts['dsb-heatmap'], pmu.dsb_set_index(ip))
          # TODO: consider the branch instruction's bytes (once support added to perf-script)
          if 'indirect-x2g' in hsts and is_type(x86.INDIRECT, lines[-1]) and abs(ip - xip) >= 2**31:
            inc(hsts['indirect-x2g'], xip)
            if 'MISP' in lines[-1]: inc(hsts['indirect-x2g-misp'], xip)
          if xip in indirects:
            inc(hsts['indirect_%s_targets' % hex(xip)], ip)
            inc(hsts['indirect_%s_paths' % hex(xip)], '%s.%s.%s' % (hex(get_taken(lines, -2)['from']), hex(xip), hex(ip)))
          detect_loop(ip, lines, loop_ipc, takens, srcline)
        if skip_bad: tc_state = loop_stats(line, loop_ipc, tc_state)
      if len(lines) or event in line:
        line = line.rstrip('\r\n')
        if has_timing(line):
          cycles = line_timing(line)[0]
          stat['total_cycles'] += cycles
        if mispred_ip and is_taken(line) and mispred_ip == line_ip(line) and 'MISPRED' in line: valid += 1
        lines += [ line ]
      xip = ip
    if read_sample.dump: print_sample(lines, read_sample.dump)
    if read_sample.stop and stat['total'] >= int(read_sample.stop):
      C.info('stopping after %s valid samples' % read_sample.stop)
      print_common(stat['total'], print_summary=True)
      exit(None, lines, 'stop', msg="run:\t 'kill -9 $(pidof perf)'\t!")
  update_size_stats()
  return lines
read_sample.stop = os.getenv('LBR_STOP')
read_sample.tick = C.env2int('LBR_TICK', 1000)
read_sample.dump = C.env2int('LBR_DUMP', 0)


def is_type(t, l):    return re.match(r"\s+\S+\s+%s" % inst2pred(t), l)
def is_callret(l):    return is_type(x86.CALL_RET, l)

# TODO: re-design this function to return: event-name, ip, timestamp, cost, etc as a dictiorary if header or None otherwise
def is_header(line):
  def patch(x):
    if debug: C.printf("\nhacking '%s' in: %s" % (x, line))
    return line.replace(x, '-', 1)
  if '[' in line[:50]:
    p = line.split('[')[0]
    assert p, "is_header('%s'); expect a '[CPU #]'" % line.strip()
    if '::' in p: pass
    elif ': ' in p: line = patch(': ')
    elif ':' in p: line = patch(':')
  return (re.match(r"([^:]*):\s+(\d+)\s+(\S*)\s+(\S*)", line) or
#    tmux: server  3881 [103] 1460426.037549:    9000001 instructions:ppp:  ffffffffb516c9cf exit_to_user_mode_prepare+0x4f ([kernel.kallsyms])
# kworker/0:3-eve 105050 [000] 1358881.094859:    7000001 r20c4:ppp:  ffffffffb5778159 acpi_ps_get_arguments.constprop.0+0x1ca ([kernel.kallsyms])
#                              re.match(r"(\s?[\S]*)\s+([\d\[\]\.\s]+):\s+\d+\s+(\S*:)\s", line) or
#AUX data lost 1 times out of 33!
                              re.match(r"(\w)([\w\s]+)(.)", line) or
#         python3 105303 [000] 1021657.227299:          cbr:  cbr: 11 freq: 1100 MHz ( 55%)               55e235 PyObject_GetAttr+0x415 (/usr/bin/python3.6)
                              re.match(r"([^:]*):(\s+)(\w+:)\s", line) or
# instruction trace error type 1 time 1021983.206228655 cpu 1 pid 105468 tid 105468 ip 0 code 8: Lost trace data
                              re.match(r"(\s)(\w[\w\s]+\d) time ([\d\.]+)", line))

def is_jmp_next(br, # a hacky implementation for now
  JS=2,             # short direct Jump Size
  CDLA=16):         # compiler default loops alignment
  mask = ~(CDLA - 1)
  return (br['to'] == (br['from'] + JS)) or (
         (br['to'] & mask) ==  ((br['from'] & mask) + CDLA))

def has_timing(line): return line.endswith('IPC')
def is_line_start(ip, xip): return (ip >> 6) ^ (xip >> 6) if ip and xip else False

def is_label(line):
  line = line.strip()
  return line.endswith(':') or (len(line.split()) == 1 and line.endswith(']')) or \
      (len(line.split()) > 1 and line.split()[-2].endswith(':')) or \
      (':' in line and line.split(':')[-1].isnumeric())

def get_srcline(line):
  if line.endswith(':') or line.startswith('['): return None
  if line.endswith(']'):
    label_split = line.split()[-1].split('[')
    optional = '[' + label_split[-1]
    return 'N/A (%s%s)' % (label_split[0], optional if verbose else '')
  if len(line.split()) > 1 and line.split()[-2].endswith(':'): return line.split()[-1]
  if ':' in line and line.split(':')[-1].isnumeric(): return line
  return None

def is_loop_by_ip(ip):  return ip in loops
def is_loop(line):    return is_loop_by_ip(line_ip(line))
def is_taken(line):   return '# ' in line
# FIXME: this does not work for non-contigious loops!
def is_in_loop(ip, loop): return ip >= loop and ip <= loops[loop]['back']
def get_inst(l):      return C.str2list(l)[1]
def get_loop(ip):     return loops[ip] if ip in loops else None

def get_taken_idx(sample, n):
  i = len(sample)-1
  while i >= 0:
    if is_taken(sample[i]):
      n += 1
      if n==0:
        break
    i -= 1
  return i

def get_taken(sample, n):
  assert n in range(-32, 0), 'invalid n='+str(n)
  i = get_taken_idx(sample, n)
  frm, to = -1, -1
  if i >= 0:
    frm = line_ip(sample[i], sample)
    if i < (len(sample)-1): to = line_ip(sample[i+1], sample)
  return {'from': frm, 'to': to, 'taken': 1}

def print_loop_hist(loop_ipc, name, weighted=False, sortfunc=None):
  loop = loops[loop_ipc]
  if not name in loop: return None
  d = print_hist((loop[name], name, loop, loop_ipc, sortfunc, weighted))
  if not type(d) is dict: return d
  tot = d['total']
  del d['total']
  del d['type']
  for x in d.keys(): loop['%s-%s' % (name, x)] = d[x]
  print('')
  return tot

def print_glob_hist(hist, name, weighted=False, Threshold=0.01):
  d = print_hist((hist, name, None, None, None, weighted), Threshold)
  if not type(d) is dict: return d
  if d['type'] == 'hex': d['mode'] = hex(int(d['mode']))
  del d['type']
  print('%s histogram summary: %s' % (name, hist_fmt(d)))
  return d['total']

def print_hist(hist_t, Threshold=0.01):
  if not len(hist_t[0]): return 0
  hist, name, loop, loop_ipc, sorter, weighted = hist_t[0:]
  tot = sum(hist.values())
  d = {}
  d['type'] = 'paths' if 'paths' in name else ('hex' if 'indir' in name else 'number')
  d['mode'] = str(C.hist2slist(hist)[-1][0])
  keys = [sorter(x) for x in hist.keys()] if sorter else list(hist.keys())
  if d['type'] == 'number' and numpy_imported: d['mean'] = str(round(average(keys, weights=list(hist.values())), 2))
  d['num-buckets'] = len(hist)
  if d['num-buckets'] > 1:
    C.printc('%s histogram%s:' % (name, ' of loop %s' % hex(loop_ipc) if loop_ipc else ''))
    left, threshold = 0, int(Threshold * tot)
    for k in sorted(hist.keys(), key=sorter):
      if hist[k] >= threshold and hist[k] > 1:
        bucket = ('%70s' % k) if d['type'] == 'paths' else '%5s' % (hex(k) if d['type'] == 'hex' else k)
        print('%s: %7d%6.1f%%' % (bucket, hist[k], 100.0 * hist[k] / tot))
      else: left += hist[k]
    if left: print('other: %6d%6.1f%%\t// buckets > 1, < %.1f%%' % (left, 100.0 * left / tot, 100.0 * Threshold))
  d['total'] = sum(hist[k] * int((k.split('+')[0]) if type(k) == str else k) for k in hist.keys()) if weighted else tot
  return d

def print_hist_sum(name, h):
  s = sum(hsts[h].values())
  print_stat(name, s, comment='histogram' if s else '')
def print_stat(name, count, prefix='count', comment='', ratio_of=None):
  def c(x): return x.replace(':', '-')
  def nm(x):
    if not ratio_of or ratio_of[0] != 'ALL': return x
    n = (x if 'cond' in name else x.upper()) + ' '
    if x.startswith('vec'): n += 'comp '
    if x in is_imix(None):  n += 'insts-class'
    elif 'cond' in name:    n += 'branches'
    else: n += 'instructions'
    return n
  if len(comment): comment = '\t:(see %s below)' % c(comment)
  elif ratio_of: comment = '\t: %7s of %s' % (ratio(count, ratio_of[1]), ratio_of[0])
  print('%s of %s: %10s%s' % (c(prefix), '{: >{}}'.format(c(nm(name)), 60 - len(prefix)), str(count), comment))
def print_estimate(name, s): print_stat(name, s, 'estimate')
def print_imix_stat(n, c): print_stat(n, c, ratio_of=('ALL', glob['all']))

def print_global_stats():
  def nc(x): return 'non-cold ' + x
  cycles, scl = os.getenv('PTOOLS_CYCLES'), 1e3
  if cycles:
    lbr_ratio = ratio(scl * stat['total_cycles'], int(cycles))
    print_estimate('LBR cycles coverage (x%d)' % scl, lbr_ratio)
    stat['lbr-cov'] = float(lbr_ratio.split('%')[0])
    if stat['lbr-cov'] < 3: C.warn('LBR poor coverage of overall time')
  if len(footprint): print_estimate(nc('code footprint [KB]'), '%.2f' % (len(footprint) / 16.0))
  if len(pages): print_stat(nc('code 4K-pages'), len(pages))
  print_stat(nc('loops'), len(loops), prefix='proxy count', comment='hot loops')
  for n in (4, 5, 6): print_stat(nc('%dB-unaligned loops' % 2**n), len([l for l in loops.keys() if l & (2**n-1)]),
                                 prefix='proxy count', ratio_of=('loops', len(loops)))
  if glob['size_stats_en']:
    for x in ('backward', ' forward'): print_imix_stat(x + ' taken conditional', glob['cond_' + x.strip()])
    for x in ('non-taken', 'fusible', 'non-fusible', 'taken-not-first', 
			  'LD-CMP-JCC fusible', 'CISC_CMP_IMM-JCC non-fusible'):
      print_imix_stat(x + ' conditional', glob['cond_' + x])
    for x in Insts_global: print_imix_stat(x, glob[x])
  if 'indirect-x2g' in hsts:
    print_hist_sum('indirect (call/jump) of >2GB offset', 'indirect-x2g')
    print_hist_sum('mispredicted indirect of >2GB offset', 'indirect-x2g-misp')
    for x in indirects:
      if x in hsts['indirect-x2g-misp'] and x in hsts['indirect-x2g']:
        print_stat('branch at %s' % hex(x), ratio(hsts['indirect-x2g-misp'][x], hsts['indirect-x2g'][x]),
                   prefix='misprediction-ratio', comment='paths histogram')

def print_common(total, print_summary=False):
  if glob['size_stats_en']:
    totalv = (total - stat['bad'] - stat['bogus'])
    stat['size']['avg'] = round(stat['size']['sum'] / totalv, 1) if totalv else -1
  print('LBR samples:', hist_fmt(stat))
  if edge_en and total: print_global_stats()
  print('\n'.join(['# CMP denotes CMP or TEST instructions', '#Global-stats-end', '']))
  if print_summary:
    if verbose & 0xf00: C.warn_summary()

def print_all(nloops=10, loop_ipc=0):
  total = sum(stat['IPs'].values()) if glob['ip_filter'] else stat['total']
  if not loop_ipc: print_common(total)
  if total and (stat['bad'] + stat['bogus']) / float(total) > 0.5:
    if verbose & 0x800: C.warn('Too many LBR bad/bogus samples in profile')
    else: C.error('Too many LBR bad/bogus samples in profile')
  if not loop_ipc and verbose & 0xf00: C.warn_summary()
  for x in sorted(hsts.keys()): print_glob_hist(hsts[x], x, Threshold=.03)
  sloops = sorted(loops.items(), key=lambda x: loops[x[0]]['hotness'])
  if loop_ipc:
    if loop_ipc in loops:
      lp = loops[loop_ipc]
      tot = print_loop_hist(loop_ipc, 'IPC')
      for x in paths_range(): print_loop_hist(loop_ipc, 'paths-%d'%x, sortfunc=lambda x: x[::-1])
      if glob['loop_iters']: lp['cyc/iter'] = '%.2f' % (glob['loop_cycles'] / glob['loop_iters'])
      lp['FL-cycles%'] = ratio(glob['loop_cycles'], stat['total_cycles'])
      if 'Cond_polarity' in lp and len(lp['Cond_polarity']) == 1 and lp['taken'] < 2:
        for c in lp['Cond_polarity'].keys():
          lp['%s_taken' % hex(c)] = ratio(lp['Cond_polarity'][c]['tk'], lp['Cond_polarity'][c]['tk'] + lp['Cond_polarity'][c]['nt'])
      tot = print_loop_hist(loop_ipc, 'tripcount', True, lambda x: int(x.split('+')[0]))
      if tot: lp['tripcount-coverage'] = ratio(tot, lp['hotness'])
      if hitcounts and lp['size']:
        if lp['taken'] == 0:
          C.exe_cmd('%s && echo' % C.grep('0%x' % loop_ipc, hitcounts, '-B1 -A%d' % lp['size']),
          'Hitcounts & ASM of loop %s' % hex(loop_ipc))
          if llvm_log: lp['IPC-ideal'] = llvm_mca_lbr.get_llvm(hitcounts, llvm_log, lp, hex(loop_ipc))
        else: lp['attributes'] += ';likely_non-contiguous'
      find_print_loop(loop_ipc, sloops)
    else:
      C.warn('Loop %s was not observed' % hex(loop_ipc))
  if nloops and len(loops):
    if os.getenv("LBR_LOOPS_LOG"):
      log = open(os.getenv("LBR_LOOPS_LOG"), 'w')
      num = len(loops)
      for l in sloops:
        print_loop(l[0], num, log)
        num -= 1
      log.close()
    ploops = sloops
    if len(loops) > nloops: ploops = sloops[-nloops:]
    else: nloops = len(ploops)
    C.printc('top %d loops:' % nloops)
    for l in ploops:
      print_loop(l[0], nloops)
      nloops -=  1
    if 'lbr-cov' in stat and stat['lbr-cov'] < 1: C.error('LBR poor coverage (%.2f%%) of overall time' % stat['lbr-cov'])

def print_br(br):
  print('[from: %s, to: %s, taken: %d]' % (hex(br['from']), hex(br['to']), br['taken']))

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
  if not ip in loops:
    printl('No loop was detected at %s!' % hex(ip), '\n')
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
  if glob['loop_cycles']: fixl.append('FL-cycles%')
  fixl.append('size')
  loop['hotness'] = '%6d' % loop['hotness']
  loop['size'] = str(loop['size']) if loop['size'] else '-'
  printl('%soop#%d: [ip: %s, ' % ('L' if detailed else 'l', num, hex(ip)))
  for x in fixl: printl('%s: %s, ' % (x, loop[x]))
  if not glob['loop_stats_en']: del loop['attributes']
  elif not len(loop['attributes']): loop['attributes'] = '-'
  elif ';' in loop['attributes']: loop['attributes'] = ';'.join(sorted(loop['attributes'].split(';')))
  dell = ['hotness', 'srcline', 'FL-cycles%', 'size', 'back', 'entry-block', 'IPC', 'tripcount']
  for x in paths_range(): dell += ['paths-%d'%x]
  if 'taken' in loop and loop['taken'] <= loop['Conds']: dell += ['taken']
  if not (verbose & 0x20): dell += ['Cond_polarity', 'cyc/iter'] # No support for >1 Cond. cyc/iter needs debug (e.g. 548-xm3-basln)
  for x in ('back', 'entry-block'): printl('%s: %s, ' % (x, hex(loop[x])))
  for x, y in (('inn', 'out'), ('out', 'inn')):
    if loop[x + 'er'] > 0: set2str(y + 'er-loops')
    else: dell += [y + 'er-loops']
  for x in dell:
    if x in loop: del loop[x]
  printl(C.chop(str(loop), "'{}\"") + ']', '\n')

def print_sample(sample, n=10):
  if not len(sample): return
  C.printf('\n'.join(('sample#%d size=%d' % (stat['total'], len(sample)-1), sample[0], '\n')))
  if len(sample) > 1: C.printf('\n'.join((sample[-min(n, len(sample)-1):] if n else sample) + ['\n']))
  sys.stderr.flush()

def print_header():
  C.printc('Global stats:')
  print("perf-tools' lbr.py module version %.2f" % __version__)
