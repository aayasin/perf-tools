#!/usr/bin/env python
# Copyright (c) 2020-2024, Intel Corporation
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

import common as C, pmu
from common import inc
import lbr.common_lbr as LC
import lbr.loops as loops
import lbr.funcs as funcs
import os, re, sys, time
from lbr.llvm_mca import get_llvm
from kernels import x86
try:
  from numpy import average
  numpy_imported = True
except ImportError:
  numpy_imported = False
__version__= x86.__version__ + 2.18 # see version line of do.py

llvm_log = C.envfile('LLVM_LOG')

def hist_fmt(d): return '%s%s' % (str(d).replace("'", ""), '' if 'num-buckets' in d and d['num-buckets'] == 1 else '\n')
def ratio(a, b): return C.ratio(a, b) if b else '-'
def read_line(): return sys.stdin.readline()

def skip_sample(s):
  line = read_line()
  while not re.match(r"^$", line):
    line = read_line()
    assert line, 'was input truncated? sample:\n%s'%s
  return 0

header_field = {
  'ip': 5,
  'sym': 6,
  'dso': 7,
}
def header_ip_str(line):
  x = is_header(line)
  assert x, "Not a head of sample: " + line
  #           clang 155371 [062] 1286179.977117:      70001 r20c4:ppp:      7ffff7de04c2 _dl_relocate_object+0xbc2 (/lib/x86_64-linux-gnu/ld-2.27.so)
  if 0:
    x = re.match(r'^\s+(\w+)\s(\d+)\s(\[\d+\])?\s(\d+\.\d+):\s+(\d+)\s(\S+)\s+([0-9a-f]+)', line)
    # comm pid cpu timestamp period event ip sym dso
    return x.group(header_field['ip'])
  if header_ip_str.first:
    if '[' in x.group(1): header_ip_str.position += 1
    header_ip_str.first = False
  return x.group(4) #C.str2list(line)[header_ip_str.position]
header_ip_str.first = True
header_ip_str.position = 5
def header_ip(line): return LC.str2int(header_ip_str(line), (line, None))

def header_cost(line):
  x = is_header(line)
  assert x, "Not a head of sample: " + line
  return LC.str2int(C.str2list(line.split(':')[2])[2], (line, None))

def num_valid_sample(): return LC.stat['total'] - LC.stat['bad'] - LC.stat['bogus']

def info_lines(info, lines1): C.info_p(info, '\t\n'.join(['\t'] + lines1))

LBR_Event = pmu.lbr_event()[:-4]
LBR_Edge_Events = pmu.lbr_unfiltered_events()
lbr_events = []

footprint = set()
pages = set()
indirects = set()
ips_after_uncond_jmp = set()

def inc_pair(first, second='JCC', suffix='non-fusible'):
  c = '%s-%s %s' % (first, second, suffix)
  k = 'cond_%s' % c if second == 'JCC' else c
  new = inc_stat(k)
  if new and second == 'JCC': # new JCC paired stat added
    LC.Insts_cond += [c]
  if second == 'JCC' and suffix == 'non-fusible':
    LC.glob['counted_non-fusible'] += 1
    return True
  return False

# inc/init stat, returns True when new stat is initialized
def inc_stat(stat):
  if stat in LC.glob:
    LC.glob[stat] += 1
    return False
  else:
    LC.glob[stat] = 1
    return True

IPTB  = 'inst-per-taken-br--IpTB'
IPLFC = 'inst-per-leaf-func-call'
NOLFC = 'inst-per-leaf-func-name' # name-of-leaf-func-call would plot it away from IPFLC!
IPLFCB0 = 'inst-per-%s' % LC.Insts_leaf_func[0]; IPLFCB1 = 'inst-per-%s' % LC.Insts_leaf_func[1]
FUNCI = 'Function-invocations'
FUNCP = 'Params_of_func'
FUNCR = 'Regs_by_func'
def count_of(t, lines, x, hist):
  r = 0
  while x < len(lines):
    if LC.is_type(t, lines[x]): r += 1
    x += 1
  inc(hsts[hist], r)
  return r

hsts, hsts_threshold = {}, {NOLFC: 0.01, IPLFCB0: 0, IPLFCB1: 0}
def edge_en_init(indirect_en):
  for x in (FUNCI, 'IPC', IPTB, IPLFC, NOLFC, IPLFCB0, IPLFCB1, FUNCR, FUNCP): hsts[x] = {}
  if indirect_en:
    for x in ('', '-misp'): hsts['indirect-x2g%s' % x] = {}
  if os.getenv('LBR_INDIRECTS'):
    for x in os.getenv('LBR_INDIRECTS').split(','):
      indirects.add(int(x, 16))
      hsts['indirect_%s_targets' % x] = {}
      hsts['indirect_%s_paths' % x] = {}
  if pmu.dsb_msb() and not pmu.cpu('smt-on'): hsts['dsb-heatmap'], hsts_threshold['dsb-heatmap']  = {}, 0

def edge_leaf_func_stats(lines, line): # invoked when a RET is observed
  branches, dirjmps, insts_per_call, x = 0, 0, 0, len(lines) - 1
  while x > 0:
    if LC.is_type('ret', lines[x]): break # not a leaf function call
    if LC.is_type('call', lines[x]):
      inc(hsts[IPLFC], insts_per_call)
      LC.glob['leaf-call'] += (insts_per_call + 2)
      d = 'ind' if '%' in lines[x] else 'dir'
      if branches == 0:
        if d == 'dir': inc(hsts[IPLFCB0], insts_per_call)
        LC.glob['branchless-leaf-%scall' % d] += (insts_per_call + 2)
      elif branches == dirjmps:
        if d == 'dir': inc(hsts[IPLFCB1], insts_per_call)
        LC.glob['dirjmponly-leaf-%scall' % d] += (insts_per_call + 2)
      callder_idx, ok = x, x < len(lines) - 1
      name = lines[x + 1].strip()[:-1] if ok and LC.is_label(lines[x + 1]) else 'Missing-func-name-%s' % (
        '0x' + LC.line_ip_hex(lines[x + 1]) if ok else 'unknown')
      while callder_idx > 0:
        if LC.is_label(lines[callder_idx]): break
        callder_idx -= 1
      name = ' -> '.join((lines[callder_idx].strip()[:-1] if callder_idx > 0 else '?', name))
      inc(hsts[NOLFC], name + '-%d' % insts_per_call)
      if LC.verbose & 0x10 and 'IPC' in lines[-(len(lines) - x)]:
        info_lines('call to leaf-func %s of size %d' % (name, insts_per_call), lines[-(len(lines)-x):] + [line])
      break
    elif LC.is_branch(lines[x]):
      branches += 1
      if 'jmp' in lines[x] and '%' not in lines[x]: dirjmps += 1
    if not LC.is_label(lines[x]): insts_per_call += 1
    x -= 1

def edge_stats(line, lines, xip, size):
  if LC.is_label(line): return
  # An instruction may be counted individually and/or per imix class
  for x in LC.Insts:
    if LC.is_type(x, line):
      LC.glob[x] += 1
      if x == 'lea' and LC.is_type(x86.LEA_S, line): LC.glob['lea-scaled'] += 1
  t = LC.line_inst(line)
  if t and LC.is_imix(t):
    LC.glob[t] += 1
    if t in x86.MEM_INSTS and x86.mem_type(line):
      LC.glob[x86.mem_type(line)] += 1
  ip = LC.line_ip(line, lines)
  new_line = is_line_start(ip, xip)
  if new_line:
    footprint.add(ip >> 6)
    pages.add(ip >> 12)
  # lines[-1]/lines[-2] etc w/ no labels
  def prev_line(i=-1):
    idx = 0
    while i < 0:
      idx -= 1
      while LC.is_label(lines[idx]):
        idx -= 1
      i += 1
    return lines[idx]
  xline = prev_line()
  if 'dsb-heatmap' in hsts and (LC.is_taken(xline) or new_line):
    inc(hsts['dsb-heatmap'], pmu.dsb_set_index(ip))
  if 'indirect-x2g' in hsts and LC.is_type(x86.INDIRECT, xline):
    ilen = LC.get_ilen(xline) or 2
    if abs(ip - (xip + ilen)) >= 2 ** 31:
      inc(hsts['indirect-x2g'], xip)
      if 'MISP' in xline: inc(hsts['indirect-x2g-misp'], xip)
  if xip and xip in indirects:
    inc(hsts['indirect_%s_targets' % LC.hex_ip(xip)], ip)
    #inc(hsts['indirect_%s_paths' % hex_ip(xip)], '%s.%s.%s' % (hex_ip(get_taken(lines, -2)['from']), hex_ip(xip), hex_ip(ip)))
  #MRN with IDXReg detection
  mrn_dst=x86.get("dst",line)
  # CHECK: is this RIP only (64-bit) or applies to EIP too ?!
  def mrn_cond(l):return not LC.is_type(x86.JUMP, l) and '%rip' not in l and re.search(x86.MEM_IDX, l) and not re.search("[x-z]mm", l) and not re.search("%([a-d]x|[sd]i|[bs]p|r(?:[89]|1[0-5])w)", l)
  if LC.is_type("inc-dec", line) and x86.is_memory(line) and re.search(x86.MEM_IDX, line):
    inc_stat('%s non-MRNable' % ('INC' if 'inc' in x86.get('inst',line) else 'DEC'))
  elif mrn_cond(line) and (x86.is_mem_store(line) or x86.is_mem_rmw(line)) and not re.search("%[a-d]h",mrn_dst):
    x = len(lines)-1
    while x > 0:
      if mrn_cond(lines[x]) and x86.is_mem_load(lines[x]):
        mrn_src=x86.get("srcs",lines[x])
        if mrn_src and mrn_src[0] == mrn_dst:
          inc_pair('LD','ST',suffix='non-MRNable')
          break
      x-=1 
  if LC.is_type(x86.COND_BR, xline) and LC.is_taken(xline):
    LC.glob['cond_%sward-taken' % ('for' if ip > xip else 'back')] += 1
  # checks all lines but first
  if LC.is_type(x86.COND_BR, line):
    if LC.is_taken(line): LC.glob['cond_taken-not-first'] += 1
    else: LC.glob['cond_non-taken'] += 1
    if x86.is_jcc_fusion(xline, line):
      LC.glob['cond_fusible'] += 1
      if size > 1 and LC.is_type(x86.TEST_CMP, xline) and LC.is_type(x86.LOAD, prev_line(-2)):
        inc_pair('LD-CMP', suffix='fusible')
    else:
      LC.glob['cond_non-fusible'] += 1
      if x86.is_mem_imm(xline):
        inc_pair('%s_MEM%sIDX_IMM' % ('CMP' if LC.is_type(x86.TEST_CMP, xline) else 'OTHER',
                                      '' if LC.is_type(x86.MEM_IDX, xline) else 'NO'))
      else:
        counted = False
        for x in LC.user_jcc_pair:
          if LC.is_type(x.lower(), xline):
            counted = inc_pair(x)
            break
        if counted: pass
        elif LC.is_type(x86.COND_BR, xline): counted = inc_pair('JCC')
        elif LC.is_type(x86.COMI, xline): counted = inc_pair('COMI')
        if size > 1 and x86.is_jcc_fusion(prev_line(-2), line):
          def inc_pair2(x): return inc_pair(x, suffix='non-fusible-IS')
          if LC.is_type(x86.MOV, xline): inc_pair2('MOV')
          elif re.search(r"lea\s+([\-0x]+1)\(%[a-z0-9]+\)", xline): inc_pair2('LEA-1')
  # check erratum for line (with no consideration of macro-fusion with previous line)
  if LC.is_jcc_erratum(line, None if size == 1 else xline): inc_stat('JCC-erratum')
  if LC.verbose & 0x1 and LC.is_type('ret', line): edge_leaf_func_stats(lines, line)
  if size <= 1: return # a sample with >= 2 instructions after this point
  if not x86.is_jcc_fusion(xline, line):
    x2line = prev_line(-2)
    if x86.is_ld_op_fusion(x2line, xline): inc_pair('LD', 'OP', suffix='fusible')
    elif x86.is_mov_op_fusion(x2line, xline): inc_pair('MOV', 'OP', suffix='fusible')
    if x86.is_vec_ld_op_fusion(lines[-2], lines[-1]): inc_pair('VEC LD', 'OP', suffix='fusible')
    elif x86.is_vec_mov_op_fusion(lines[-2], lines[-1]): inc_pair('VEC MOV', 'OP', suffix='fusible')
  if LC.is_type('call', xline): inc(hsts[FUNCI], ip)

def read_sample(ip_filter=None, skip_bad=True, min_lines=0, ret_latency=False,
                loop_ipc=0, lp_stats_en=False, event=LBR_Event, indirect_en=True, mispred_ip=None):
  def invalid(bad, msg):
    LC.stat[bad] += 1
    if not loop_ipc: C.warn('%s sample encountered (%s)' % (bad, msg))
  def header_only_str(l):
    dso = get_field(l, 'dso').replace('(','').replace(')','')
    return 'header-only: ' + (dso if 'kallsyms' in dso else ' '.join((get_field(l, 'sym'), dso)))
  global lbr_events
  valid, lines, loops.bwd_br_tgts = 0, [], []
  labels = LC.verbose & 0x1 and not loop_ipc
  assert LC.verbose & 0x1 or not labels, "labels argument must be False!"
  if skip_bad and not loop_ipc: LC.stats.enables |= LC.stats.SIZE
  if lp_stats_en: LC.stats.enables |= LC.stats.LOOP
  LC.glob['ip_filter'] = ip_filter
  # edge_en permits to collect per-instruction stats (beyond per-taken-based) if config is good for edge-profile
  LC.edge_en = event in LBR_Edge_Events and not ip_filter and not loop_ipc
  if LC.stat['total'] == 0:
    if LC.edge_en: edge_en_init(indirect_en)
    if ret_latency: header_ip_str.position = 8
    if LC.debug: C.printf('LBR_DBG=%s\n' % LC.debug)
    if loop_ipc:
      read_sample.tick *= 10
      read_sample.stop = None
    else:
      LC.stat['samples/s'] = time.time()

  while not valid:
    valid, lines, loops.bwd_br_tgts = 1, [], []
    # size is # instructions in sample while insts is # instruction since last taken
    insts, size, takens, xip, timestamp, srcline = 0, 0, [], None, None, None
    tc_state = 'new'
    def update_size_stats():
      if not LC.stats.size() or size<0: return
      if LC.stat['size']['sum'] == 0:
        LC.stat['size']['min'] = LC.stat['size']['max'] = size
      else:
        if LC.stat['size']['min'] > size: LC.stat['size']['min'] = size
        if LC.stat['size']['max'] < size: LC.stat['size']['max'] = size
      LC.stat['size']['sum'] += size
      inc(LC.stat['takens'], len(takens))
    LC.stat['total'] += 1
    if LC.stat['total'] % read_sample.tick == 0: C.printf('.')
    while True:
      line = read_line()
      # input ended
      if not line:
        if len(lines): invalid('bogus', 'input truncated')
        if LC.stat['total'] == LC.stat['bogus']:
          print_all()
          C.error('No LBR data in profile')
        if not loop_ipc: C.printf(' .\n')
        return lines if len(lines) > min_lines and not skip_bad else None
      header = is_header(line)
      if header:
        ev = header.group(3)[:-1]
        # first sample here (of a given event)
        if ev not in lbr_events:
          if not len(lbr_events) and '[' in header.group(1):
            for k in header_field.keys(): header_field[k] += 1
          lbr_events += [ev]
          x = 'events= %s @ %s' % (str(lbr_events), header.group(1).split(' ')[-1])
          def f2s(x): return C.flag2str(' ', C.env2str(x, prefix=True))
          if len(lbr_events) == 1: x += ' primary= %s edge=%d%s%s' % (event, LC.edge_en, f2s('LBR_STOP'), f2s('LBR_IMIX'))
          if ip_filter: x += ' ip_filter= %s' % str(ip_filter)
          if loop_ipc: x += ' loop= %s%s' % (LC.hex_ip(loop_ipc), C.flag2str(' history= ', C.env2int('LBR_PATH_HISTORY')))
          if LC.verbose: x += ' verbose= %s' % LC.hex_ip(LC.verbose)
          if not header.group(2).isdigit(): C.printf(line)
          C.printf(x+'\n')
        inc(LC.stat['events'], ev)
        func = func_srcline = None
        if LC.debug: timestamp = header.group(1).split()[-1]
      # a new sample started
      # perf  3433 1515065.348598:    1000003 EVENT.NAME:      7fd272e3b217 __regcomp+0x57 (/lib/x86_64-linux-gnu/libc-2.23.so)
        if ip_filter:
          if not C.any_in(ip_filter, line):
            valid = skip_sample(line)
            break
          inc(LC.stat['IPs'], header_ip_str(line))
      # a sample ended
      if re.match(r"^$", line):
        if not skip_bad and (not min_lines or len(lines) > min_lines): break
        len_m1 = 0
        if len(lines): len_m1 = len(lines)-1
        if len_m1 == 0 or\
           min_lines and (len_m1 < min_lines) or\
           header_ip(lines[0]) != LC.line_ip(lines[len_m1]):
          valid = 0
          if 'out of order events' in line: invalid('bogus', 'out of order events')
          else: invalid('bogus', 'too short' if len_m1 else (header_only_str(lines[0]) if len(lines) else 'no header'))
          # apparently there is a perf-script bug (seen with perf tool 6.1)
          update_size_stats()
          if LC.debug and LC.debug == timestamp:
            exit((line.strip(), len(lines)), lines, 'a bogus sample ended')
        elif len_m1 and type(tc_state) is int and loops.is_in_loop(LC.line_ip(lines[-1]), loop_ipc):
          if tc_state == 31 or (LC.verbose & 0x80):
            inc(loops.loops[loop_ipc]['tripcount'], '%d+' % (tc_state + 1))
            if loops.loop_stats_id: loops.loop_stats(None, 0, 0)
          # else: note a truncated tripcount, i.e. unknown in 1..31, is not accounted for by default.
        if mispred_ip and valid < 2: valid = 0
        if func: funcs.detect_functions(lines[func:], func_srcline)
        if LC.debug and LC.debug == timestamp:
          exit((line.strip(), len(lines)), lines, 'sample-of-interest ended')
        break
      elif header and len(lines): # sample had no LBR data; new one started
        # exchange2_r_0.j 57729 3736595.069891:    1000003 r20c4:pp:            41f47a brute_force_mp_brute_+0x43aa (/home/admin1/ayasin/perf-tools/exchange2_r_0.jmpi4)
        # exchange2_r_0.j 57729 3736595.069892:    1000003 r20c4:pp:            41fad4 brute_force_mp_brute_+0x4a04 (/home/admin1/ayasin/perf-tools/exchange2_r_0.jmpi4)
        lines = []
        invalid('bogus', 'header-only') # for this one
        LC.stat['total'] += 1 # for new one
      # invalid sample is about to end
      tag = 'not reaching sample'
      if skip_bad and tag in line:
        valid = 0
        invalid('bad', tag)
        assert re.match(r"^$", read_line())
        break
      # a line with a label
      if not labels and LC.is_label(line):
        srcline = LC.get_srcline(line.strip())
        continue
      # e.g. "        00007ffff7afc6ca        <bad>" then "mismatch of LBR data and executable"
      tag = 'mismatch of LBR data'
      if tag in line:
        valid = skip_sample(lines[0])
        invalid('bad', tag)
        break
      # e.g. "        prev_nonnote_           addb  %al, (%rax)"
      if skip_bad and len(lines) and not LC.is_label(line) and not line.strip().startswith('0'):
        if LC.debug and LC.debug == timestamp:
          exit(line, lines, "bad line")
        valid = skip_sample(lines[0])
        invalid('bogus', 'instruction address missing')
        break
      if skip_bad and len(lines) and not LC.is_label(line) and LC.is_taken(line) and not LC.is_branch(line):
        valid = skip_sample(lines[0])
        invalid('bogus', 'non-branch instruction "%s" marked as taken' % x86.get('inst', line))
        break
      if (not len(lines) and event in line) or (len(lines) and LC.is_label(line)):
        lines += [ line.rstrip('\r\n') ]
        continue
      elif not len(lines): continue
      ip = None if header or 'not reaching sample' in line else LC.line_ip(line, lines)
      if LC.is_taken(line): takens += [ip]
      if len(takens) < 2:
        # perf may return subset of LBR-sample with < 32 records
        size += 1
      elif LC.edge_en: # instructions after 1st taken is observed (none of takens/IPC/IPTB used otherwise)
        insts += 1
        if LC.is_taken(line):
          inc(hsts[IPTB], insts); size += insts; insts = 0
          if 'IPC' in line: inc(hsts['IPC'], LC.line_timing(line)[1])
      LC.glob['all'] += 1
      if not labels and size > 0:
        loops.detect_loop(ip, lines, loop_ipc, takens, srcline)
        if ip in loops.loops and 'srcline' in loops.loops[ip] and loops.loops[ip]['srcline'] == srcline:
          srcline = None  # srcline <-> loop
      if skip_bad: tc_state = loops.loop_stats(line, loop_ipc, tc_state)
      if LC.edge_en:
        if LC.glob['all'] == 1:  # 1st instruction observed
          if 'ilen:' in line: LC.stats.enables |= LC.stats.ILEN
          if LC.stats.ilen(): LC.glob['JCC-erratum'] = 0
        if len(takens) and LC.is_taken(line) and LC.verbose & 0x2: #FUNCR
          x = get_taken_idx(lines, -1)
          if x >= 0:
            if LC.is_type('call', line): count_of('st-stack', lines, x + 1, FUNCP)
            if LC.is_type('call', lines[x]): count_of('push', lines, x + 1, FUNCR)
        edge_stats(line, lines, xip, size)
      if (LC.edge_en or 'DSB_MISS' in event) and LC.is_type('jmp', line):
        ilen = LC.get_ilen(line)
        if ilen: ips_after_uncond_jmp.add(ip + ilen)
      if 'call' in line and not func:
        func = len(lines)
        func_srcline = srcline
      assert len(lines) or event in line
      line = line.rstrip('\r\n')
      if LC.has_timing(line):
        cycles = LC.line_timing(line)[0]
        LC.stat['total_cycles'] += cycles
        if LC.edge_en and loops.is_loop_line(line):
          loops.total_cycles += cycles
      if mispred_ip and LC.is_taken(line) and mispred_ip == LC.line_ip(line) and 'MISPRED' in line: valid += 1
      lines += [ line ]
      xip = ip
    if read_sample.dump: LC.print_sample(lines, read_sample.dump)
    if read_sample.stop and LC.stat['total'] >= int(read_sample.stop):
      C.info('stopping after %s valid samples' % read_sample.stop)
      print_common(LC.stat['total'])
      exit(None, lines, 'stop', msg="run:\t 'kill -9 $(pidof perf)'\t!")
  lines[0] += ' #size=%d' % size
  update_size_stats()
  return lines
read_sample.stop = os.getenv('LBR_STOP')
read_sample.tick = C.env2int('LBR_TICK', 1000)
read_sample.dump = C.env2int('LBR_DUMP', 0)

# TODO: re-design this function to return: event-name, ip, timestamp, cost, etc as a dictiorary if header or None otherwise
def is_header(line):
  def patch(x):
    if LC.debug: C.printf("\nhacking '%s' in: %s" % (x, line))
    return line.replace(x, '-', 1)
  if '\tilen:' in line: return False
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

def is_line_start(ip, xip): return (ip >> 6) ^ (xip >> 6) if ip and xip else False

def is_after_uncond_jmp(ip): return ip in ips_after_uncond_jmp

def get_field(l, f):
  try:
    return C.str2list(l)[header_field[f]]
  except:
    return l

def get_taken_idx(sample, n):
  i = len(sample)-1
  while i >= 0:
    if LC.is_taken(sample[i]):
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
    frm = LC.line_ip(sample[i], sample)
    if i < (len(sample)-1): to = LC.line_ip(sample[i + 1], sample)
  return {'from': frm, 'to': to, 'taken': 1}

def print_glob_hist(hist, name, weighted=False, threshold=.03):
  if name in hsts_threshold: threshold = hsts_threshold[name]
  d = LC.print_hist((hist, name, None, None, None, weighted), threshold)
  if not type(d) is dict: return d
  if d['type'] == 'hex': d['mode'] = LC.hex_ip(int(d['mode']))
  del d['type']
  print('%s histogram summary: %s' % (name, hist_fmt(d)))
  return d['total']

def print_hist_sum(name, h):
  s = sum(hsts[h].values())
  print_stat(name, s, comment='histogram' if s else '')

c = lambda x: x.replace(':', '-')
def stat_name(name, prefix='count', ratio_of=None):
  def nm(x):
    if not ratio_of or ratio_of[0] != 'ALL': return x
    n = (x if 'cond' in name or 'fusible' in name or 'MRN' in name else x.upper()) + ' '
    if x.startswith('vec'): n += 'comp '
    if x in LC.is_imix(None):  n += 'insts-class'
    elif x in x86.mem_type(None):  n += 'insts-subclass'
    elif 'cond' in name:    n += 'branches'
    elif 'fusible' in name or 'LD-ST' in name: n += 'pairs'
    else: n += 'instructions'
    return n
  return '%s of %s' % (c(prefix), '{: >{}}'.format(c(nm(name)), 60 - len(prefix)))
def print_stat(name, count, prefix='count', comment='', ratio_of=None, log=None):
  if len(comment): comment = '\t:(see %s below)' % c(comment)
  elif ratio_of: comment = '\t: %7s of %s' % (ratio(count, ratio_of[1]), ratio_of[0])
  res = '%s: %10s%s' % (stat_name(name, prefix=prefix, ratio_of=ratio_of), str(count), comment)
  C.fappend(res, log) if log else print(res)
def print_estimate(name, s): print_stat(name, s, 'estimate')
def print_imix_stat(n, c): print_stat(n, c, ratio_of=('ALL', LC.glob['all']))

def print_global_stats():
  def nc(x): return 'non-cold ' + x
  def print_loops_stat(n, c): print_stat(nc(n + ' loops'), c, prefix='proxy count', ratio_of=('loops', len(loops.loops)))
  cycles, scl = os.getenv('PTOOLS_CYCLES'), 1e3
  if cycles:
    lbr_ratio = ratio(scl * LC.stat['total_cycles'], int(cycles))
    print_estimate('LBR cycles coverage (x%d)' % scl, lbr_ratio)
    LC.stat['lbr-cov'] = float(lbr_ratio.split('%')[0])
    if LC.stat['lbr-cov'] < 3: C.warn('LBR poor coverage of overall time')
  if len(footprint): print_estimate(nc('code footprint [KB]'), '%.2f' % (len(footprint) / 16.0))
  if len(pages): print_stat(nc('code 4K-pages'), len(pages))
  print_stat(nc('loops'), len(loops.loops), prefix='proxy count', comment='hot loops')
  print_stat('cycles in loops', loops.total_cycles, prefix='proxy count', ratio_of=('total cycles', LC.stat['total_cycles']))
  print_stat('cycles in functions', funcs.total_cycles, prefix='proxy count', ratio_of=('total cycles', LC.stat['total_cycles']))
  for n in (4, 5, 6): print_loops_stat('%dB-unaligned' % 2 ** n, len([l for l in loops.loops.keys() if l & (2 ** n - 1)]))
  print_loops_stat('undetermined size', len([l for l in loops.loops.keys() if loops.loops[l]['size'] is None]))
  if LC.stats.ilen() : print_loops_stat('non-contiguous', len(loops.loops) - len(loops.contigous_loops))
  print_stat(nc('functions'), len(hsts[FUNCI]), prefix='proxy count', comment=FUNCI)
  if LC.stats.size():
    for x in LC.Insts_cond: print_imix_stat(x + ' conditional', LC.glob['cond_' + x])
    print_imix_stat('unaccounted non-fusible conditional', LC.glob['cond_non-fusible'] - LC.glob['counted_non-fusible'])
    if LC.stats.ilen():
      print_imix_stat('JCC-erratum conditional', LC.glob['JCC-erratum'])
      print_imix_stat('jump-into-mid-loop', sum(loops.jump_to_mid_loop.values()))
    for x in LC.Insts_Fusions: print_imix_stat(x, LC.glob[x])
    for x in LC.Insts_MRN: print_imix_stat(x, LC.glob[x])
    for x in LC.Insts_global: print_imix_stat(x, LC.glob[x])
  if 'indirect-x2g' in hsts:
    print_hist_sum('indirect (call/jump) of >2GB offset', 'indirect-x2g')
    print_hist_sum('mispredicted indirect of >2GB offset', 'indirect-x2g-misp')
    for x in indirects:
      if x in hsts['indirect-x2g-misp'] and x in hsts['indirect-x2g']:
        print_stat('a cross-2GB branch at %s' % LC.hex_ip(x), ratio(hsts['indirect-x2g-misp'][x], hsts['indirect-x2g'][x]),
                   prefix='misprediction-ratio', comment='paths histogram')

def print_common(total):
  if LC.stats.size():
    totalv = (total - LC.stat['bad'] - LC.stat['bogus'])
    LC.stat['size']['avg'] = round(LC.stat['size']['sum'] / totalv, 1) if totalv else -1
  LC.stat['samples/s'] = round(total / (time.time() - LC.stat['samples/s']), 1)
  print('LBR samples:', hist_fmt(LC.stat))
  if LC.edge_en and total:
    print_global_stats()
    print("""# Notes: CMP = CMP or TEST instructions.
# RMW = Read-Modify-Write instructions.
# GLOBAL denotes Global or static memory references.
#Global-stats-end\n""")
  C.warn_summary('info', 50)
  C.warn_summary()

def print_all(nloops=10, loop_ipc=0):
  total = sum(LC.stat['IPs'].values()) if LC.glob['ip_filter'] else LC.stat['total']
  if not loop_ipc: print_common(total)
  if total and (LC.stat['bad'] + LC.stat['bogus']) / float(total) > 0.5:
    if LC.verbose & 0x800: C.warn('Too many LBR bad/bogus samples in profile')
    else: C.error('Too many LBR bad/bogus samples in profile')
  for x in sorted(hsts.keys()): print_glob_hist(hsts[x], x)
  sloops = sorted(loops.loops.items(), key=lambda x: loops.loops[x[0]]['hotness'])
  if loop_ipc:
    if loop_ipc in loops.loops:
      lp = loops.loops[loop_ipc]
      tot = loops.print_loop_hist(loop_ipc, 'IPC')
      for x in LC.paths_range(): loops.print_loop_hist(loop_ipc, 'paths-%d' % x, sortfunc=lambda x: x[::-1])
      if LC.glob['loop_iters']: lp['cyc/iter'] = '%.2f' % (LC.glob['loop_cycles'] / LC.glob['loop_iters'])
      lp['FL-cycles%'] = ratio(LC.glob['loop_cycles'], LC.stat['total_cycles'])
      if 'Cond_polarity' in lp and len(lp['Cond_polarity']) == 1:
        for c in lp['Cond_polarity'].keys():
          lp['%s_taken' % LC.hex_ip(c)] = ratio(lp['Cond_polarity'][c]['tk'], lp['Cond_polarity'][c]['tk'] + lp['Cond_polarity'][c]['nt'])
      tot = loops.print_loop_hist(loop_ipc, 'tripcount', True, lambda x: int(x.split('+')[0]))
      if tot: lp['tripcount-coverage'] = ratio(tot, lp['hotness'])
      if LC.hitcounts:
        if lp['size']:
          C.exe_cmd('%s && echo' % C.grep('0%x' % loop_ipc, LC.hitcounts, '-B1 -A%d' % lp['size'] if LC.verbose & 0x40 else '-A%d' % (lp['size'] - 1)),
            'Hitcounts & ASM of loop %s' % LC.hex_ip(loop_ipc))
          if llvm_log: lp['IPC-ideal'] = get_llvm(LC.hitcounts, llvm_log, lp, LC.hex_ip(loop_ipc))
        else:
          if LC.debug: C.exe_cmd('%s && echo' % C.grep('0%x' % loop_ipc, LC.hitcounts), 'Headline of loop %s' % LC.hex_ip(loop_ipc))
          lp['attributes'] += ';likely_non-contiguous'
      loops.find_print_loop(loop_ipc, sloops)
    else:
      C.warn('Loop %s was not observed' % LC.hex_ip(loop_ipc))
  if nloops and len(loops.loops):
    if os.getenv("LBR_LOOPS_LOG"):
      log = open(os.getenv("LBR_LOOPS_LOG"), 'w')
      num = len(loops.loops)
      for l in sloops:
        loops.print_loop(l[0], num, log)
        num -= 1
      log.close()
    ploops = sloops
    if len(loops.loops) > nloops: ploops = sloops[-nloops:]
    else: nloops = len(ploops)
    C.printc('top %d loops:' % nloops)
    for l in ploops:
      loops.print_loop(l[0], nloops)
      nloops -=  1
    if 'lbr-cov' in LC.stat and LC.stat['lbr-cov'] < 1: C.error('LBR poor coverage (%.2f%%) of overall time' % LC.stat['lbr-cov'])
  # print functions
  if not loop_ipc:
    funcs_list = sorted(funcs.funcs, reverse=True)
    nfuncs = min(len(funcs_list), 10)
    if nfuncs:
      if os.getenv("LBR_FUNCS_LOG"):
        log = open(os.getenv("LBR_FUNCS_LOG"), 'w')
        for i in range(len(funcs_list) - nfuncs):
          print('Function#%d:' % (len(funcs_list) - i), funcs_list[i].__str__(detailed=True), file=log)
      C.printc('top %d functions:' % nfuncs)
      for i in range(nfuncs):
        print('function#%d:' % (nfuncs - i), funcs_list[len(funcs_list) - nfuncs + i])
        print('Function#%d:' % (nfuncs - i), funcs_list[len(funcs_list) - nfuncs + i].__str__(detailed=True), file=log)

def print_br(br):
  print('[from: %s, to: %s, taken: %d]' % (LC.hex_ip(br['from']), LC.hex_ip(br['to']), br['taken']))

def print_header():
  C.printc('Global stats:')
  print("perf-tools' lbr.py module version %.2f" % __version__)
