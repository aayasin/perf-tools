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
import os, re, sys
import llvm_mca_lbr
from kernels import x86
try:
  from numpy import average
  numpy_imported = True
except ImportError:
  numpy_imported = False
__version__= x86.__version__ + 2.11 # see version line of do.py

def INT_VEC(i): return r"\s%sp.*%s" % ('(v)?' if i == 0 else 'v', vec_reg(i))

hitcounts = C.envfile('PTOOLS_HITS')
llvm_log = C.envfile('LLVM_LOG')
debug = os.getenv('LBR_DBG')
verbose = C.env2int('LBR_VERBOSE', base=16) # nibble 0: stats, 1: extra info, 2: warnings
use_cands = os.getenv('LBR_USE_CANDS')
user_imix = C.env2list('LBR_IMIX', ['vpmovmskb', 'imul'])
user_loop_imix = C.env2list('LBR_LOOP_IMIX', ['zcnt'])
user_jcc_pair = C.env2list('LBR_JCC_PAIR', ['JZ', 'JNZ'])

def hex_ip(ip): return '0x%x' % ip if ip > 0 else '-'
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
def header_ip(line): return str2int(header_ip_str(line), (line, None))

def header_cost(line):
  x = is_header(line)
  assert x, "Not a head of sample: " + line
  return str2int(C.str2list(line.split(':')[2])[2], (line, None))

def line_ip_hex(line):
  if is_label(line): return None
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

def is_loop_line(line):
  ip = line_ip(line)
  for loop_ipc in loops:
    if loop_ipc <= ip <= loops[loop_ipc]['back']: return True
  return False

def num_valid_sample(): return stat['total'] - stat['bad'] - stat['bogus']

vec_size = 3 if pmu.cpu_has_feature('avx512vl') else 2
def vec_reg(i): return '%%%smm' % chr(ord('x') + i)
def vec_len(i, t='int'): return 'vec%d-%s' % (128 * (2 ** i), t)
IMIX_CLASS = x86.MEM_INSTS + ['mem_indir-branch', 'nonmem-branch']
def line_inst(line):
  pInsts = ['cmov', 'pause', 'pdep', 'pext', 'popcnt', 'pop', 'push', 'vzeroupper'] + user_loop_imix
  allInsts = ['nop', 'lea', 'cisc-test'] + IMIX_CLASS + pInsts
  if not line: return allInsts
  if 'nop' in line: return 'nop'
  if '(' in line:  # load/store take priority in CISC insts
    if 'lea' in line: return 'lea'
    if is_branch(line): return 'mem_indir-branch'
    return x86.get_mem_inst(line)
  if is_branch(line): return 'nonmem-branch'
  for x in pInsts: # skip non-vector p/v-prefixed insts
    if x in line: return x
  r = re.match(r"\s+\S+\s+(\S+)", line)
  if not r: pass
  elif re.match(r"^(and|or|xor|not)", r.group(1)): return 'logic'
  elif re.match(r"^[pv]", r.group(1)):
    for i in range(vec_size):
      if re.findall(INT_VEC(i), line): return vec_len(i)
    warn(0x400, 'vec-int: ' + ' '.join(line.split()[1:]))
    return 'vecX-int'
  return None

jump_to_mid_loop = {}
def detect_jump_to_mid_loop(ip, xip):
  if xip in jump_to_mid_loop:
    jump_to_mid_loop[xip] += 1
    return
  for l in contigous_loops:
    if ip != l and is_in_loop(ip, l) and not is_in_loop(xip, l):
      jump_to_mid_loop[xip] = 1
      break

def info_lines(info, lines1): C.info_p(info, '\t\n'.join(['\t'] + lines1))

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

def loop_stats(line, loop_ipc, tc_state):
  def mark(regex, tag):
    if re.findall(regex, line):
      if not loop_stats.atts or tag not in loop_stats.atts:
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
  #if (stats.loops() == 'No' or
  #  (stats.loops() == 'One' and line_ip(line) != loop_ipc and tc_state == 'new')):
  #  #not (is_loop(line) or (type(tcstate) == int)))):
  #  return tc_state
  #elif tc_state == 'new' and is_loop(line):
  if stats.loop() and tc_state == 'new' and is_loop(line):
    loop_stats.id = line_ip(line)
    loop_stats.atts = ''
  if loop_stats.id:
    if not is_in_loop(line_ip(line), loop_stats.id): # just exited a loop
      loop_stats(None, 0, 0)
    else:
      mark(x86.INDIRECT, 'indirect')
      mark(x86.IMUL, 'scalar-int')
      if get_inst(line).startswith('vp'): pass
      else: mark(r"[^k]s%s\s[\sa-z0-9,\(\)%%]+mm" % x86.FP_SUFFIX, 'scalar-fp')
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
  global bwd_br_tgts, loop_cands, contigous_loops # unlike nonlocal, global works in python2 too!
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
    assert ip == loop_ipc
    if 'IPC' not in loop: loop['IPC'] = {}
    for x in paths_range():
      if 'paths-%d' % x not in loop: loop['paths-%d' % x] = {}
      inc(loop['paths-%d' % x], ';'.join([hex_ip(a) for a in lbr_takens[-x:]]))
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
  def ilen_on(): return 'ilen:' in lines[-1]
  def indirect_jmp_enter(): return 'jmp' in lines[-1] and is_type(x86.INDIRECT, lines[-1])

  if ip in loops:
    loop = loops[ip]
    loop['hotness'] += 1
    if srcline and not 'srcline' in loop: loop['srcline'] = srcline
    if is_taken(lines[-1]):
      if indirect_jmp_enter() and 'entered_by_indirect' not in loop['attributes']:
        loop['attributes'] += ';entered_by_indirect'
      if ip == loop_ipc and line_ip(lines[-1]) == loop['back']: iter_update()
    elif not loop['entry-block']:
      loop['entry-block'] = find_block_ip()[0]
    # Try to fill size & attributes for already detected loops
    if not loop['size'] and not loop['outer'] and len(lines)>2 and line_ip(lines[-1]) == loop['back']:
      size, cnt, conds, op_jcc_mf, mov_op_mf, ld_op_mf, erratum = 1, {}, [], 0, 0, 0, 0 if ilen_on() else None
      types = ['lea', 'cmov'] + x86.MEM_INSTS + user_loop_imix
      for i in types: cnt[i] = 0
      x = len(lines)-2
      while x >= 1:
        size += 1
        inst_ip = line_ip(lines[x])
        if is_taken(lines[x]):
          break # do not fill loop size/etc unless all in-body branches are non-takens
        if is_type(x86.COND_BR, lines[x]): conds += [inst_ip]
        if x86.is_jcc_fusion(lines[x], lines[x + 1]): op_jcc_mf += 1
        elif x == len(lines) - 2 or not x86.is_jcc_fusion(lines[x + 1], lines[x + 2]):
          if x86.is_ld_op_fusion(lines[x], lines[x + 1]): ld_op_mf += 1
          elif x86.is_mov_op_fusion(lines[x], lines[x + 1]): mov_op_mf += 1
        # erratum feature disabled if erratum is None, otherwise erratum counts feature cases
        if erratum is not None and is_jcc_erratum(lines[x+1], lines[x]): erratum += 1
        t = line_inst(lines[x])
        if t and t in types: cnt[t] += 1
        if inst_ip == ip:
          loop['size'], loop['Conds'], loop['op-jcc-mf'], loop['mov-op-mf'], loop['ld-op-mf'] = (size,
            len(conds), op_jcc_mf, mov_op_mf, ld_op_mf)
          if erratum is not None: loop['jcc-erratum'] = erratum
          for i in types: loop[i] = cnt[i]
          hexa = lambda x: hex(x)[2:]
          loop['imix-ID'] = hexa(loop['load']) + hexa(loop['store']) + hexa(loop['Conds']) + hexa(loop['lea'])
          if len(conds):
            loop['Cond_polarity'] = {}
            for c in conds: loop['Cond_polarity'][c] = {'tk': 0, 'nt': 0}
          break
        elif inst_ip < ip or inst_ip > loop['back']:
          break
        x -= 1
    return
  
  # only simple loops, of these attributes, are supported:
  # * loop-body is entirely observed in a single sample
  # * a tripcount > 1 is observed
  # * no function calls
  if is_taken(lines[-1]):
    xip = line_ip(lines[-1])
    if ilen_on(): detect_jump_to_mid_loop(ip, xip)
    if xip <= ip: pass # not a backward jump
    elif is_callret(lines[-1]): pass # requires --xed
    elif (xip - ip) >= MOLD: warn(0x200, "too large distance in:\t%s" % lines[-1].split('#')[0].strip())
    elif (use_cands and ip in loop_cands) or (not use_cands and ip in bwd_br_tgts):
      if use_cands: loop_cands.remove(ip)
      else: bwd_br_tgts.remove(ip)
      inner, outer = 0, 0
      ins, outs = set(), set()
      for l in loops:
        if ip > l and xip < loops[l]['back']:
          inner += 1
          outs.add(hex_ip(l))
          loops[l]['outer'] = 1
          loops[l]['inner-loops'].add(hex_ip(ip))
        if ip < l and xip > loops[l]['back']:
          outer = 1
          ins.add(hex_ip(l))
          loops[l]['inner'] += 1
          loops[l]['outer-loops'].add(hex_ip(ip))
      loops[ip] = {'back': xip, 'hotness': 1, 'size': None, 'imix-ID': None,
        'attributes': ';entered_by_indirect' if indirect_jmp_enter() else '',
        'entry-block': 0 if xip > ip else find_block_ip()[0], #'BK': {hex(xip): 1, },
        'inner': inner, 'outer': outer, 'inner-loops': ins, 'outer-loops': outs
      }
      if srcline: loops[ip]['srcline'] = srcline.replace(':', ';')
      ilen = get_ilen(lines[-1])
      if ilen:
        loops[ip]['sizeIB'] = int(xip) - ip + ilen # size In Bytes
        if (ip + loops[ip]['sizeIB'] - ilen) == int(xip): contigous_loops += [ip]
      return
    elif use_cands and len(lines) > 2 and ip in bwd_br_tgts and has_ip(len(lines)-2):
      bwd_br_tgts.remove(ip)
      loop_cands += [ip]
    elif ip not in bwd_br_tgts and (use_cands or has_ip(len(lines)-2)):
      bwd_br_tgts += [ip]

edge_en = 0
LBR_Event = pmu.lbr_event()[:-4]
lbr_events = []
loops, contigous_loops = {}, []
stat = {x: 0 for x in ('bad', 'bogus', 'total', 'total_cycles', 'total_loops_cycles')}
for x in ('IPs', 'events', 'takens'): stat[x] = {}
stat['size'] = {'min': 0, 'max': 0, 'avg': 0, 'sum': 0}

def inst2pred(i):
  i2p = {'st-stack':  r'mov\S*\s+[^\(\),]+, [0-9a-fx\-]*\(%.sp',
    'st-reg-stack':   r'mov\S*\s+%[^\(\),]+, [0-9a-fx\-]*\(%.sp',
    'add-sub':        '(add|sub).*',
    'inc-dec':        '(inc|dec).*',
    '_cisc-cmp':      x86.CISC_CMP,
    '_risc-cmp':      r'(cmp[^x]|test)[^\(]*',
    'nop':            '.*nop.*',
  }
  if i is None:
    del i2p['st-stack']
    return sorted(list(i2p.keys()))
  return i2p[i] if i in i2p else i

# determine what is counted globally
def is_imix(t):
  # TODO: cover FP vector too
  IMIX_LIST = IMIX_CLASS + ['logic']
  if not t: return IMIX_LIST + [vec_len(x) for x in range(vec_size)] + ['vecX-int']
  return t in IMIX_LIST or t.startswith('vec')
Insts = inst2pred(None) + ['cmov', 'lea', 'lea-scaled', 'jmp', 'call', 'ret', 'push', 'pop', 'vzeroupper'] + user_imix
Insts_leaf_func = ['-'.join([x, 'leaf', y]) for y in ('dircall', 'indcall') for x in ('branchless', 'dirjmponly')] + ['leaf-call']
Insts_global = Insts + is_imix(None) + x86.mem_type() + Insts_leaf_func + ['all']
Insts_cond = ['backward-taken', 'forward-taken', 'non-taken', 'fusible', 'non-fusible', 'taken-not-first'
              ] + ['%s-JCC non-fusible'%x for x in user_jcc_pair]
Insts_Fusions = [x + '-OP fusible' for x in ['MOV', 'LD']] 
Insts_MRN = ['%s non-MRNable'%x for x in ['INC','DEC','LD-ST']]
Insts_all = ['cond_%s'%x for x in Insts_cond] + Insts_Fusions + Insts_MRN + Insts_global

glob = {x: 0 for x in ['loop_cycles', 'loop_iters', 'counted_non-fusible'] + Insts_all}
footprint = set()
pages = set()
indirects = set()
ips_after_uncond_jmp = set()

class stats:
  SIZE, LOOP, ILEN = (2**i for i in range(3))
  enables = 0
  @staticmethod
  def ilen(): return stats.enables & stats.ILEN
  @staticmethod
  def loop(): return stats.enables & stats.LOOP
  @staticmethod
  def size(): return stats.enables & stats.SIZE

def inc_pair(first, second='JCC', suffix='non-fusible'):
  c = '%s-%s %s' % (first, second, suffix)
  k = 'cond_%s' % c if second == 'JCC' else c
  new = inc_stat(k)
  if new and second == 'JCC': # new JCC paired stat added
    global Insts_cond
    Insts_cond += [c]
  if second == 'JCC' and suffix == 'non-fusible':
    glob['counted_non-fusible'] += 1
    return True
  return False

# inc/init stat, returns True when new stat is initialized
def inc_stat(stat):
  if stat in glob:
    glob[stat] += 1
    return False
  else:
    glob[stat] = 1
    return True

IPTB  = 'inst-per-taken-br--IpTB'
IPLFC = 'inst-per-leaf-func-call'
NOLFC = 'inst-per-leaf-func-name' # name-of-leaf-func-call would plot it away from IPFLC!
IPLFCB0 = 'inst-per-%s' % Insts_leaf_func[0]; IPLFCB1 = 'inst-per-%s' % Insts_leaf_func[1]
FUNCI = 'Function-invocations'
FUNCP = 'Params_of_func'
FUNCR = 'Regs_by_func'
def count_of(t, lines, x, hist):
  r = 0
  while x < len(lines):
    if is_type(t, lines[x]): r += 1
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
    if is_type('ret', lines[x]): break # not a leaf function call
    if is_type('call', lines[x]):
      inc(hsts[IPLFC], insts_per_call)
      glob['leaf-call'] += (insts_per_call + 2)
      d = 'ind' if '%' in lines[x] else 'dir'
      if branches == 0:
        if d == 'dir': inc(hsts[IPLFCB0], insts_per_call)
        glob['branchless-leaf-%scall' % d] += (insts_per_call + 2)
      elif branches == dirjmps:
        if d == 'dir': inc(hsts[IPLFCB1], insts_per_call)
        glob['dirjmponly-leaf-%scall' % d] += (insts_per_call + 2)
      callder_idx, ok = x, x < len(lines) - 1
      name = lines[x + 1].strip()[:-1] if ok and is_label(lines[x + 1]) else 'Missing-func-name-%s' % (
        '0x'+line_ip_hex(lines[x + 1]) if ok else 'unknown')
      while callder_idx > 0:
        if is_label(lines[callder_idx]): break
        callder_idx -= 1
      name = ' -> '.join((lines[callder_idx].strip()[:-1] if callder_idx > 0 else '?', name))
      inc(hsts[NOLFC], name + '-%d' % insts_per_call)
      if verbose & 0x10:
        info_lines('call to leaf-func %s of size %d' % (name, insts_per_call), lines[-(len(lines)-x):] + [line])
      break
    elif is_branch(lines[x]):
      branches += 1
      if 'jmp' in lines[x] and '%' not in lines[x]: dirjmps += 1
    if not is_label(lines[x]): insts_per_call += 1
    x -= 1

def edge_stats(line, lines, xip, size):
  if is_label(line): return
  # An instruction may be counted individually and/or per imix class
  for x in Insts:
    if is_type(x, line):
      glob[x] += 1
      if x == 'lea' and is_type(x86.LEA_S, line): glob['lea-scaled'] += 1
  t = line_inst(line)
  if t and is_imix(t):
    glob[t] += 1
    if t in x86.MEM_INSTS and x86.mem_type(line):
      glob[x86.mem_type(line)] += 1
  ip = line_ip(line, lines)
  new_line = is_line_start(ip, xip)
  if new_line:
    footprint.add(ip >> 6)
    pages.add(ip >> 12)
  # lines[-1]/lines[-2] etc w/ no labels
  def prev_line(i=-1):
    idx = 0
    while i < 0:
      idx -= 1
      while is_label(lines[idx]):
        idx -= 1
      i += 1
    return lines[idx]
  xline = prev_line()
  if 'dsb-heatmap' in hsts and (is_taken(xline) or new_line):
    inc(hsts['dsb-heatmap'], pmu.dsb_set_index(ip))
  if 'indirect-x2g' in hsts and is_type(x86.INDIRECT, xline):
    ilen = get_ilen(xline) or 2
    if abs(ip - (xip + ilen)) >= 2 ** 31:
      inc(hsts['indirect-x2g'], xip)
      if 'MISP' in xline: inc(hsts['indirect-x2g-misp'], xip)
  if xip in indirects:
    inc(hsts['indirect_%s_targets' % hex_ip(xip)], ip)
    inc(hsts['indirect_%s_paths' % hex_ip(xip)], '%s.%s.%s' % (hex_ip(get_taken(lines, -2)['from']), hex_ip(xip), hex_ip(ip)))
  #MRN with IDXReg detection
  mrn_dst=x86.get("dst",line)
  def mrn_cond(l):return not is_type(x86.JUMP,l) and '%rip' not in l and re.search(x86.MEM_IDX,l)and not re.search("[x-z]mm",l) and not re.search("%([a-d]x|[sd]i|[bs]p|r(?:[89]|1[0-5])w)",l)
  if is_type("inc-dec",line) and x86.is_memory(line) and re.search(x86.MEM_IDX,line):
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
  if is_type(x86.COND_BR, xline) and is_taken(xline):
    glob['cond_%sward-taken' % ('for' if ip > xip else 'back')] += 1
  # checks all lines but first
  if is_type(x86.COND_BR, line):
    if is_taken(line): glob['cond_taken-not-first'] += 1
    else: glob['cond_non-taken'] += 1
    if x86.is_jcc_fusion(xline, line):
      glob['cond_fusible'] += 1
      if size > 1 and is_type(x86.TEST_CMP, xline) and is_type(x86.LOAD, prev_line(-2)):
        inc_pair('LD-CMP', suffix='fusible')
    else:
      glob['cond_non-fusible'] += 1
      if x86.is_mem_imm(xline):
        inc_pair('%s_MEM%sIDX_IMM' % ('CMP' if is_type(x86.TEST_CMP, xline) else 'OTHER',
                                      '' if is_type(x86.MEM_IDX, xline) else 'NO'))
      else:
        counted = False
        for x in user_jcc_pair:
          if is_type(x.lower(), xline):
            counted = inc_pair(x)
            break
        if counted: pass
        elif is_type(x86.COND_BR, xline): counted = inc_pair('JCC')
        elif is_type(x86.COMI, xline): counted = inc_pair('COMI')
        if size > 1 and x86.is_jcc_fusion(prev_line(-2), line):
          def inc_pair2(x): return inc_pair(x, suffix='non-fusible-IS')
          if is_type(x86.MOV, xline): inc_pair2('MOV')
          elif re.search(r"lea\s+([\-0x]+1)\(%[a-z0-9]+\)", xline): inc_pair2('LEA-1')
  # check erratum for line (with no consideration of macro-fusion with previous line)
  if is_jcc_erratum(line, None if size == 1 else xline): inc_stat('JCC-erratum')
  if verbose & 0x1 and is_type('ret', line): edge_leaf_func_stats(lines, line)
  if size <= 1: return # a sample with >= 2 instructions after this point
  if not x86.is_jcc_fusion(xline, line):
    x2line = prev_line(-2)
    if x86.is_ld_op_fusion(x2line, xline): inc_pair('LD', 'OP', suffix='fusible')
    elif x86.is_mov_op_fusion(x2line, xline): inc_pair('MOV', 'OP', suffix='fusible')
  if is_type('call', xline): inc(hsts[FUNCI], ip)

def read_sample(ip_filter=None, skip_bad=True, min_lines=0, labels=False, ret_latency=False,
                loop_ipc=0, lp_stats_en=False, event=LBR_Event, indirect_en=True, mispred_ip=None):
  def invalid(bad, msg):
    stat[bad] += 1
    if not loop_ipc: C.warn('%s sample encountered (%s)' % (bad, msg))
  def header_only_str(l):
    dso = get_field(l, 'dso').replace('(','').replace(')','')
    return 'header-only: ' + (dso if 'kallsyms' in dso else ' '.join((get_field(l, 'sym'), dso)))
  global lbr_events, bwd_br_tgts, edge_en
  valid, lines, bwd_br_tgts = 0, [], []
  labels = verbose & 0x1 and not loop_ipc
  assert verbose & 0x1 or not labels, "labels argument must be False!"
  if skip_bad and not loop_ipc: stats.enables |= stats.SIZE
  if lp_stats_en: stats.enables |= stats.LOOP
  glob['ip_filter'] = ip_filter
  # edge_en permits to collect per-instruction stats (beyond per-taken-based) if config is good for edge-profile
  edge_en = event in pmu.lbr_unfiltered_events() and not ip_filter and not loop_ipc
  if stat['total'] == 0:
    if edge_en: edge_en_init(indirect_en)
    if ret_latency: header_ip_str.position = 8
    if debug: C.printf('LBR_DBG=%s\n' % debug)
    if loop_ipc:
      read_sample.tick *= 10
      read_sample.stop = None

  while not valid:
    valid, lines, bwd_br_tgts = 1, [], []
    # size is # instructions in sample while insts is # instruction since last taken
    insts, size, takens, xip, timestamp, srcline = 0, 0, [], None, None, None
    tc_state = 'new'
    def update_size_stats():
      if not stats.size() or size<0: return
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
        ev = header.group(3)[:-1]
        # first sample here (of a given event)
        if ev not in lbr_events:
          if not len(lbr_events) and '[' in header.group(1):
            for k in header_field.keys(): header_field[k] += 1
          lbr_events += [ev]
          x = 'events= %s @ %s' % (str(lbr_events), header.group(1).split(' ')[-1])
          def f2s(x): return C.flag2str(' ', C.env2str(x, prefix=True))
          if len(lbr_events) == 1: x += ' primary= %s edge=%d%s%s' % (event, edge_en, f2s('LBR_STOP'), f2s('LBR_IMIX'))
          if ip_filter: x += ' ip_filter= %s' % str(ip_filter)
          if loop_ipc: x += ' loop= %s%s' % (hex_ip(loop_ipc), C.flag2str(' history= ', C.env2int('LBR_PATH_HISTORY')))
          if verbose: x += ' verbose= %s' % hex_ip(verbose)
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
          if 'out of order events' in line: invalid('bogus', 'out of order events')
          else: invalid('bogus', 'too short' if len_m1 else (header_only_str(lines[0]) if len(lines) else 'no header'))
          # apparently there is a perf-script bug (seen with perf tool 6.1)
          update_size_stats()
          if debug and debug == timestamp:
            exit((line.strip(), len(lines)), lines, 'a bogus sample ended')
        elif len_m1 and type(tc_state) is int and is_in_loop(line_ip(lines[-1]), loop_ipc):
          if tc_state == 31 or (verbose & 0x80):
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
      if skip_bad and len(lines) and not is_label(line) and not line.strip().startswith('0'):
        if debug and debug == timestamp:
          exit(line, lines, "bad line")
        valid = skip_sample(lines[0])
        invalid('bogus', 'instruction address missing')
        break
      if skip_bad and len(lines) and not is_label(line) and is_taken(line) and not is_branch(line):
        valid = skip_sample(lines[0])
        invalid('bogus', 'non-branch instruction "%s" marked as taken' % get_inst(line))
        break
      if (not len(lines) and event in line) or (len(lines) and is_label(line)):
        lines += [ line.rstrip('\r\n') ]
        continue
      elif not len(lines): continue
      ip = None if header or 'not reaching sample' in line else line_ip(line, lines)
      if is_taken(line): takens += [ip]
      if len(takens) < 2:
        # perf may return subset of LBR-sample with < 32 records
        size += 1
      elif edge_en: # instructions after 1st taken is observed (none of takens/IPC/IPTB used otherwise)
        insts += 1
        if is_taken(line):
          inc(hsts[IPTB], insts); size += insts; insts = 0
          if 'IPC' in line: inc(hsts['IPC'], line_timing(line)[1])
      glob['all'] += 1
      if not labels and size > 0:
        detect_loop(ip, lines, loop_ipc, takens, srcline)
        if ip in loops and 'srcline' in loops[ip] and loops[ip]['srcline'] == srcline:
          srcline = None  # srcline <-> loop
      if skip_bad: tc_state = loop_stats(line, loop_ipc, tc_state)
      if edge_en:
        if glob['all'] == 1:  # 1st instruction observed
          if 'ilen:' in line: stats.enables |= stats.ILEN
          if stats.ilen(): glob['JCC-erratum'] = 0
        if len(takens) and is_taken(line) and verbose & 0x2: #FUNCR
          x = get_taken_idx(lines, -1)
          if x >= 0:
            if is_type('call', line): count_of('st-stack', lines, x+1, FUNCP)
            if is_type('call', lines[x]): count_of('push', lines, x+1, FUNCR)
        edge_stats(line, lines, xip, size)
      if (edge_en or 'DSB_MISS' in event) and is_type('jmp', line):
        ilen = get_ilen(line)
        if ilen: ips_after_uncond_jmp.add(ip + ilen)
      assert len(lines) or event in line
      line = line.rstrip('\r\n')
      if has_timing(line):
        cycles = line_timing(line)[0]
        stat['total_cycles'] += cycles
        if edge_en and is_loop_line(line):
          stat['total_loops_cycles'] += cycles
      if mispred_ip and is_taken(line) and mispred_ip == line_ip(line) and 'MISPRED' in line: valid += 1
      lines += [ line ]
      xip = ip
    if read_sample.dump: print_sample(lines, read_sample.dump)
    if read_sample.stop and stat['total'] >= int(read_sample.stop):
      C.info('stopping after %s valid samples' % read_sample.stop)
      print_common(stat['total'])
      exit(None, lines, 'stop', msg="run:\t 'kill -9 $(pidof perf)'\t!")
  lines[0] += ' #size=%d' % size
  update_size_stats()
  return lines
read_sample.stop = os.getenv('LBR_STOP')
read_sample.tick = C.env2int('LBR_TICK', 1000)
read_sample.dump = C.env2int('LBR_DUMP', 0)


def is_type(t, l):    return x86.is_type(inst2pred(t), l)
def is_callret(l):    return is_type(x86.CALL_RET, l)
def is_branch(l):     return is_type(x86.JUMP, l)

# TODO: re-design this function to return: event-name, ip, timestamp, cost, etc as a dictiorary if header or None otherwise
def is_header(line):
  def patch(x):
    if debug: C.printf("\nhacking '%s' in: %s" % (x, line))
    return line.replace(x, '-', 1)
  if 'ilen:' in line: return False
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

def is_after_uncond_jmp(ip): return ip in ips_after_uncond_jmp

def is_jcc_erratum(line, previous=None):
  length = get_ilen(line)
  if not length: return False
  # JCC/CALL/RET/JMP
  if not is_type(x86.COND_BR, line) and not is_type(x86.CALL_RET, line) and not is_type(x86.JMP_RET, line): return False
  ip = line_ip(line)
  if previous and x86.is_jcc_fusion(previous, line):
    ip = line_ip(previous)
    length += get_ilen(previous)
  next_ip = ip + length
  return not ip >> 5 == next_ip >> 5

def is_label(line):
  line = line.strip()
  if 'ilen:' in line: return False
  return line.endswith(':') or (len(line.split()) == 1 and line.endswith(']')) or \
      (len(line.split()) > 1 and line.split()[-2].endswith(':')) or \
      (':' in line and line.split(':')[-1].isdigit())

def get_ilen(line):
  ilen = re.search(r"ilen:\s+(\d+)", line)
  return int(ilen.group(1)) if ilen else None

def get_srcline(line):
  if line.endswith(':') or line.startswith('['): return None
  if line.endswith(']'):
    label_split = line.split()[-1].split('[')
    optional = '[' + label_split[-1]
    return 'N/A (%s%s)' % (label_split[0], optional if verbose else '')
  if len(line.split()) > 1 and line.split()[-2].endswith(':'): return line.split()[-1]
  if ':' in line and line.split(':')[-1].isdigit(): return line
  return None

def is_loop_by_ip(ip):  return ip in loops
def is_loop(line):    return is_loop_by_ip(line_ip(line))
def is_taken(line):   return '# ' in line
# FIXME: this does not work for non-contigious loops!
def is_in_loop(ip, loop): return loop <= ip <= loops[loop]['back']
def get_inst(l):      return C.str2list(l)[1]
def get_loop(ip):     return loops[ip] if ip in loops else None
def get_field(l, f):
  try:
    return C.str2list(l)[header_field[f]]
  except:
    return l

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

# tripcount-mean stat calculation for loops with tripcount-mode 32+
# supports only loops with size attribute
# no support for non-contiguous loops
# calculation doesn't consider indirect jumps entrances to loops
def tripcount_mean(loop, loop_ipc):
  if not isinstance(loop['size'], int): return None
  if 'non-contiguous' in loop['attributes']: return None
  hotness = lambda l: int(C.str2list(l)[0])
  hex_ipc, size = '0%x' % loop_ipc, loop['size']
  loop_body = C.exe_output(C.grep(hex_ipc, hitcounts, '-B1 -A%s' % size), sep='\n').split('\n')
  before = 0
  hex_ipc = hex_ipc[1:]
  head = 0 if hex_ipc in loop_body[0] else 1
  loop_hotness = hotness(loop_body[head])
  if head == 1 and not re.search(x86.JMP_RET, loop_body[0]):  # JCC before loop is not considered a special case
    before += hotness(loop_body[0])  # entrance by inst before loop
  addresses = hex_ipc
  for i in range(head + 1, head + size):
    line = loop_body[i].replace(str(hotness(loop_body[i])), '')
    addresses += '|' + line_ip_hex(line)
  # entrance by JMP to loop code
  # JCC that may jump to loop is not included
  entrances = C.exe_output(C.grep(r'jmp*\s+0x(%s)' % addresses, hitcounts, '-E'), sep='\n')
  if entrances != '':
    for line in entrances.split('\n'): before += hotness(line)
  if before == 0:
    C.warn('used default tripcount-mean calculation for loop at %s' % hex_ip(loop_ipc))
    return None
  if not '0x%x' % loop['back'] in loop_body[-1]:  # hotness after exiting loop code
    after = hotness(loop_body[-1])
    avg = float(before + after) / 2
  else: avg = float(before)
  return round(loop_hotness / avg, 2)

def print_loop_hist(loop_ipc, name, weighted=False, sortfunc=None):
  loop = loops[loop_ipc]
  if name not in loop: return None
  d = print_hist((loop[name], name, loop, loop_ipc, sortfunc, weighted))
  if not type(d) is dict: return d
  tot = d['total']
  del d['total']
  del d['type']
  for x in d.keys(): loop['%s-%s' % (name, x)] = d[x]
  print('')
  return tot

def print_glob_hist(hist, name, weighted=False, threshold=.03):
  if name in hsts_threshold: threshold = hsts_threshold[name]
  d = print_hist((hist, name, None, None, None, weighted), threshold)
  if not type(d) is dict: return d
  if d['type'] == 'hex': d['mode'] = hex_ip(int(d['mode']))
  del d['type']
  print('%s histogram summary: %s' % (name, hist_fmt(d)))
  return d['total']

def print_hist(hist_t, threshold=0.05):
  if not len(hist_t[0]): return 0
  hist, name, loop, loop_ipc, sorter, weighted = hist_t[0:]
  tot = sum(hist.values())
  d = {}
  d['type'] = 'str' if C.any_in(('name', 'paths'), name) else 'hex' if C.any_in(('indir', 'Function'), name) else 'number'
  d['mode'] = str(C.hist2slist(hist)[-1][0])
  keys = [sorter(x) for x in hist.keys()] if sorter else list(hist.keys())
  if d['type'] == 'number' and numpy_imported: d['mean'] = str(round(average(keys, weights=list(hist.values())), 2))
  do_tripcount_mean = name == 'tripcount' and d['mode'] == '32+'
  if do_tripcount_mean:
    mean = tripcount_mean(loop, loop_ipc)
    if mean: d['mean'] = mean
  d['num-buckets'] = len(hist)
  if d['num-buckets'] > 1:
    C.printc('%s histogram%s:' % (name, ' of loop %s' % hex_ip(loop_ipc) if loop_ipc else ''))
    left, limit = 0, int(threshold * tot)
    for k in sorted(hist.keys(), key=sorter):
      if not limit or hist[k] >= limit and hist[k] > 1:
        bucket = ('%70s' % k) if d['type'] == 'str' else '%5s' % (hex_ip(k) if d['type'] == 'hex' else k)
        print('%s: %7d%6.1f%%' % (bucket, hist[k], 100.0 * hist[k] / tot))
      else: left += hist[k]
    if left: print('other: %6d%6.1f%%\t// buckets > 1, < %.1f%%' % (left, 100.0 * left / tot, 100.0 * threshold))
  if do_tripcount_mean: d['num-buckets'] = '-'
  d['total'] = sum(hist[k] * int((k.split('+')[0]) if type(k) is str else k) for k in hist.keys()) if weighted else tot
  return d

def print_hist_sum(name, h):
  s = sum(hsts[h].values())
  print_stat(name, s, comment='histogram' if s else '')

c = lambda x: x.replace(':', '-')
def stat_name(name, prefix='count', ratio_of=None):
  def nm(x):
    if not ratio_of or ratio_of[0] != 'ALL': return x
    n = (x if 'cond' in name or 'fusible' in name or 'MRN' in name else x.upper()) + ' '
    if x.startswith('vec'): n += 'comp '
    if x in is_imix(None):  n += 'insts-class'
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
def print_imix_stat(n, c): print_stat(n, c, ratio_of=('ALL', glob['all']))

def print_global_stats():
  def nc(x): return 'non-cold ' + x
  def print_loops_stat(n, c): print_stat(nc(n + ' loops'), c, prefix='proxy count', ratio_of=('loops', len(loops)))
  cycles, scl = os.getenv('PTOOLS_CYCLES'), 1e3
  if cycles:
    lbr_ratio = ratio(scl * stat['total_cycles'], int(cycles))
    print_estimate('LBR cycles coverage (x%d)' % scl, lbr_ratio)
    stat['lbr-cov'] = float(lbr_ratio.split('%')[0])
    if stat['lbr-cov'] < 3: C.warn('LBR poor coverage of overall time')
  if len(footprint): print_estimate(nc('code footprint [KB]'), '%.2f' % (len(footprint) / 16.0))
  if len(pages): print_stat(nc('code 4K-pages'), len(pages))
  print_stat(nc('loops'), len(loops), prefix='proxy count', comment='hot loops')
  print_stat('cycles in loops', stat['total_loops_cycles'], prefix='proxy count', ratio_of=('total cycles', stat['total_cycles']))
  for n in (4, 5, 6): print_loops_stat('%dB-unaligned' % 2**n, len([l for l in loops.keys() if l & (2**n-1)]))
  print_loops_stat('undetermined size', len([l for l in loops.keys() if loops[l]['size'] is None]))
  if stats.ilen() : print_loops_stat('non-contiguous', len(loops) - len(contigous_loops))
  print_stat(nc('functions'), len(hsts[FUNCI]), prefix='proxy count', comment=FUNCI)
  if stats.size():
    for x in Insts_cond: print_imix_stat(x + ' conditional', glob['cond_' + x])
    print_imix_stat('unaccounted non-fusible conditional', glob['cond_non-fusible'] - glob['counted_non-fusible'])
    if stats.ilen():
      print_imix_stat('JCC-erratum conditional', glob['JCC-erratum'])
      print_imix_stat('jump-into-mid-loop', sum(jump_to_mid_loop.values()))
    for x in Insts_Fusions: print_imix_stat(x, glob[x]) 
    for x in Insts_MRN: print_imix_stat(x, glob[x])
    for x in Insts_global: print_imix_stat(x, glob[x])
  if 'indirect-x2g' in hsts:
    print_hist_sum('indirect (call/jump) of >2GB offset', 'indirect-x2g')
    print_hist_sum('mispredicted indirect of >2GB offset', 'indirect-x2g-misp')
    for x in indirects:
      if x in hsts['indirect-x2g-misp'] and x in hsts['indirect-x2g']:
        print_stat('a cross-2GB branch at %s' % hex_ip(x), ratio(hsts['indirect-x2g-misp'][x], hsts['indirect-x2g'][x]),
                   prefix='misprediction-ratio', comment='paths histogram')

def print_common(total):
  if stats.size():
    totalv = (total - stat['bad'] - stat['bogus'])
    stat['size']['avg'] = round(stat['size']['sum'] / totalv, 1) if totalv else -1
  print('LBR samples:', hist_fmt(stat))
  if edge_en and total:
    print_global_stats()
    print(' instructions.\n#'.join(['# Notes: CMP = CMP or TEST', ' RMW = Read-Modify-Write', 'Global-stats-end'])+'\n')
  C.warn_summary('info', 50)
  C.warn_summary()

def print_all(nloops=10, loop_ipc=0):
  total = sum(stat['IPs'].values()) if glob['ip_filter'] else stat['total']
  if not loop_ipc: print_common(total)
  if total and (stat['bad'] + stat['bogus']) / float(total) > 0.5:
    if verbose & 0x800: C.warn('Too many LBR bad/bogus samples in profile')
    else: C.error('Too many LBR bad/bogus samples in profile')
  for x in sorted(hsts.keys()): print_glob_hist(hsts[x], x)
  sloops = sorted(loops.items(), key=lambda x: loops[x[0]]['hotness'])
  if loop_ipc:
    if loop_ipc in loops:
      lp = loops[loop_ipc]
      tot = print_loop_hist(loop_ipc, 'IPC')
      for x in paths_range(): print_loop_hist(loop_ipc, 'paths-%d'%x, sortfunc=lambda x: x[::-1])
      if glob['loop_iters']: lp['cyc/iter'] = '%.2f' % (glob['loop_cycles'] / glob['loop_iters'])
      lp['FL-cycles%'] = ratio(glob['loop_cycles'], stat['total_cycles'])
      if 'Cond_polarity' in lp and len(lp['Cond_polarity']) == 1:
        for c in lp['Cond_polarity'].keys():
          lp['%s_taken' % hex_ip(c)] = ratio(lp['Cond_polarity'][c]['tk'], lp['Cond_polarity'][c]['tk'] + lp['Cond_polarity'][c]['nt'])
      tot = print_loop_hist(loop_ipc, 'tripcount', True, lambda x: int(x.split('+')[0]))
      if tot: lp['tripcount-coverage'] = ratio(tot, lp['hotness'])
      if hitcounts:
        if lp['size']:
          C.exe_cmd('%s && echo' % C.grep('0%x' % loop_ipc, hitcounts, '-B1 -A%d' % lp['size'] if verbose & 0x40 else '-A%d' % (lp['size']-1)),
            'Hitcounts & ASM of loop %s' % hex_ip(loop_ipc))
          if llvm_log: lp['IPC-ideal'] = llvm_mca_lbr.get_llvm(hitcounts, llvm_log, lp, hex_ip(loop_ipc))
        else:
          if debug: C.exe_cmd('%s && echo' % C.grep('0%x' % loop_ipc, hitcounts), 'Headline of loop %s' % hex_ip(loop_ipc))
          lp['attributes'] += ';likely_non-contiguous'
      find_print_loop(loop_ipc, sloops)
    else:
      C.warn('Loop %s was not observed' % hex_ip(loop_ipc))
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
  print('[from: %s, to: %s, taken: %d]' % (hex_ip(br['from']), hex_ip(br['to']), br['taken']))

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
    printl('No loop was detected at %s!' % hex_ip(ip), '\n')
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
  fixl += ['size', 'imix-ID']
  loop['hotness'] = '%6d' % loop['hotness']
  loop['size'] = str(loop['size']) if loop['size'] else '-'
  printl('%soop#%d: [ip: %s, ' % ('L' if detailed else 'l', num, hex_ip(ip)))
  for x in fixl: printl('%s: %s, ' % (x, loop[x]))
  if not stats.loop(): del loop['attributes']
  elif not len(loop['attributes']): loop['attributes'] = '-'
  elif ';' in loop['attributes']: loop['attributes'] = ';'.join(sorted(loop['attributes'].split(';')))
  dell = ['hotness', 'srcline', 'FL-cycles%', 'size', 'imix-ID', 'back', 'entry-block', 'IPC', 'tripcount']
  for x in paths_range(): dell += ['paths-%d'%x]
  #if 'taken' in loop and loop['taken'] <= loop['Conds']: dell += ['taken']
  if 'takens' in loop:
    for i in range(len(loop['takens'])):
      loop['takens'][i] = hex_ip(loop['takens'][i])
  if not (verbose & 0x20): dell += ['Cond_polarity', 'cyc/iter'] # No support for >1 Cond. cyc/iter needs debug (e.g. 548-xm3-basln)
  for x in ('back', 'entry-block'): printl('%s: %s, ' % (x, hex_ip(loop[x])))
  for x, y in (('inn', 'out'), ('out', 'inn')):
    if loop[x + 'er'] > 0: set2str(y + 'er-loops')
    else: dell += [y + 'er-loops']
  for x in dell:
    if x in loop: del loop[x]
  printl(C.chop(str(loop), "'{}\"") + ']', '\n')

def print_sample(sample, n=10):
  if not len(sample): return
  C.printf('\n'.join(('sample#%d' % stat['total'], sample[0], '\n')))
  size = int(sample[0].split('#size=')[1])
  if len(sample) > 1: C.printf('\n'.join((sample[-min(n, size):] if n else sample[1:]) + ['\n']))
  sys.stderr.flush()

def print_header():
  C.printc('Global stats:')
  print("perf-tools' lbr.py module version %.2f" % __version__)
