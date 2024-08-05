#!/usr/bin/env python
# Copyright (c) 2020-2024, Intel Corporation
# Author: Ahmad Yasin
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# A module for common code for lbr scripts
#
from __future__ import print_function
__author__ = 'ayasin'

import sys, os, re
import common as C, pmu
from lbr import x86
from lbr.x86_fusion import is_jcc_fusion
try:
  from numpy import average
  numpy_imported = True
except ImportError:
  numpy_imported = False

hitcounts = C.envfile('PTOOLS_HITS')
debug = os.getenv('LBR_DBG')
verbose = C.env2int('LBR_VERBOSE', base=16) # nibble 0: stats, 1: extra info, 2: warnings; verbose=0x1 is free
user_imix = C.env2list('LBR_IMIX', ['vpmovmskb', 'imul'])
user_loop_imix = C.env2list('LBR_LOOP_IMIX', ['zcnt'])
user_jcc_pair = C.env2list('LBR_JCC_PAIR', ['JZ', 'JNZ'])

edge_en = 0
def warn(mask, x): return C.warn(x) if edge_en and (verbose & mask) else None

if debug: C.dump_stack_on_error = 1
def exit(x, sample, label, n=0, msg=str(debug), stack=False):
  if x: C.annotate(x, label, stack=stack)
  print_sample(sample, n)
  C.error(msg) if x else sys.exit(0)

def paths_range(): return range(3, C.env2int('LBR_PATH_HISTORY', 3))

stat = {x: 0 for x in ('bad', 'bogus', 'total', 'total_cycles')}
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

def INT_VEC(i): return r"\s%sp.*%s" % ('(v)?' if i == 0 else 'v', vec_reg(i))
vec_size = 3 if pmu.cpu_has_feature('avx512vl') else 2
def vec_reg(i): return '%%%smm' % chr(ord('x') + i)
def vec_len(i, t='int'): return 'vec%d-%s' % (128 * (2 ** i), t)

IMIX_CLASS = x86.MEM_INSTS + ['mem_indir-branch', 'nonmem-branch']
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
Insts_Fusions = [x + '-OP fusible' for x in [y + z for z in ['MOV', 'LD'] for y in ['', 'VEC ']]]
Insts_MRN = ['%s non-MRNable'%x for x in ['INC','DEC','LD-ST']]
Insts_V2II2V = ['%s transition-Penalty'%x for x in ['V2I','I2V']]
Insts_all = ['cond_%s'%x for x in Insts_cond] + Insts_Fusions + Insts_MRN + Insts_V2II2V + Insts_global

glob = {x: 0 for x in ['loop_cycles', 'loop_iters', 'counted_non-fusible'] + Insts_all}

class stats:
  SIZE, LOOP, ILEN = (2**i for i in range(3))
  enables = 0
  @staticmethod
  def ilen(): return stats.enables & stats.ILEN
  @staticmethod
  def loop(): return stats.enables & stats.LOOP
  @staticmethod
  def size(): return stats.enables & stats.SIZE

def line_inst(line):
  pInsts = ['cmov', 'pause', 'pdep', 'pext', 'popcnt', 'pop', 'push', 'vzeroupper'] + user_loop_imix
  allInsts = ['nop', 'lea', 'cisc-test'] + IMIX_CLASS + pInsts
  if not line: return allInsts
  if 'nop' in line: return 'nop'
  if '(' in line:  # load/store take priority in CISC insts
    if 'lea' in line: return 'lea'
    if x86.is_branch(line): return 'mem_indir-branch'
    return x86.get_mem_inst(line)
  if x86.is_branch(line): return 'nonmem-branch'
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

def is_type(t, l):    return x86.is_type(inst2pred(t), l)
def is_callret(l):    return is_type(x86.CALL_RET, l)
def is_taken(line):   return '# ' in line
def has_timing(line): return line.endswith('IPC')

def line_timing(line):
  x = re.match(r"[^#]+# (\S+) (\d+) cycles \[\d+\] ([0-9\.]+) IPC", line)
  # note: this ignores timing of 1st LBR entry (has cycles but not IPC)
  assert x, 'Could not match IPC in:\n%s' % line
  ipc = round(float(x.group(3)), 1)
  cycles = int(x.group(2))
  return cycles, ipc

# TODO: re-design this function to return: event-name, ip, timestamp, cost, etc as a dictionary if header or None otherwise
def is_header(line):
  def patch(x):
    if debug: C.printf("\nhacking '%s' in: %s" % (x, line))
    return line.replace(x, '-', 1)
  if '\tilen:' in line: return False
  if '[' in line[:50]:
    p = line.split('[')[0]
    assert p, "is_header('%s'); expect a '[CPU #]'" % line.strip()
    if '::' in p: pass
    elif ': ' in p: line = patch(': ')
    elif ':' in p: line = patch(':')
  #    tmux: server  3881 [103] 1460426.037549:    9000001 instructions:ppp:  ffffffffb516c9cf exit_to_user_mode_prepare+0x4f ([kernel.kallsyms])
  return (re.match(r"([^:]*):\s+(\d+)\s+(\S*)\s+(\S*)", line) or
# kworker/0:3-eve 105050 [000] 1358881.094859:    7000001 r20c4:ppp:  ffffffffb5778159 acpi_ps_get_arguments.constprop.0+0x1ca ([kernel.kallsyms])
#                              re.match(r"(\s?[\S]*)\s+([\d\[\]\.\s]+):\s+\d+\s+(\S*:)\s", line) or
#AUX data lost 1 times out of 33!
                              re.match(r"(\w)([\w\s]+)(.)", line) or
#         python3 105303 [000] 1021657.227299:          cbr:  cbr: 11 freq: 1100 MHz ( 55%)               55e235 PyObject_GetAttr+0x415 (/usr/bin/python3.6)
                              re.match(r"([^:]*):(\s+)(\w+:)\s", line) or
# instruction trace error type 1 time 1021983.206228655 cpu 1 pid 105468 tid 105468 ip 0 code 8: Lost trace data
                              re.match(r"(\s)(\w[\w\s]+\d) time ([\d\.]+)", line))

def is_label(line):
  line = line.strip()
  if 'ilen:' in line: return False
  return line.endswith(':') or (len(line.split()) == 1 and line.endswith(']')) or \
      (len(line.split()) > 1 and line.split()[-2].endswith(':')) or \
      (':' in line and line.split(':')[-1].isdigit())

def is_srcline(line): return 'srcline:' in line or is_label(line)
def get_srcline(line):
  if 'srcline:' in line:
    srcline = re.search(r"srcline:\s+(\S+)", line)
    return srcline.group(1) if srcline else None
  if line.endswith(':') or line.startswith('['): return None
  if line.endswith(']'):
    label_split = line.split()[-1].split('[')
    optional = '[' + label_split[-1]
    return 'N/A (%s%s)' % (label_split[0], optional if verbose else '')
  if len(line.split()) > 1 and line.split()[-2].endswith(':'): return line.split()[-1]
  if ':' in line and line.split(':')[-1].isdigit(): return line
  return None

def get_ilen(line):
  ilen = re.search(r"ilen:\s+(\d+)", line)
  return int(ilen.group(1)) if ilen else None

def is_jcc_erratum(line, previous=None):
  length = get_ilen(line)
  if not length: return False
  # JCC/CALL/RET/JMP
  if not is_type(x86.COND_BR, line) and not is_type(x86.CALL_RET, line) and not is_type(x86.JMP_RET, line): return False
  ip = line_ip(line)
  if previous and is_jcc_fusion(previous, line):
    ip = line_ip(previous)
    length += get_ilen(previous)
  next_ip = ip + length
  return not ip >> 5 == next_ip >> 5

def print_sample(sample, n=10):
  if not len(sample): return
  C.printf('\n'.join(('sample#%d' % stat['total'], sample[0], '\n')))
  size = int(sample[0].split('#size=')[1])
  if len(sample) > 1: C.printf('\n'.join((sample[-min(n, size):] if n else sample[1:]) + ['\n']))
  sys.stderr.flush()

def str2int(ip, plist):
  try:
    return int(ip, 16)
  except ValueError:
    print_sample(plist[1])
    assert 0, "expect address in '%s' of '%s'" % (ip, plist[0])

def line_ip_hex(line):
  if is_label(line): return None
  x = re.match(r"\s+(\S+)\s+(\S+)", line)
  # assert x, "expect <address> at left of '%s'" % line
  return x.group(1).lstrip("0")
def line_ip(line, sample=None):
  if is_label(line) or is_header(line): return None
  try:
    return str2int(line_ip_hex(line), (line, sample))
  except:
    exit(line, sample, 'line_ip()', msg="expect <address> at left of '%s'" % line.strip(), stack=True)
def hex_ip(ip): return '0x%x' % ip if ip and ip > 0 else '-'

def print_ipc_hist(hist, keys, threshold=0.05):
  r = lambda x: round(x, 1)
  tot = sum(hist.values())
  left, total_eff, left_eff = 0, 0, 0
  all_eff = {}
  # calculate efficiencies
  for k in keys:
    fk = float(k)
    eff = hist[k] / fk if fk else 0
    all_eff[k] = eff
    total_eff += eff
  limit = int(threshold * total_eff)
  # print histogram
  result = "{:>6} {:>8} {:>14} {:>12} {:>17}\n".format('IPC', 'Samples', '% of samples', 'Efficiency', '% of efficiency')
  for k in keys:
    eff = all_eff[k]
    if limit and (eff < limit or not hist[k] > 1):
      left += hist[k]
      left_eff += eff
    else:
      result += "{:>5}: {:>8} {:>13}% {:>12} {:>16}%\n".\
        format(k, hist[k], r(100.0 * hist[k] / tot), r(eff), r(100.0 * eff / total_eff))
  if left:
    result += "other: {:>8} {:>13}% {:>12} {:>16}%\t//  buckets > 1, < {}%".\
      format(left, r(100.0 * left / tot), r(left_eff), r(100.0 * left_eff / total_eff), 100.0 * threshold)
  return result

def print_hist(hist_t, threshold=0.05, tripcount_mean_func=None, print_hist=True):
  if not len(hist_t[0]): return 0
  hist, name, loop, loop_ipc, sorter, weighted = hist_t[0:]
  tot = sum(hist.values())
  d = {}
  d['type'] = 'str' if C.any_in(('name', 'paths'), name) else 'hex' if C.any_in(('indir', 'Function'), name) else 'number'
  d['mode'] = str(C.hist2slist(hist)[-1][0])
  keys = [sorter(x) for x in hist.keys()] if sorter else [float(x) for x in list(hist.keys())] if name == 'IPC' else list(hist.keys())
  if d['type'] == 'number' and numpy_imported: d['mean'] = str(round(average(keys, weights=list(hist.values())), 2))
  do_tripcount_mean = name == 'tripcount' and d['mode'] == '32+'
  if do_tripcount_mean and tripcount_mean_func:
    mean = tripcount_mean_func(loop, loop_ipc)
    if mean: d['mean'] = mean
  d['num-buckets'] = len(hist)
  if not print_hist: return d
  if d['num-buckets'] > 1:
    C.printc('%s histogram%s:' % (name, ' of loop %s' % hex_ip(loop_ipc) if loop_ipc else ''))
    sorted_keys = sorted(hist.keys(), key=sorter)
    if name == 'IPC': print(print_ipc_hist(hist, sorted_keys, threshold))
    else:
      left, limit = 0, int(threshold * tot)
      for k in sorted_keys:
        if not limit or hist[k] >= limit and hist[k] > 1:
          bucket = ('%70s' % k) if d['type'] == 'str' else '%5s' % (hex_ip(k) if d['type'] == 'hex' else k)
          print('%s: %7d%6.1f%%' % (bucket, hist[k], 100.0 * hist[k] / tot))
        else: left += hist[k]
      if left: print('other: %6d%6.1f%%\t// buckets > 1, < %.1f%%' % (left, 100.0 * left / tot, 100.0 * threshold))
  if do_tripcount_mean: d['num-buckets'] = '-'
  d['total'] = sum(hist[k] * int((k.split('+')[0]) if type(k) is str else k) for k in hist.keys()) if weighted else tot
  return d
