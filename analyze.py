#!/usr/bin/env python
# Copyright (c) 2020-2024, Intel Corporation
# Author: Ahmad Yasin
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# A module for analyzing profiling logs
#
# TODO:
#  - add a way to summarize supported SW optimizations per-bottleneck in a table,
#     akind to creation of profile-mask-help.md
#  - support Branching_Overhead
#
from __future__ import print_function
__author__ = 'ayasin'
__version__ = 0.62 # see version line of do.py

import common as C, pmu, stats, tma
from lbr import x86
import re

threshold = {
  'code-footprint':   600,
  'CPUs_Utilized':    0.95,
  'hot-func':         0.02,
  'hot-loop':         0.05,
  'indirect-target':  0.15,
  'IpTB':             3 * pmu.cpu_pipeline_width(),
  'misp-sig':         5,
  'misp-sig-ifetch':  1,
  'useless-hwpf':     0.15,
}
def bottlenecks(): return tma.get('bottlenecks-list-5')
for b in bottlenecks(): threshold[b] = tma.threshold_of(b);

handles = {}
def ext(e):
  if e in handles: return handles[e]
  if 'app' in handles:
    handles[e] = stats.get_file(handles['app'], e)
    return handles[e]
  C.error("did you missed to invoke analyze.setup('app name') ?")
def setup(app, basename=None, verbose=0):
  global handles
  C.info("analyze setup for '%s'" % app)
  if len(handles): handles.clear()
  handles['app'] = app
  handles['verbose'] = verbose
  log_exts = ('funcs', 'hitcounts', 'info', 'mispreds')
  if basename:
    for e in log_exts: handles[e] = '.'.join((basename, e, 'log'))

def lbr_info():
  if not lbr_info.info_d: lbr_info.info_d = stats.strip(stats.read_info(ext('info')))
  return lbr_info.info_d
lbr_info.info_d = None

def advise(m, prefix='Advice'): C.printc('\t%s:: %s' % (prefix, m), C.color.PURPLE)
def exe(x, msg=None): return C.exe_cmd(x, msg=msg, debug=handles['verbose'] > 1)
def file2lines(f, pop=False): return C.file2lines(f, fail=True, pop=pop, debug=handles['verbose'] > 3)
def hint(m): advise(m, '\tHint')
def percent(x): return '%.1f%%' % (100.0 * x)

def verbose(tag, x, level):
  if not handles['verbose'] or level > handles['verbose']: return
  if type(x) is list:
    x = x[0] if handles['verbose'] == 1 else ','.join(x)
  C.printc('\t%s:: %s' % (tag, str(x)))

def analyze_misp():
  def code_between(start, end): return C.exe_output("grep --color -A20 %s %s | sed /%s/q" % (start, ext('hitcounts'), end), '\n')
  def hits2line(h): return '\t' + ' '.join(h.split()[1:])
  def lookup(x): return C.exe_one_line("grep %s %s" % (x, ext('hitcounts')), fail=1)
  info_d = lbr_info()
  def top_target(src, i='indirect'):
    h = i + '_0x%s_targets' % src
    mode = h + '_mode'
    exe(stats.grep_histo(h, ext('info')))
    if mode in info_d:
      t = info_d[mode]
      t_cov = info_d[i + '_0x%s_targets_[%s]' % (src, t)] / info_d[i + '_0x%s_targets_total' % src]
      if t_cov > threshold['indirect-target']:
        hint('de-virtualize above %s branch when target is %s (%s of cases)' % (i, t, percent(t_cov)))

  exe(C.tail(ext('mispreds')), '@ top significant (== # executions * # mispredicts) branches')
  misp = file2lines(ext('mispreds'), pop=True)
  while 1:
    b = C.str2list(misp.pop())
    verbose('misp', b, 1)
    if float(b[0][:-1]) < threshold['misp-sig']: break
    line, forward, src, tgt = lookup(b[3]), -1, None, None  # forward < 0 denotes non-cond
    hits0, line = line[0], hits2line(line)
    src = line.split()[0].lstrip('0')
    if x86.is_branch(line, x86.COND_BR):
      tgt = line.split()[2].replace('0x', '0')
      forward = int(tgt, 16) > int(src, 16)
    elif x86.is_branch(line, x86.INDIRECT):
      forward = -2
    advise('branch at %s has significance of %s, misp-ratio %s, %s' % (b[3].lstrip('0'), b[0], b[2],
      ('non-cond:' + ('indirect' if forward == -2 else '?')) if forward < 0 else 'cond:forward=%d' % int(forward)))
    if forward == -2:
      verbose('indirect', line, 2)
      top_target(src)
      top_target(src, 'indirect-misp')
    if forward < 0: continue
    code = code_between(src, tgt) if forward else code_between(tgt, src)
    print(code)
    code = code.split('\n')
    if forward > 0:
      easy = True
      for h in code[1:-1]:
        aline = hits2line(h)
        if x86.is_branch(aline) or x86.is_memory(aline):
          easy = False
          break
      if easy: hint('above forward-conditional branch should be converted to CMOV. check your compiler')

# interface for do.py
def analyze(app, args, do=None, analyze_all=True):
  handles['app'] = app
  handles['verbose'] = args.verbose
  handles['stat'] = 1
  info, hits = ext('info'), ext('hitcounts')
  if args.verbose > 2: print(app, info, hits, sep=', ')
  assert info and hits, 'Profiling info or hitcounts file is missing'
  if do:
    for x in threshold.keys():
      if 'az-%s' % x in do: threshold[x] = do['az-%s' % x]

  def examine(bottleneck):
    value = stats.get(bottleneck, app)
    flagged = value > threshold[bottleneck]
    atts = ('\n', 'exceeded', C.color.RED) if flagged else ('', 'within its threshold', C.color.GREEN)
    C.printc('%s%s = %s is %s' % (atts[0], bottleneck, value, atts[1]), atts[2])
    return flagged

  CPUs_Utilized = stats.get('CPUs_Utilized', app)
  if CPUs_Utilized < threshold['CPUs_Utilized']:
    advise('Low # CPU utilized = %.2f; is your workload CPU-Bound?' % CPUs_Utilized)

  if examine('Mispredictions'):       analyze_misp()
  if examine('Big_Code'):             analyze_bigcode()
  if examine('Instruction_Fetch_BW'): analyze_ifetch()
  if not analyze_all: return

  if examine('Cache_Memory_Bandwidth'):
    value = stats.get('Useless_HWPF', app)
    if value > threshold['useless-hwpf']:
      advise('too much useless HW prefetches of %s; try to disable them' % percent(value))

def analyze_bigcode():
  app, d = handles['app'], {}
  # TODO: let stats.py rollup also lbr_info by default, so that
  #  stats.get('code footprint') works (no cosmetic spaces)
  def c(s): return re.sub(r'[ ]+', ' ', s)
  bc_metrics = ('L2MPKI_Code_All',
    'count of                                  non-cold code 4K-pages',
    'estimate of                         non-cold code footprint [KB]',
  )
  assert 'footprint' in bc_metrics[-1] # keep it last
  for s in bc_metrics:
    if ' ' in s:
      d[c(s)] = lbr_info()[s]
    elif 'stat' in handles:
      d[s] = stats.get(s, app)
  if d[c(bc_metrics[-1])] < threshold['code-footprint']: return
  advise('Large code footprint symptom. Are you using a profile-guided optimization tool, like autoFDO or BOLT?')
  C.printc(C.dict2str(d))

def analyze_ifetch():
  # TODO: move loop_code, loop_uops to lbr/loops.py
  def loop_code(loop): exe(C.grep(loop['ip'].replace('x', ''), ext('hitcounts'), '--color -B1 -A%d' % loop['size']))
  def func_code(func): exe(C.grep_start_end('flows of function at %s' % func['ip'], 'flow ', ext('funcs')))
  def loop_uops(loop, loop_size): return loop_size - sum(loop[x] for x in loop.keys() if x.endswith('-mf'))
  def l2s(l): return ', '.join(l)
  loops = stats.read_loops_info(ext('info'), as_loops=True)
  sig_misp = stats.read_mispreds(ext('mispreds'), threshold['misp-sig-ifetch'])
  for l in sorted(loops.keys()):
    verbose('loop', (l, loops[l]), 2)
    if 'FL-cycles%' not in loops[l]: continue
    back, cycles, issues, extra, hints = loops[l]['back'].lstrip('0x'), loops[l]['FL-cycles%'], [], [], set()
    if cycles <= threshold['hot-loop'] and back not in sig_misp: continue
    verbose('loop', (l, loops[l]), 1)
    loop_size = loops[l]['size'] if type(loops[l]['size']) == int else -1
    if 0 < loop_size < threshold['IpTB']:
      issues += ['tight in size']
      if 'sizeIB' in loops[l]: extra += ['size-in-bytes=%d' % loops[l]['sizeIB']]
      hints.add('unroll')
    if loops[l]['inner']:
      issues += ['inner-loop']
      extra += ['nest-level=%d' % loops[l]['outer-loops'].count('[')]
      hints.add('unroll')
      if int(loops[l]['ip'], 16) & 0x3F:
        issues += ['64-byte unaligned']
        hints.add('align')
    if int(loops[l]['ip'], 16) & 0x1F:
      issues += ['32-byte unaligned']
      hints.add('align')
    if back in sig_misp:
      issues += ['back=%s is costly mispredict' % loops[l]['back']]
      hints.add('unroll')
    if len(issues) == 0: continue
    advise('Hot %s is %s. Loop accounts for %s of time, size= ~%d uops, %s;\n\t\t\t-> try to %s it' % (l,
      l2s(issues), percent(cycles), loop_uops(loops[l], loop_size), l2s(extra), l2s(hints)))
    #if loop_size > 0 and loops[l]['taken'] == 0: loop_code(loops[l])
    if loop_size > 0: loop_code(loops[l])
  funcs = stats.read_funcs_info(ext('info'), as_funcs=True)
  for f in sorted(funcs.keys()):
    verbose('func', (f, funcs[f]), 2)
    if 'FF-cycles%' not in funcs[f]: continue
    cycles, issues, hints = funcs[f]['FF-cycles%'], [], set()
    if cycles <= threshold['hot-func']: continue
    verbose('func', (f, funcs[f]), 1)
    if funcs[f]['flows-num'] == 1 and '<serial>' in funcs[f]['flows']:
      issues += ['serial']
      hints.add('inline')
      # FIXME:06: report size of flow
      advise('Hot %s is %s. Function accounts for %s of time, # flows = %d;\n\t\t\t-> try to %s it' % (f,
        l2s(issues), percent(cycles), funcs[f]['flows-num'], l2s(hints)))
      func_code(funcs[f])
    # FIXME:06: handle non-serial single flow

def gen_misp_report(data, header='Branch Misprediction Report (taken-only)', verbose=None):
  if not data: handles['verbose'] = verbose; return header.lower()
  def filename(ext='mispreds-tmp'): return '%s.%s.log' % (data, ext)
  takens_freq, mispreds = {}, {}
  for l in file2lines(filename('takens'))[:-1]:
    b = C.str2list(l)
    takens_freq[ b[2] ] = int(b[1])
  for l in file2lines(filename('tk-mispreds'))[:-1]:
    b = C.str2list(l)
    m = int(b[1])
    mispreds[ (' '.join(b[2:]), C.ratio(m, takens_freq[b[2]])) ] = m * takens_freq[b[2]]
  # significance := takens x mispredicts (based on taken-branch IP)
  with open(filename(), 'w') as f:
    f.write('%s:\n' % header + ' '.join(('significance', '%7s' % 'misp-ratio', 'instruction address & ASM')) + '\n')
    for b in C.hist2slist(mispreds):
      if b[1] > 1: f.write('\t'.join(('%12s' % b[1], '%7s' % b[0][1], b[0][0]))+'\n')
  C.exe_cmd("cat %s | %s > %s && rm -f %s" % (filename(), C.ptage(), filename('mispreds'), filename()))
