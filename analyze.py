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
from __future__ import print_function
__author__ = 'ayasin'
__version__ = 0.42 # see version line of do.py

import common as C, pmu, stats, tma
from lbr import x86

threshold = {
  'hot-loop': 0.05,
  'misp-sig': 5,
  'useless-hwpf': 0.15,
}
def bottlenecks(): return tma.get('bottlenecks-list-5')
for b in bottlenecks(): threshold[b] = tma.threshold_of(b);

def advise(m, prefix='Advise'): C.printc('\t%s:: %s' % (prefix, m), C.color.PURPLE)
def hint(m): advise(m, '\tHint')
def percent(x): return '%.1f%%' % (100.0 * x)

def analyze(app, args, do=None):
  info, hits = stats.get_file(app, 'info'), stats.get_file(app, 'hitcounts')
  if args.verbose > 2: print(app, info, hits, sep=', ')
  assert info and hits, 'Profiling info or hitcounts file is missing'
  if do:
    for x in threshold.keys():
      if 'az-%s' % x in do: threshold[x] = do['az-%s' % x]
  threshold['IpTB'] = 3 * pmu.cpu_pipeline_width()
  def exe(x, msg=None): return C.exe_cmd(x, msg=msg, debug = args.verbose > 1)
  def verbose(tag, x, level):
    if not args.verbose or level > args.verbose: return
    if type(x) is list:
      x = x[0] if args.verbose == 1 else ','.join(x)
    C.printc('\t%s:: %s' % (tag, str(x)))
  def lookup(x, f=hits): return C.exe_one_line("grep %s %s" % (x, f), fail=1)
  # TODO: move loop_code, loop_uops to lbr/loops.py
  def loop_code(loop): exe(C.grep(loop['ip'].replace('x', ''), hits, '--color -B1 -A%d' % loop['size']))
  def loop_uops(loop, loop_size): return loop_size - sum(loop[x] for x in loop.keys() if x.endswith('-mf'))
  def l2s(l): return ', '.join(l)
  def hits2line(h): return '\t' + ' '.join(h.split()[1:])
  def code_between(start, end): return C.exe_output("grep --color -A20 %s %s | sed /%s/q" % (start, hits, end), '\n')
  def examine(bottleneck):
    value = stats.get(bottleneck, app)
    flagged = value > threshold[bottleneck]
    atts = ('\n', 'exceeded', C.color.RED) if flagged else ('', 'within its threshold', C.color.DARKCYAN)
    C.printc('%s%s = %s is %s' % (atts[0], bottleneck, value, atts[1]), atts[2])
    return flagged

  if examine('Mispredictions'):
    mispreds = stats.get_file(app, 'mispreds')
    misp1 = mispreds.replace('.log', '-ptage.log')
    exe("cat %s | ./ptage | tee %s | tail | grep -E -v '=total|^\s+0'" % (mispreds, misp1),
        '@ top significant (== # executions * # mispredicts) branches')
    misp = C.file2lines(misp1); misp.pop()
    while 1:
      b = C.str2list(misp.pop())
      verbose('misp', b, 1)
      if float(b[0][:-1]) < threshold['misp-sig']: break
      line, forward, src, tgt = lookup(b[3]), -1, None, None # forward < 0 denotes unknown
      if x86.is_branch(hits2line(line), x86.COND_BR):
        line = line.split()
        src, tgt = line[1], line[3].replace('0x', '0')
        forward = int(tgt, 16) > int(src, 16)
      advise('branch at %s has significance of %s, misp-ratio %s, forward=%s' % (b[3].lstrip('0'), b[0], b[2],
              '?' if forward < 0 else int(forward)))
      if forward < 0: continue
      code = code_between(src, tgt) if forward else code_between(tgt, src)
      print(code)
      code = code.split('\n')
      if forward > 0:
        easy = True
        for h in code[1:-1]:
          line = hits2line(h)
          if x86.is_branch(line) or x86.is_memory(line):
            easy = False
            break
        if easy: hint('above forward-conditional branch should be converted to CMOV. check your compiler')

  if examine('Cache_Memory_Bandwidth'):
    value = stats.get('Useless_HWPF', app)
    if value > threshold['useless-hwpf']:
      advise('too much useless HW prefetches of %s; try to disable them' % percent(value))

  if not examine('Instruction_Fetch_BW'): return
  loops = stats.read_loops_info(info, as_loops=True)
  for l in sorted(loops.keys()):
    verbose('loop', (l, loops[l]), 2)
    if 'FL-cycles%' not in loops[l]: continue
    cycles, issues, extra, hints = loops[l]['FL-cycles%'], [], [], set()
    if cycles <= threshold['hot-loop']: continue
    verbose('loop', (l, loops[l]), 1)
    loop_size = loops[l]['size'] if type(loops[l]['size']) == int else -1
    if 0 < loop_size < threshold['IpTB']:
      issues += ['tight in size']
      extra += ['size-in-bytes=%d' % loops[l]['sizeIB']]
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
    if len(issues) == 0: continue
    advise('Hot %s is %s (%s of time, size= ~%d uops, %s);\n\t\t\t-> try to %s it' % (l,
      l2s(issues), percent(cycles), loop_uops(loops[l], loop_size), l2s(extra), l2s(hints)))
    #if loop_size > 0 and loops[l]['taken'] == 0: loop_code(loops[l])
    if loop_size > 0: loop_code(loops[l])

def gen_misp_report(data, header='Branch Misprediction Report (taken-only)'):
  if not data: return header.lower()
  def filename(ext): return '%s.%s.log' % (data, ext)
  def file2lines(ext): return C.file2lines(filename(ext), fail=True)
  takens_freq, mispreds = {}, {}
  for l in file2lines('takens')[:-1]:
    b = C.str2list(l)
    takens_freq[ b[2] ] = int(b[1])
  for l in file2lines('tk-mispreds')[:-1]:
    b = C.str2list(l)
    m = int(b[1])
    mispreds[ (' '.join(b[2:]), C.ratio(m, takens_freq[b[2]])) ] = m * takens_freq[b[2]]
  # significance := takens x mispredicts (based on taken-branch IP)
  with open(filename('mispreds'), 'w') as f:
    f.write('%s:\n' % header + ' '.join(('significance', '%7s' % 'misp-ratio', 'instruction address & ASM')) + '\n')
    for b in C.hist2slist(mispreds):
      if b[1] > 1: f.write('\t'.join(('%12s' % b[1], '%7s' % b[0][1], b[0][0]))+'\n')
