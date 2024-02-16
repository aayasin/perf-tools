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
__version__ = 0.20 # see version line of do.py

import common as C, pmu, stats

threshold = {
  'Instruction_Fetch_BW': 20,
  'Mispredictions': 15,
  'hot-loop': 0.05,
  'misp-sig': 3,
}

def advise(m): C.printc('Advise:: %s' % m, C.color.PURPLE)
def percent(x): return '%.1f%%' % (100.0 * x)

def analyze(app, args, do=None):
  info, hits = stats.get_file(app, 'info'), stats.get_file(app, 'hitcounts')
  if args.verbose > 2: print(app, info, hits, sep=', ')
  assert info and hits, 'Profiling info or hitcounts file is missing'
  if do:
    for x in threshold.keys():
      if 'az-%s' % x in do: threshold[x] = do['az-%s' % x]
  threshold['IpTB'] = 3 * pmu.cpu_pipeline_width()
  def exe(x): return C.exe_cmd(x, debug = args.verbose > 1)
  def loop_code(loop): exe(C.grep(loop['ip'].replace('x', ''), hits, '--color -B1 -A%d' % loop['size']))
  def loop_uops(loop, loop_size): return loop_size - sum(loop[x] for x in loop.keys() if x.endswith('-mf'))
  def l2s(l): return ', '.join(l)
  def within(bott): print(bott, '=', stats.get(bott, app), 'within its threshold')

  bott = 'Mispredictions'
  if stats.get(bott, app) > threshold[bott]:
    mispreds = stats.get_file(app, 'mispreds')
    misp1 = mispreds.replace('.log', '-ptage.log')
    exe("grep -A9999 'Branch Misprediction Report' %s | ./ptage | tee %s | tail" % (mispreds, misp1))
    misp = C.file2lines(misp1); misp.pop()
    while 1:
      b = C.str2list(misp.pop())
      if float(b[0][:-1]) < threshold['misp-sig']: break
      advise('misp at %s sig%% %s sig %s ratio %s' % (b[3], b[0], b[1], b[2]))
      exe('grep -B9 %s %s' % (b[3], hits))
  else: within(bott)
  bott = 'Instruction_Fetch_BW'
  if stats.get(bott, app) < threshold[bott]:
    within(bott)
    return
  loops = stats.read_loops_info(info, as_loops=True)
  for l in sorted(loops.keys()):
    if args.verbose > 1: print(l)
    if 'FL-cycles%' not in loops[l]: continue
    cycles, issues, extra, hints = loops[l]['FL-cycles%'], [], [], set()
    if cycles > threshold['hot-loop']:
      loop_size = loops[l]['size'] if type(loops[l]['size']) == int else -1
      if 0 < loop_size < threshold['IpTB']:
        issues += ['tight in size']
        hints.add('unroll')
      if loops[l]['inner']:
        issues += ['inner-loop']
        extra += ['nest-level=%d' % loops[l]['outer-loops'].count('[')]
        hints.add('unroll')
      if int(loops[l]['ip'], 16) & 0x1F:
        issues += ['32-byte unaligned']
        hints.add('align')
      if len(issues) == 0: continue
      if args.verbose > 0: print(loops[l])
      advise('Hot %s is %s (%s of time, size= ~%d uops, %s); try to %s it' % (l,
        l2s(issues), percent(cycles), loop_uops(loops[l], loop_size), l2s(extra), l2s(hints)))
      if loop_size > 0 and loops[l]['taken'] == 0: loop_code(loops[l])

