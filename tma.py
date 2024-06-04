#!/usr/bin/env python
# Copyright (c) 2020-2024, Intel Corporation
# Author: Ahmad Yasin
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# Interface to the Top-down Microarchitecture Analysis (TMA) logic
#
from __future__ import print_function
__author__ = 'ayasin'

import common as C, pmu
import os

def fixed_metrics(intel_names=False, force_glc=False):
  events, flags = ','.join(pmu.fixed_events(intel_names)), None
  if pmu.perfmetrics():
    prefix = ',topdown-'
    def prepend(l): return prefix.join([''] + l)
    events += prepend(['retiring', 'bad-spec', 'fe-bound', 'be-bound'])
    events_files = len([f for f in os.listdir(pmu.sys_devices_cpu() + '/events/') if f.startswith('topdown')])
    if (pmu.goldencove_on() or force_glc) and events_files == 8:
      events += prepend(['heavy-ops', 'br-mispredict', 'fetch-lat', 'mem-bound'])
      flags = ' --td-level=2'
    events = '{%s}' % events
    if pmu.hybrid():
      for x, y in ((prefix, '/,cpu_core/topdown-'), ('}', '/}'), ('{slots/', '{slots'), ('ref-cycles/,', 'ref-cycles,')):
        events = events.replace(x, y)
  return events, flags

metrics = {
  'bot-fe':       '+Mispredictions,+Big_Code,+Instruction_Fetch_BW,+Branching_Overhead,+DSB_Misses',
  'bot-rest':     '+Cache_Memory_Bandwidth,+Cache_Memory_Latency,+Memory_Data_TLBs,+Memory_Synchronization'
                  ',+Compute_Bound_Est,+Irregular_Overhead,+Other_Bottlenecks,+Useful_Work' +
                  C.flag2str(',+Core_Bound_Likely', pmu.cpu('smt-on')),
  'fixed':        '+IPC,+Instructions,+UopPI,+Time,+SLOTS,+CLKS,-CPUs_Utilized',
  'key-info':     '+Load_Miss_Real_Latency,+L2MPKI,+ILP,+IpTB,+IpMispredict,+UopPI' +
                    C.flag2str(',+IpAssist', pmu.v4p()) +
                    C.flag2str(',+Memory_Bound*/3', pmu.goldencove_on()),
  'version':      '4.8-full-perf',
  'num-mux-groups':   58, # -pm 0x80 on ICX
}

def get(tag):
  combo_tags = '[fe-]bottlenecks[-only|-as-list] zero-ok '
  def prepend_info(x): return ','.join((metrics['fixed'], x))
  def settings_file(x): return '/'.join((C.dirname(), 'settings', x))
  if tag =='bottlenecks': return prepend_info(','.join((metrics['bot-fe'], metrics['bot-rest'])))
  if tag =='bottlenecks-only': return ','.join((metrics['bot-fe'], metrics['bot-rest']))
  if tag =='fe-bottlenecks': return prepend_info(metrics['bot-fe'])
  if tag =='bottlenecks-list':
    return get('bottlenecks-only').replace(',+DSB_Misses', '').replace('+', '').split(',')
  if tag =='bottlenecks-list-2':
    all = get('bottlenecks-list')
    return [all[i] for i in (0, 2)]
  model = pmu.cpu('CPU') or C.env2str('TMA_CPU', 'SPR')
  if tag == 'zero-ok':
    ZeroOk = C.csv2dict(settings_file('tma-zero-ok.csv'))
    return ZeroOk[model].split(';')
  if tag == 'dedup-nodes':
    Dedup = C.csv2dict(settings_file('tma-many-counters.csv'))
    return Dedup[model].replace(';', ',')
  if tag == 'perf-groups':
    groups = ','.join(C.file2lines(settings_file('bottlenecks/%s.txt' % model), True))
    td_groups = [f for f in os.listdir('/sys/devices/cpu/events/') if f.startswith('topdown')]
    for e in ['heavy-ops', 'br-mispredict', 'fetch-lat', 'mem-bound']:
      name = 'topdown-' + e
      if not name in td_groups: groups = groups.replace(',' + name, '')
    return groups
  assert tag in metrics, "Unsupported tma.get(%s)! Supported tags: %s" % (tag, combo_tags + ' '.join(metrics.keys()))
  return metrics[tag]

# TODO: import the model's ratios.py file under pmu-tools/ to look it up per metric
def threshold_of(metric):
  return 20
