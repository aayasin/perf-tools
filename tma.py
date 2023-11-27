#!/usr/bin/env python
# Copyright (c) 2020-2023, Intel Corporation
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

def fixed_metrics(intel_names=False, force_glc=False):
  events, flags = ','.join(pmu.fixed_events()) if intel_names else 'instructions,cycles,ref-cycles', None
  if pmu.perfmetrics():
    prefix = ',topdown-'
    def prepend(l): return prefix.join([''] + l)
    if not intel_names: events = events.replace(pmu.fixed_events()[0], 'slots')
    events += prepend(['retiring', 'bad-spec', 'fe-bound', 'be-bound'])
    if pmu.goldencove() or force_glc:
      events += prepend(['heavy-ops', 'br-mispredict', 'fetch-lat', 'mem-bound'])
      flags = ' --td-level=2'
    events = '{%s}' % events
    if pmu.hybrid(): events = events.replace(prefix, '/,cpu_core/topdown-').replace('}', '/}').replace('{slots/', '{slots')
  return events, flags

metrics = {
  'bot-fe':       '+Mispredictions,+Big_Code,+Instruction_Fetch_BW,+Branching_Overhead,+DSB_Misses',
  'bot-rest':     '+Cache_Memory_Bandwidth,+Cache_Memory_Latency,+Memory_Data_TLBs,+Memory_Synchronization'
                  ',+Irregular_Overhead,+Other_Bottlenecks,+Base_Non_Br' +
                  C.flag2str(',+Core_Bound_Likely', pmu.cpu('smt-on')),
  'fixed':        '+IPC,+Instructions,+UopPI,+Time,+SLOTS,+CLKS',
  'key-info':     '+Load_Miss_Real_Latency,+L2MPKI,+ILP,+IpTB,+IpMispredict,+UopPI' +
                    C.flag2str(',+IpAssist', pmu.v4p()) +
                    C.flag2str(',+Memory_Bound*/3', pmu.goldencove()), # +UopPI once ICL mux fixed, +ORO with TMA 4.5
  'version':      '4.6-full-perf',
}

def get(tag):
  combo_tags = '[fe-]bottlenecks[-only] zero-ok '
  def prepend_info(x): return ','.join((metrics['fixed'], x))
  def settings_file(x): return '/'.join((C.dirname(), 'settings', x))
  if tag =='bottlenecks': return prepend_info(','.join((metrics['bot-fe'], metrics['bot-rest'])))
  if tag =='bottlenecks-only': return ','.join((metrics['bot-fe'], metrics['bot-rest']))
  if tag =='fe-bottlenecks': return prepend_info(metrics['bot-fe'])
  model = pmu.cpu('CPU') or C.env2str('TMA_CPU', 'SPR')
  if tag == 'zero-ok':
    ZeroOk = C.csv2dict(settings_file('tma-zero-ok.csv'))
    return ZeroOk[model].split(';')
  if tag == 'dedup-nodes':
    Dedup = C.csv2dict(settings_file('tma-many-counters.csv'))
    return Dedup[model].replace(';', ',')
  if tag == 'perf-groups':
    return ','.join(C.file2lines(settings_file('bottlenecks/%s.txt' % model)))
  assert tag in metrics, "Unsupported tma.get(%s)! Supported tags: %s" % (tag, combo_tags + ' '.join(metrics.keys()))
  return metrics[tag]
