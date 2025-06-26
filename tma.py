#!/usr/bin/env python3
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
    events_files = len([f for f in os.listdir(pmu.sys_devices_cpu('/events')) if f.startswith('topdown')])
    if (pmu.goldencove_on() or force_glc) and events_files == 8:
      events += prepend(['heavy-ops', 'br-mispredict', 'fetch-lat', 'mem-bound'])
      flags = ' --td-level=2'
    events = '{%s}' % events
    if pmu.hybrid():
      for x, y in ((prefix, '/,cpu_%s/topdown-' % C.Globals['cputype']), ('}', '/}'), ('{slots/', '{slots'), ('ref-cycles/,', 'ref-cycles,')):
        events = events.replace(x, y)
  return events, flags

metrics = {
  'bot-fe':       '+Mispredictions,+Big_Code,+Instruction_Fetch_BW,+Branching_Overhead,+DSB_Misses',
  'bot-rest':     '+Cache_Memory_Bandwidth,+Cache_Memory_Latency,+Memory_Data_TLBs,+Memory_Synchronization'
                  ',+Compute_Bound_Est,+Irregular_Overhead,+Other_Bottlenecks,+Useful_Work' +
                  C.flag2str(',+Core_Bound_Likely', pmu.cpu('smt-on')),
  'extra-fe':     '+Fetch_Latency*/3,+Branch_Resteers*/4,+IpTB,+L2MPKI_Code*' +
                    ('' if pmu.lioncove_on() else ',+CoreIPC'),
  'fixed':        '+IPC,+Instructions,+UopPI,+Time,+SLOTS,+CLKS,-CPUs_Utilized',
  'key-info':     '+Load_Miss_Real_Latency,+L2MPKI,+ILP,+IpTB,+L2MPKI_Code,+IpMispredict,+UopPI' +
                    # C.flag2str(',+IpAssist', pmu.v4p()) +
                    C.flag2str(',+Memory_Bound*/3', pmu.goldencove_on()),
  'key-nodes':    ("+IPC,+CLKS" if pmu.lioncove_on() else "+CoreIPC,+CORE_CLKS") +
                    ",+Instructions,+Time,-CPUs_Utilized,-CPU_Utilization",
}

def settings_file(x):   return '/'.join((C.dirname(), 'settings', x))
def setting2dict(x):    return C.csv2dict(settings_file(x + '.csv'))
settings = setting2dict('tma')
for x in ('version', 'BV-version', 'num-levels', 'num-mux-groups'):
  metrics[x] = int(settings[x]) if C.is_num(settings[x]) else settings[x]

def get(tag):
  combo_tags = '[fe-]bottlenecks[-only|-as-list] zero-ok '
  def prepend_info(x): return ','.join((metrics['fixed'], x))
  def lookup(d, model):
    if model not in d.keys(): C.error("No support for model: %s" % model)
    return d[model]
  if tag =='bottlenecks': return prepend_info(','.join((metrics['bot-fe'], metrics['bot-rest'])))
  if tag =='bottlenecks-only': return ','.join((metrics['bot-fe'], metrics['bot-rest']))
  if tag =='fe-bottlenecks': return prepend_info(metrics['bot-fe'])
  if tag =='bottlenecks-list':
    return get('bottlenecks-only').replace(',+DSB_Misses', '').replace('+', '').split(',')
  if tag.startswith('bottlenecks-list-'):
    all = get('bottlenecks-list')
    return [all[i] for i in range(int(tag[-1]))]
  model = pmu.cpu_CPU('SPR')
  if tag == 'zero-ok':
    ZeroOk = setting2dict('tma-zero-ok')
    return lookup(ZeroOk, model).split(';')
  if tag == 'dedup-nodes':
    Dedup = setting2dict('tma-many-counters')
    return lookup(Dedup, model).replace(';', ',')
  if tag == 'perf-groups':
    groups = ','.join(C.file2lines(settings_file('bottlenecks/%s.txt' % model), True))
    td_groups = [f for f in os.listdir(pmu.sys_devices_cpu('/events')) if f.startswith('topdown')]
    for e in ['heavy-ops', 'br-mispredict', 'fetch-lat', 'mem-bound']:
      name = 'topdown-' + e
      if not name in td_groups: groups = groups.replace(',' + name, '')
    return groups
  assert tag in metrics, "Unsupported tma.get(%s)! Supported tags: %s" % (tag, combo_tags + ' '.join(metrics.keys()))
  return metrics[tag]

# TODO: import the model's ratios.py file under pmu-tools/ to look it up per metric
def threshold_of(metric):
  return 15

# Bottlenecks View over TMA - a *cheap* support for the yperf 1-shot collection
def add_tma(d):
  def ratio(x, denom='slots'):  return float(d[x]) / d[denom]
  def ratioc(x): return ratio(x, 'cycles')
  assert pmu.goldencove_on()
  glc = 'topdown-br-mispredict' in d
  d['#Mispred_Clears_Fr'] = float((d['topdown-br-mispredict'] / d['topdown-bad-spec']))
    #if glc else 1 / (1 + d['MACHINE_CLEARS.COUNT'] / d['BR_MISP_RETIRED.ALL_BRANCHES']))
  d['Branch_Mispredicts'] = ratio('topdown-br-mispredict') # if glc else d['topdown-bad-spec'] * d['#Mispred_Clears_Fr'])
  d['Frontend_Bound'] = ratio('topdown-fe-bound')
  d['Fetch_Latency'] = ratio('topdown-fetch-lat')
  d['Mispredicts_Resteers'] = d['#Mispred_Clears_Fr'] * ratioc('INT_MISC.CLEAR_RESTEER_CYCLES')
  d['Misp_Clear_Resteers'] = ratioc('INT_MISC.CLEAR_RESTEER_CYCLES')
  d['Unknown_Branches'] = ratioc('INT_MISC.UNKNOWN_BRANCH_CYCLES')
  d['ICache_Misses'] = ratioc('ICACHE_DATA.STALLS')
  d['ITLB_Misses'] = ratioc('ICACHE_TAG.STALLS')
  d['DSB_Switches'] = ratioc('DSB2MITE_SWITCHES.PENALTY_CYCLES')
  #d['MS_Switches'] = 3 * ratioc('IDQ.MS_UOPS:c1:e1')
  return d

#
## WARNING: this code merely does an ESTIMATION of the real metric! pmu-tools should have the right calculation.
#
def estimate(metric, d):
  bottlenecks = get('bottlenecks-list-3')
  if not metric: return bottlenecks
  assert metric in bottlenecks
  if 'Frontend_Bound' not in d: d = add_tma(d)
  def scale(x): return round(100 * x, 2)
  if metric == 'Mispredictions':
    # 100 * ( 1 - #Umisp ) * ( Branch_Mispredicts + Fetch_Latency * Mispredicts_Resteers / ##Fetch_Latency )
    return scale(d['Branch_Mispredicts'] + d['Mispredicts_Resteers'])
  if metric == 'Big_Code':
    # 100 * Fetch_Latency * ( ITLB_Misses + ICache_Misses + Unknown_Branches ) / ##Fetch_Latency
    big_code = d['ITLB_Misses'] + d['ICache_Misses'] + d['Unknown_Branches']
    return scale(min(big_code, d['Fetch_Latency'] - d['DSB_Switches'])) # - d['MS_Switches']))
  if metric == 'Instruction_Fetch_BW':
    # 100 * ( Frontend_Bound - ( 1 - #Umisp ) * Fetch_Latency * Mispredicts_Resteers / ##Fetch_Latency - #Assist_Frontend ) - Big_Code
    return round(100 * (d['Frontend_Bound'] - d['Misp_Clear_Resteers']) - estimate('Big_Code', d), 2)
  assert 0

