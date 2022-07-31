#!/usr/bin/env python
# Abstraction of Intel Architecture and its Performance Monitoring Unit (PMU)
# Author: Ahmad Yasin
# edited: June 2022
from __future__ import print_function
__author__ = 'ayasin'

import sys, os
import common as C

#
# PMU, no prefix
#
def name():
  f = '/sys/devices/cpu_core' if os.path.isdir('/sys/devices/cpu_core') else '/sys/devices/cpu'
  f += '/caps/pmu_name'
  return C.file2str(f) or 'Unknown PMU'

# per CPU PMUs
def skylake():    return name() == 'skylake'
def icelake():    return name() == 'icelake'
def alderlake():  return name() == 'alderlake_hybrid'
def sapphire():   return name() == 'sapphire_rapids'

# aggregations
def goldencove():   return alderlake() or sapphire()
def perfmetrics():  return icelake() or goldencove()
# Icelake onward PMU, e.g. Intel PerfMon Version 5+
def v5p(): return perfmetrics()
def server():     return os.path.isdir('/sys/devices/uncore_cha_0')
def hybrid():     return 'hybrid' in name()

# events
def pmu():  return 'cpu_core' if hybrid() else 'cpu'

def event(x):
  e = {'lbr':     'r20c4:Taken-branches:ppp',
    'work-proxy': 'r03c4:Work-progress-proxy',
    'sentries':   'r40c4:System-entries:u',
    }[x]
  return perf_format(e) if x == 'lbr' or v5p() else ''

def lbr_event():
  return ('cpu_core/event=0xc4,umask=0x20/' if hybrid() else 'r20c4:') + 'ppp'

def basic_events():
  return ','.join((event('work-proxy'), event('sentries')))

# perf_events add-ons
def perf_format(es):
  rs = []
  for e in es.split(','):
    if e.startswith('r') and ':' in e:
      e, f, n = e.split(':'), None, ':'.join(e.split(':')[1:])
      if len(e[0])==5:   f='%s/event=0x%s,umask=0x%s,name=%s/' % (pmu(), e[0][3:5], e[0][1:3], n)
      elif len(e[0])==7: f='%s/event=0x%s,umask=0x%s,cmask=0x%s,name=%s/' % (pmu(), e[0][5:7], e[0][3:5], e[0][1:3], n)
      elif len(e[0])==9: f='%s/event=0x%s,umask=0x%s,cmask=0x%s,edge=%d,name=%s/' % (pmu(),
        e[0][7:9], e[0][5:7], e[0][3:5], (int(e[0][1:3], 16) >> 2) & 0x1, n)
      else: C.error("profile:perf-stat: invalid syntax in '%s'" % ':'.join(e))
      rs += [ f ]
    else: rs += [ e ]
  return ','.join(rs)

import csv, re
def read_perf_toplev(filename):
  perf_fields_tl = ['Timestamp', 'CPU', 'Group', 'Event', 'Value', 'Perf-event', 'Index', 'STDDEV', 'MULTI', 'Nodes']
  d = {}
  with open(filename) as csvfile:
    reader = csv.DictReader(csvfile, fieldnames=perf_fields_tl)
    for r in reader:
      if r['Event'] in ('Event', 'dummy'): continue
      x = r['Event']
      v = int(float(r['Value']))
      if x == 'msr/tsc/': x = 'tsc'
      elif x == 'duration_time':
        x = 'DurationTimeInMilliSeconds'
        v = float(v/1e6)
        d[x] = v
        continue
      elif '.' in x or x.startswith('cpu/topdown-'): pass
      else: print(r['Event'])
      b = re.match(r"[a-zA-Z\.0-9_]+:?", x).group(0)
      for i in (b, ':sup', ':user'): x = x.replace(i, i.upper())
      if v == 0 and x in d and d[x] != 0: C.warn('skipping zero override in: ' + str(r))
      else: d[x] = v
  return d

#
# CPU, cpu_ prefix
#
def cpu_has_feature(feature):
  flags = C.exe_output("lscpu | grep Flags:")
  return feature in flags

def cpu(what):
  if 1:  # not cpu.state:
    sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/pmu-tools')
    import tl_cpu
    cs = tl_cpu.CPU((), False, tl_cpu.Env()) # cpu.state
  if what == 'get': return cs
  return {'smt-on': cs.ht,
    'corecount': int(len(cs.allcpus) / cs.threads),
  }[what]
# cpu.state = None

def cpu_msrs():
  msrs = ['0x48', '0x8b', '0x1a4']
  if goldencove(): msrs += ['0x6a0', '0x6a2']
  if server() and v5p(): msrs += ['0x6d']
  return msrs

def cpu_TLA():
  return name()[:3].upper() # a hack for now

def cpu_peak_kernels(widths=range(4, 7)):
  return ['peak%dwide' % x for x in widths]

def cpu_pipeline_width():
  width = 4
  if icelake(): width = 5
  elif goldencove(): width = 6
  return width

# deeper uarch stuff

# returns MSB bit of DSB's set-index, if uarch is supported
def dsb_msb():
  return 10 if goldencove() else (9 if skylake() or icelake() else None)

def dsb_set_index(ip):
  left = dsb_msb()
  if left:
    mask = 2 ** (left + 1) - 1
    return ((ip & mask) >> 6)
  return None
