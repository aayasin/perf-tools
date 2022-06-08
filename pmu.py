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

def lbr_event():
  return ('cpu_core/event=0xc4,umask=0x20/' if hybrid() else 'r20c4:') + 'ppp'

def workproxy_event():
  return 'r03c4:BR_INST_RETIRED.WORK_PROXY' if v5p() else ''

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
