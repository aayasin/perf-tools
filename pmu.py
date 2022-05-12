#!/usr/bin/env python
# Abstraction of Intel Architecture and its Performance Monitoring Unit (PMU)
# Author: Ahmad Yasin
# edited: May 2022
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

# events
def lbr_event():
  return ('cpu_core/event=0xc4,umask=0x20/' if alderlake() else 'r20c4:') + 'ppp'

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
    cpu_state = tl_cpu.CPU((), False, tl_cpu.Env())
  return {'smt-on': cpu_state.ht}[what]
# cpu.state = None

def cpu_msrs():
  msrs = ['0x48', '0x8b', '0x1a4']
  if server(): msrs += ['0x6d']
  return msrs

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
