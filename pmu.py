#!/usr/bin/env python
# Abstraction of Intel Architecture and its Performance Monitoring Unit (PMU)
# Author: Ahmad Yasin
# edited: March 2022
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

#Icelake onward PMU, e.g. Intel PerfMon Version 5+
def v5p(): return perfmetrics()

#per CPU PMUs
def icelake():
  return name() in ['icelake']
def alderlake():
  return name() in ['alderlake_hybrid']
def sapphire():
  return name() in ['sapphire_rapids']

#aggregations
def goldencove():
  return alderlake() or sapphire()
def perfmetrics():
  return icelake() or goldencove()

#events
def lbr_event():
  return ('cpu_core/event=0xc4,umask=0x20/' if alderlake() else 'r20c4:') + 'ppp'

#
# CPU, cpu_ prefix
#
def cpu_has_feature(feature):
  flags = C.exe_output("lscpu | grep Flags:")
  return feature in flags

def cpu_pipeline_width():
  width = 4
  if icelake(): width = 5
  elif goldencove(): width = 6
  return width

def cpu_peak_kernels(widths=range(4,7)):
  return ['peak%dwide'%x for x in widths]

