#!/usr/bin/env python
# Copyright (c) 2020-2023, Intel Corporation
# Author: Ahmad Yasin
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# Abstraction of Intel Architecture and its Performance Monitoring Unit (PMU)
#
from __future__ import print_function
__author__ = 'ayasin'

import json, os, platform, sys
import common as C
if sys.version_info[0] < 3:
  from multiprocessing import cpu_count
else:
  from os import cpu_count

#
# PMU, no prefix
#
def sys_devices_cpu(): return '/sys/devices/cpu_core' if os.path.isdir('/sys/devices/cpu_core') else '/sys/devices/cpu'
def name():       return C.file2str(sys_devices_cpu() + '/caps/pmu_name') or 'Unknown PMU'

# per CPU PMUs
def skylake():    return name() == 'skylake'
def icelake():    return name() == 'icelake'
def alderlake():  return name() == 'alderlake_hybrid'
def sapphire():   return name() == 'sapphire_rapids'
def meteorlake(): return name() == 'meteorlake_hybrid'
# aggregations
def goldencove():   return alderlake() or sapphire()
def redwoodcove():  return meteorlake()
def perfmetrics():  return icelake() or goldencove() or goldencove_on()
# Skylake onwards
def v4p(): return os.path.exists(sys_devices_cpu() + '/format/frontend') # PEBS_FRONTEND introduced by Skylake (& no root needed)
  # int(msr_read(0x345)[2], 16) >= 3 # Skylake introduced PEBS_FMT=3 (!= PerfMon Version 4)
# Icelake onward PMU, e.g. Intel PerfMon Version 5+
def v5p(): return perfmetrics()
# Golden Cove onward PMUs have Arch LBR
def goldencove_on():  return cpu_has_feature('arch_lbr')

def server():     return os.path.isdir('/sys/devices/uncore_cha_0')
def hybrid():     return 'hybrid' in name()

# events
def pmu():  return 'cpu_core' if hybrid() else 'cpu'

def event(x):
  e = {'lbr':     'r20c4:Taken-branches:ppp',
    'calls-loop': 'r0bc4:callret_loop-overhead',
    'cycles':     '%s/cycles/' % pmu() if hybrid() else 'cycles',
    'dsb-miss':   '%s/event=0xc6,umask=0x1,frontend=0x1,name=FRONTEND_RETIRED.ANY_DSB_MISS/uppp' % pmu(),
    'sentries':   'r40c4:System-entries:u',
    }[x]
  return perf_format(e)

def event_name(x):
  e = C.flag_value(x, '-e')
  if 'name=' in e: return e.split('name=')[1].split('/')[0]
  return e

def lbr_event():
  return ('cpu_core/event=0xc4,umask=0x20/' if hybrid() else 'r20c4:') + 'ppp'
def lbr_period(period=700000): return period + (1 if goldencove_on() else 0)

def ldlat_event(lat):
  return '"{%s/mem-loads-aux,period=%d/,%s/mem-loads,ldlat=%s/pp}" -d -W' % (pmu(),
         1e12, pmu(), lat) if goldencove() else 'ldlat-loads --ldlat %s' % lat

def basic_events():
  events = [event('sentries')]
  if v5p(): events += ['r2424']
  if goldencove_on(): events += ['r0262']
  return ','.join(events)

Legacy_fixed = (('INST_RETIRED.ANY', 'instructions'),
                ('CPU_CLK_UNHALTED.THREAD', 'cycles'),
                ('CPU_CLK_UNHALTED.REF_TSC', 'ref-cycles'))
def fixed_events(intel_names):
  es, idx = [], 0 if intel_names else 1
  for x in Legacy_fixed: es += [x[idx]]
  if perfmetrics(): es.insert(0, ('TOPDOWN.SLOTS', 'slots')[idx])
  return es

# TODO: lookup Metric's attribute in pmu-tools/ratio; no hardcoding!
def is_uncore_metric(m):
  return m in ('DRAM_BW_Use', 'Power', 'Socket_CLKS') or C.startswith(
    [x+'_' for x in ('MEM', 'PMM', 'HBM', 'Uncore', 'UPI', 'IO')], m)

TPEBS = {'MTL':
  "MEM_LOAD_RETIRED.L3_HIT,MEM_LOAD_L3_HIT_RETIRED.XSNP_NO_FWD,MEM_LOAD_L3_HIT_RETIRED.XSNP_MISS,MEM_LOAD_L3_HIT_RETIRED.XSNP_FWD,"
  "FRONTEND_RETIRED.L2_MISS,BR_MISP_RETIRED.RET_COST,BR_MISP_RETIRED.COND_TAKEN_COST,BR_MISP_RETIRED.COND_NTAKEN_COST,"
  "MEM_INST_RETIRED.STLB_MISS_STORES,MEM_INST_RETIRED.STLB_MISS_LOADS,MEM_INST_RETIRED.STLB_HIT_STORES,MEM_INST_RETIRED.STLB_HIT_LOADS,"
  "FRONTEND_RETIRED.STLB_MISS,BR_MISP_RETIRED.INDIRECT_COST,BR_MISP_RETIRED.INDIRECT_CALL_COST,"
  "MEM_INST_RETIRED.SPLIT_STORES,MEM_INST_RETIRED.SPLIT_LOADS,MEM_INST_RETIRED.LOCK_LOADS,FRONTEND_RETIRED.ANY_DSB_MISS,"
  "FRONTEND_RETIRED.ITLB_MISS,FRONTEND_RETIRED.L1I_MISS,FRONTEND_RETIRED.MS_FLOWS,FRONTEND_RETIRED.UNKNOWN_BRANCH",
}
def get_events(tag='MTL'):
  MTLraw = "cpu_core/event=0xd1,umask=0x4,name=mem_load_retired_l3_hit,period=100021/p,cpu_core/event=0xd2,umask=0x2,name=mem_load_l3_hit_retired_xsnp_no_fwd,period=20011/p,cpu_core/event=0xd2,umask=0x1,name=mem_load_l3_hit_retired_xsnp_miss,period=20011/p,cpu_core/event=0xd2,umask=0x4,name=mem_load_l3_hit_retired_xsnp_fwd,period=20011/p,cpu_core/event=0xc6,umask=0x3,frontend=0x13,name=frontend_retired_l2_miss,period=100007/p,cpu_core/event=0xc5,umask=0x48,name=br_misp_retired_ret_cost,period=100007/p,cpu_core/event=0xc5,umask=0x41,name=br_misp_retired_cond_taken_cost,period=400009/p,cpu_core/event=0xc5,umask=0x50,name=br_misp_retired_cond_ntaken_cost,period=400009/p,cpu_core/event=0xd0,umask=0x12,name=mem_inst_retired_stlb_miss_stores,period=100003/p,cpu_core/event=0xd0,umask=0x11,name=mem_inst_retired_stlb_miss_loads,period=100003/p,cpu_core/event=0xd0,umask=0xa,name=mem_inst_retired_stlb_hit_stores,period=100003/p,cpu_core/event=0xd0,umask=0x9,name=mem_inst_retired_stlb_hit_loads,period=100003/p,cpu_core/event=0xc6,umask=0x3,frontend=0x15,name=frontend_retired_stlb_miss,period=100007/p,cpu_core/event=0xc5,umask=0xc0,name=br_misp_retired_indirect_cost,period=100003/p,cpu_core/event=0xc5,umask=0x42,name=br_misp_retired_indirect_call_cost,period=400009/p,cpu_core/event=0xd0,umask=0x42,name=mem_inst_retired_split_stores,period=100003/p,cpu_core/event=0xd0,umask=0x41,name=mem_inst_retired_split_loads,period=100003/p,cpu_core/event=0xd0,umask=0x21,name=mem_inst_retired_lock_loads,period=100007/p,cpu_core/event=0xc6,umask=0x3,frontend=0x1,name=frontend_retired_any_dsb_miss,period=100007/p,cpu_core/event=0xc6,umask=0x3,frontend=0x14,name=frontend_retired_itlb_miss,period=100007/p,cpu_core/event=0xc6,umask=0x3,frontend=0x12,name=frontend_retired_l1i_miss,period=100007/p,cpu_core/event=0xc6,umask=0x3,frontend=0x8,name=frontend_retired_ms_flows,period=100007/p,cpu_core/event=0xc6,umask=0x3,frontend=0x17,name=frontend_retired_unknown_branch,period=100007/p"
  if tag.startswith('MTL-raw'):
    rate = int(tag.split(':')[1]) if ':' in tag else 1
    if rate == 0: return MTLraw
    elif rate == 1: return MTLraw.replace('000', '00').replace('20011', '2011')
    elif rate == 2: return MTLraw.replace('0000', '00').replace('20011', '211').replace('100021', '1021')
    elif rate == 3: return MTLraw.replace('0000', '0').replace('20011', '131').replace('100021', '131')
    else: C.error('pmu.get_events(%s): unsupported rate=%d' % (tag, rate))
  return TPEBS[tag].replace(',', ':p,') + ':p'

def default_period(): return 2000003

# perf_events add-ons
def perf_format(es):
  rs = []
  for e in es.split(','):
    if e.startswith('r') and ':' in e and len(e) != len('rUUEE:u'):
      e = e.split(':')
      f, n = None, e[1]
      if len(e[0])==5:   f='%s/event=0x%s,umask=0x%s,name=%s/' % (pmu(), e[0][3:5], e[0][1:3], n)
      elif len(e[0])==7: f='%s/event=0x%s,umask=0x%s,cmask=0x%s,name=%s/' % (pmu(), e[0][5:7], e[0][3:5], e[0][1:3], n)
      elif len(e[0])==9: f='%s/event=0x%s,umask=0x%s,cmask=0x%s,edge=%d,inv=%d,name=%s/' % (pmu(),
        e[0][7:9], e[0][5:7], e[0][1:3], (int(e[0][3:5], 16) >> 2) & 0x1, int(e[0][3:5], 16) >> 7, n)
      else: C.error("profile:perf-stat: invalid syntax in '%s'" % ':'.join(e))
      if len(e) == 3: f += e[2]
      elif len(e) == 2: pass
      else: C.error("profile:perf-stat: invalid syntax in '%s'" % ':'.join(e))
      rs += [ f ]
    else: rs += [ e ]
  return ','.join(rs)

Toplev2Intel = {}
def toplev2intel_name(e):
  if not len(Toplev2Intel):
    with open(cpu('eventlist')) as file:
      db = json.load(file)['Events']
      for event in db:
        Toplev2Intel[event['EventName'].lower().replace('.', '_')] = event['EventName']
  return Toplev2Intel[e]
#
# CPU, cpu_ prefix
#
def cpu_has_feature(feature):
  flags = C.exe_output("lscpu | grep Flags:")
  return feature in flags

def force_cpu_toplev(forcecpu): return ('sprmax' if forcecpu.upper() == 'SPR-HBM' else forcecpu.lower()) if forcecpu else ''
def force_cpu(cpu):
  if '-' in cpu: cpu = cpu.split('-')[0]
  events_dir = '%s/.cache/pmu-events' % os.path.expanduser('~')
  cpus = C.exe_output(C.grep(r"%s.*,[Cc]ore" % cpu.upper(),
                                  '%s/mapfile.csv' % events_dir, '-E'), sep='\n').split('\n')
  if cpus == '': C.error("no eventlist found for the forced CPU")
  cpu_id, key = cpus[0].split(',')[0], 'hybridcore' if cpus[0].count('_') == 2 else 'core'
  if '[' in cpu_id: cpu_id = cpu_id.split('[')[0] + cpu_id[-2]
  event_list = "%s/%s-%s.json" % (events_dir, cpu_id, 'hybridcore' if cpus[0].count('_') == 2 else 'core')
  if not os.path.exists(event_list): C.exe_cmd('%s/event_download.py %s' % (pmutools, cpu_id))
  return event_list

pmutools = os.path.dirname(os.path.realpath(__file__)) + '/pmu-tools'
def cpu(what, default=None):
  def warn(): C.warn("pmu:cpu('%s'): unsupported parameter" % what); return None
  if cpu.state:
    if what == 'all':
      s = cpu.state.copy()
      for x in ('eventlist', 'model', 'x86'): del s[x]
      return s
    return cpu.state if what == 'ALL' else (cpu.state[what] if what in cpu.state else warn())
  if not os.path.isdir(pmutools): C.error("'%s' is invalid!\nDid you cloned the right way: '%s'" % (pmutools,
      'git clone --recurse-submodules https://github.com/aayasin/perf-tools'))
  forcecpu = C.env2str('FORCECPU')
  def versions():
    def Cpu(m): M={'sprmax': 'spr-hbm'}; return (M[m] if m in M else m).upper()
    d, v = {}, C.exe_one_line("%s/toplev.py --version%s 2>&1 | tail -1" %
                              (pmutools, (' --force-cpu %s' % force_cpu_toplev(forcecpu)) if forcecpu else '')).strip()
    for x in v.split(','):
      xs = x.split(':')
      if len(xs) > 1:
        k, v = str(xs[0].strip()), str(xs[1].strip())
        d[k] = Cpu(v) if k == 'CPU' else v
      elif xs[0] != 'toplev': C.warn('toplev --version: %s' % xs[0])
    return d
  try:
    sys.path.append(pmutools)
    import tl_cpu, event_download
    cs = tl_cpu.CPU(known_cpus=((forcecpu, ()),) if forcecpu else ()) # cpu.state
    if what == 'get-cs': return cs
    cpu.state = {
      'corecount':    int(len(cs.allcpus) / cs.threads),
      'cpucount':     cpu_count(),
      'eventlist':    force_cpu(forcecpu) if forcecpu else event_download.eventlist_name(),
      'model':        cs.model,
      #'name':         cs.true_name,
      'smt-on':       cs.ht,
      'socketcount':  cs.sockets,
      'x86':          int(platform.machine().startswith('x86')),
      'forcecpu':     int(True if forcecpu else False)
    }
    cpu.state.update(versions())
    return cpu(what, default)
  except ImportError:
    C.warn("could not import tl_cpu")
    if default: return default
  except KeyError: warn()
cpu.state = None

def msr_read(m): return C.exe_one_line('sudo %s/msr.py 0x%x' % (pmutools, m))

MSR = {'IA32_MCU_OPT_CTRL': 0x123,
}
def cpu_msrs():
  msrs = [0x048, 0x08b,         # IA32_SPEC_CTRL, microcode update signature
          0x1a4,                # Prefetch Control
          0x033,                # Memory Control
          0x345,                # IA32_PERF_CAPABILITIES
  ]
  if goldencove_on(): msrs += [0x6a0, 0x6a2] # IA32_{U,S}_CET
  if server():
    msrs += [0x610]         # RAPL. TODO: assert SNB-EP onwards
    msrs += [0x1b1, 0x19c]  # Thermal status-prochot for package/core.
    if v5p(): msrs += [0x06d]
  return msrs

def cpu_peak_kernels(widths=range(4, 7)):
  return ['peak%dwide' % x for x in widths]

def cpu_pipeline_width():
  width = 4
  if icelake(): width = 5
  elif goldencove() or redwoodcove(): width = 6
  return width

# deeper uarch stuff

# returns MSB bit of DSB's set-index, if uarch is supported
def dsb_msb():
  return 10 if goldencove() or redwoodcove() else (9 if skylake() or icelake() else None)

def dsb_set_index(ip):
  left = dsb_msb()
  if left:
    mask = 2 ** (left + 1) - 1
    return ((ip & mask) >> 6)
  return None

def main():
  ALL = len(sys.argv) > 1 and sys.argv[1] == 'ALL'
  if len(sys.argv) > 1 and not ALL: return print(cpu(sys.argv[1]))
  print(cpu('ALL' if ALL else 'all'))

if __name__ == "__main__":
  main()
