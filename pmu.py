#!/usr/bin/env python3
# Copyright (c) 2020-2024, Intel Corporation
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
def sys_devices_cpu(s=''): return '/sys/devices/cpu%s%s' % ('_core' if os.path.isdir('/sys/devices/cpu_core') else '', s)
def name(real=False):
  forcecpu = C.env2str('FORCECPU')
  def pmu_name():
    x = C.file2str(sys_devices_cpu() + '/caps/pmu_name')
    return "granite_rapids" if x == 'sapphire_rapids' and redwoodcove_on() else x
  return pmu_name() or 'Unknown PMU' if real or not forcecpu else forcecpu.lower()

# per CPU PMUs
def skylake():    return name() in ('skylake', 'skl')
def icelake():    return name() in ('icelake', 'icl', 'icx', 'tgl')
def alderlake():  return name() in ('alderlake_hybrid', 'adl')
def sapphire():   return name() in ('sapphire_rapids', 'spr', 'spr-hbm')
def meteorlake(): return name() in ('meteorlake_hybrid', 'mtl')
def granite():    return name() in ('granite_rapids', 'gnr')
def lunarlake():  return name() in ('lunarlake_hybrid', 'lnl')
# aggregations
def goldencove():   return alderlake() or sapphire()
def redwoodcove():  return meteorlake() or granite()
def perfmetrics():  return icelake() or goldencove() or goldencove_on()
# Skylake onwards
def v4p(): return os.path.exists(sys_devices_cpu() + '/format/frontend') # PEBS_FRONTEND introduced by Skylake (& no root needed)
  # int(msr_read(0x345)[2], 16) >= 3 # Skylake introduced PEBS_FMT=3 (!= PerfMon Version 4)
# Icelake onward PMU, e.g. Intel PerfMon Version 5+
def v5p(): return perfmetrics()

# FIXME:09: next *cove_on() do not support FORCECPU!
# Golden Cove onward PMUs have Arch LBR
def goldencove_on():  return cpu_has_feature('arch_lbr')
# Redwood Cove onward PMUs have CPUID.0x23
def redwoodcove_on(): return cpu_has_feature('CPUID.23H')
# For now
def lioncove_on():    return lunarlake()

def retlat(real=False): return cpu_has_feature('CPUID.23H', real=real)
# FIXME:09: extract next tuple from genretlat -h output
def is_retlat(x): return x and x in ('MTL', 'GNR', 'LNL')
def server():     return os.path.isdir('/sys/devices/uncore_cha_0')
def msocket():    return cpu('socketcount') > 1 # multi-socket
def hybrid():     return 'hybrid' in name()
def intel():      return 'Intel' in cpu('vendor')

# non-IA
def amd():
  x = C.exe_one_line("lscpu | grep 'Model name'")
  return 'AMD' in x and 'EPYC' in x

# events
def pmu():  return 'cpu_core' if hybrid() else 'cpu'
def default_period(): return 2000003
def period(n): return n + (1 if (n % 10 == 0) and goldencove_on() else 0)

def lbr_event(win=False):
  # AMD https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/perf/pmu-events/arch/x86/amdzen4/branch.json
  return 'BR_INST_RETIRED.NEAR_TAKENpdir' if win else ('rc4' if amd() else (('cpu_core/event=0xc4,umask=0x20/' if hybrid() else 'r20c4:') + 'ppp'))
def lbr_period(): return period(700000)
def lbr_unfiltered_events(cut=False):
    e = lbr_event()
    return (e[:-1] if cut else e, 'instructions:ppp', 'cycles:p', 'BR_INST_RETIRED.NEAR_TAKENpdir')

def event(x, precise=0, user_only=1, retire_latency=1):
  def misp_event(sub): return perf_event('BR_MISP_RETIRED.%s%s' % (sub, '_COST' if retlat() else ''))
  def rename_event(m, n): return perf_event(m).replace(m, n)
  aliases = {'lbr':     lbr_event(),
    'all-misp':   misp_event('ALL_BRANCHES'),
    #'calls-loop': 'r0bc4:callret_loop-overhead',
    'cond-misp':  misp_event('COND'),
    'cycles':     '%s/cycles/' % pmu() if hybrid() else 'cycles',
    'dsb-miss':   perf_event('FRONTEND_RETIRED.ANY_DSB_MISS'),
    'sentries':   rename_event('BR_INST_RETIRED.FAR_BRANCH', 'sentries')
  }
  e = aliases[x] if x in aliases else perf_event(x)
  if (precise or user_only) and not e.endswith('/'): e += ':'
  e += 'u'*user_only
  if precise: e += ('p'*precise + (' -W' if retire_latency and retlat() else ''))
  if ':' in x and x.split(':')[0].isupper(): e = e.replace(x.split(':')[0], x)
  return perf_format(e)

def event_period(e, p=default_period(), precise=True, lbr=True):
  ev = event(e, (3 if goldencove_on() else 2) if precise else 0)
  return '%s-e %s -c %d' % ('-b ' if lbr else '', ev, period(p))

def find_event_name(x):
  e = C.flag_value(x, '-e')
  if 'name=' in e: return e.split('name=')[1].split('/')[0]
  return e

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
  return m in ('DRAM_BW_Use', 'Power', 'Socket_CLKS') or \
         m.startswith(tuple(x + '_' for x in ('MEM', 'PMM', 'HBM', 'Uncore', 'UPI', 'IO')))

TPEBS = {'MTL':
  "MEM_LOAD_RETIRED.L3_HIT,MEM_LOAD_L3_HIT_RETIRED.XSNP_NO_FWD,MEM_LOAD_L3_HIT_RETIRED.XSNP_MISS,MEM_LOAD_L3_HIT_RETIRED.XSNP_FWD,"
  "FRONTEND_RETIRED.L2_MISS,BR_MISP_RETIRED.RET_COST,BR_MISP_RETIRED.COND_TAKEN_COST,BR_MISP_RETIRED.COND_NTAKEN_COST,"
  "MEM_INST_RETIRED.STLB_MISS_STORES,MEM_INST_RETIRED.STLB_MISS_LOADS,MEM_INST_RETIRED.STLB_HIT_STORES,MEM_INST_RETIRED.STLB_HIT_LOADS,"
  "FRONTEND_RETIRED.STLB_MISS,BR_MISP_RETIRED.INDIRECT_COST,BR_MISP_RETIRED.INDIRECT_CALL_COST,"
  "MEM_INST_RETIRED.SPLIT_STORES,MEM_INST_RETIRED.SPLIT_LOADS,MEM_INST_RETIRED.LOCK_LOADS,FRONTEND_RETIRED.ANY_DSB_MISS,"
  "FRONTEND_RETIRED.ITLB_MISS,FRONTEND_RETIRED.L1I_MISS,FRONTEND_RETIRED.MS_FLOWS,FRONTEND_RETIRED.UNKNOWN_BRANCH",

  'GNR': "BR_MISP_RETIRED.COND_NTAKEN_COST,BR_MISP_RETIRED.COND_TAKEN_COST,BR_MISP_RETIRED.INDIRECT_CALL_COST,BR_MISP_RETIRED.INDIRECT_COST,"
    "BR_MISP_RETIRED.RET_COST,FRONTEND_RETIRED.ANY_DSB_MISS,FRONTEND_RETIRED.ITLB_MISS,FRONTEND_RETIRED.L1I_MISS,"
    "FRONTEND_RETIRED.MS_FLOWS,FRONTEND_RETIRED.UNKNOWN_BRANCH,MEM_INST_RETIRED.LOCK_LOADS,MEM_INST_RETIRED.SPLIT_LOADS,"
    "MEM_INST_RETIRED.SPLIT_STORES,MEM_INST_RETIRED.STLB_HIT_LOADS,MEM_INST_RETIRED.STLB_HIT_STORES,MEM_LOAD_RETIRED.L2_HIT,"
    "MEM_LOAD_RETIRED.L3_HIT,MEM_LOAD_L3_HIT_RETIRED.XSNP_MISS,MEM_LOAD_L3_HIT_RETIRED.XSNP_NO_FWD,MEM_LOAD_L3_HIT_RETIRED.XSNP_FWD,"
    "MEM_LOAD_L3_MISS_RETIRED.LOCAL_DRAM,MEM_LOAD_L3_MISS_RETIRED.REMOTE_DRAM,MEM_LOAD_L3_MISS_RETIRED.REMOTE_FWD,"
    "MEM_LOAD_L3_MISS_RETIRED.REMOTE_HITM,FRONTEND_RETIRED.L2_MISS,FRONTEND_RETIRED.STLB_MISS",
}
# TODO: move this code to tma module
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

# perf_events add-ons
def perf_format(es):
  rs = []
  for orig_e in es.split(','):
    e = orig_e.replace('{', '').replace('}', '')
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
      rs += [ '%s%s%s' % ('{' if orig_e.startswith('{') else '', f, '}' if orig_e.endswith('}') else '') ]
    else: rs += [ orig_e ]
  return ','.join(rs)

perftools = os.path.dirname(os.path.realpath(__file__))
pmutools = C.env2str('PMUTOOLS', perftools + '/pmu-tools')
Toplev2Intel = {}
def toplev2intel_name(e):
  if not len(Toplev2Intel):
    try:
      with open(cpu('eventlist')) as file:
        json_d = json.load(file)
        if cpu.state: cpu.state['eventlist-version'] = float(json_d['Header']['Version']) # to-be-fixed hack!
        for event in json_d['Events']:
          Toplev2Intel[event['EventName'].lower().replace('.', '_')] = event['EventName']
    except FileNotFoundError:
      C.error('PMU event list %s is missing; try: %s/event_download.py' % (cpu('eventlist'), pmutools))
  return Toplev2Intel[e]

def perf_event(e):
  perf_str = C.exe_one_line('%s/ocperf -e %s --print' % (pmutools, e))
  tl_name = find_event_name(perf_str)
  return tl_name if tl_name.isupper() else perf_str.replace(tl_name, toplev2intel_name(tl_name)).split()[2]

#
# CPU, cpu_ prefix
#
def cpu_has_feature(feature, real=False):
  if feature == 'CPUID.23H': # a hack as lscpu Flags isn't up-to-date
    if C.env2int('CPUID23H') and not real: return 1
    cpuid_f = '%s/setup-cpuid.log' % perftools
    if not os.path.exists(cpuid_f):
      C.warn("Missing file: %s" % cpuid_f)
      C.exe_cmd('cpuid -1 > ' + cpuid_f, debug=1)
    return not C.exe_cmd(r"grep -E -q '\s+0x00000023 0x00: eax=0x000000.[^0] ' " + cpuid_f, fail=-1)
  if cpu_has_feature.flags: return feature in cpu_has_feature.flags
  def get_flags():
    forcecpu = C.env2str('FORCECPU')
    flags = C.exe_output("lscpu | grep Flags:")
    def hide(x): return flags.replace(x, '-')
    if forcecpu:
      if C.any_in(['ICL', 'ICX', 'TGL'], forcecpu): flags = hide('arch_lbr')
      if C.any_in(['ADL', 'MTL'], forcecpu): flags = hide('avx512')
      if name(1) in ('icelake', ) and goldencove(): flags += ' arch_lbr'
    return flags
  cpu_has_feature.flags = get_flags()
  return cpu_has_feature(feature)
cpu_has_feature.flags = None

def force_cpu_toplev(forcecpu): return ('sprmax' if forcecpu.upper() == 'SPR-HBM' else forcecpu.lower()) if forcecpu else ''
def force_cpu(cpu):
  if '-' in cpu: cpu = cpu.split('-')[0]
  events_dir = '%s/.cache/pmu-events' % os.path.expanduser('~')
  cpus = C.exe_output(C.grep(r"%s.*,[Cc]ore" % cpu.upper(),
                                  '%s/mapfile.csv' % events_dir, '-E'), sep='\n').split('\n')
  if cpus == '': C.error("no eventlist found for the forced CPU")
  cpu_id, _ = cpus[0].split(',')[0], 'hybridcore' if cpus[0].count('_') == 2 else 'core'
  if '[' in cpu_id: cpu_id = cpu_id.split('[')[0] + cpu_id[-2]
  event_list = "%s/%s-%s.json" % (events_dir, cpu_id, 'hybridcore' if cpus[0].count('_') == 2 else 'core')
  if not os.path.exists(event_list): C.exe_cmd('%s/event_download.py %s' % (pmutools, cpu_id))
  return event_list

def cpu_CPU(default='UNK'): return 'GNR' if granite() else cpu('CPU') or C.env2str('TMA_CPU', default)
def cpu(what, default=None):
  def warn(): C.warn("pmu:cpu('%s'): unsupported parameter" % what); return None
  if cpu.state:
    if what == 'all':
      s = cpu.state.copy()
      for x in ('cpucount', 'eventlist', 'forcecpu', 'kernel-version', 'model', 'x86'): del s[x]
      return s
    return cpu.state if what == 'ALL' else (cpu.state[what] if what in cpu.state else warn())
  if not os.path.isdir(pmutools): C.error("'%s' is invalid!\nDid you cloned the right way: '%s'" % (pmutools,
      'git clone --recurse-submodules https://github.com/aayasin/perf-tools'))
  forcecpu = C.env2str('FORCECPU')
  if is_retlat(forcecpu) and not retlat():
    os.environ['CPUID23H'] = "1"
  def versions():
    def Cpu(m): M={'arl': 'lnl', 'sprmax': 'spr-hbm'}; return (M[m] if m in M else m).upper()
    d, v = {}, C.exe_one_line("%s/toplev.py --version%s 2>&1 | tail -1" %
                              (pmutools, (' --force-cpu %s' % force_cpu_toplev(forcecpu)) if forcecpu else '')).strip()
    for x in v.split(','):
      xs = x.split(':')
      if len(xs) > 1:
        k, v = str(xs[0].strip()), str(xs[1].strip())
        d[k] = (Cpu(v) if k == 'CPU' else v) if len(v) else None
      elif xs[0] != 'toplev': C.warn('toplev --version: %s' % xs[0])
    return d
  try:
    sys.path.append(pmutools)
    import tl_cpu, event_download
    cs = tl_cpu.CPU(known_cpus=((forcecpu, ()),) if forcecpu else ()) # cpu.state
    if what == 'get-cs': return cs
    cpu.state = {
      'CPUID.23H':    cpu_has_feature('CPUID.23H'),
      'corecount':    int(len(cs.allcpus) / cs.threads),
      'cpucount':     cpu_count(),
      'eventlist':    force_cpu(forcecpu) if forcecpu else event_download.eventlist_name(),
      'forcecpu':     int(True if forcecpu else False),
      'kernel-version': tuple(map(int, platform.release().split('.')[0:2])),
      'model':        cs.model,
      #'name':         cs.true_name,
      'smt-on':       cs.ht,
      'socketcount':  cs.sockets,
      'vendor':       C.exe_one_line("lscpu | grep 'Vendor'").split(':')[1].strip(), #cs.vendor,
      'x86':          int(platform.machine().startswith('x86')),
    }
    cpu.state.update(versions())
    # Forcing cpu to one with no retlat is done here to avoid infinite recursion
    if forcecpu and retlat(real=True):
      if forcecpu in ('ADL', 'SPR'): cpu.state['CPUID.23H'] = 0
      else: C.error('FORCECPU=%s is not supported for %s' % (forcecpu, name(True)))
    if hybrid():
      p_core_el = cpu.state['eventlist']
      hybrid_el = p_core_el.replace('-core.json', '-hybridcore-Core.json')
      if C.isfile(hybrid_el) and not C.isfile(p_core_el): C.exe_cmd('ln -s %s %s' % (hybrid_el, p_core_el), debug=1)
    return cpu(what, default)
  except ImportError:
    C.warn("could not import tl_cpu")
    if default: return default
  except KeyError: warn()
cpu.state = None

def msr_read(m): return C.exe_one_line('sudo %s/msr.py 0x%x' % (pmutools, m))

MSR = {'IA32_MCU_OPT_CTRL': 0x123,
}
def cpu_msrs(type='control_etc'):
  if type == 'data':
    return [0xe7, 0xe8,         # A/MPERF
            0x6e0,              # TSC_DEADLINE
            0x830]              # X2APIC_ICR
  
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
  if v5p(): # hack for not "before Ice Lake and Atom family processors"
      msrs += [0x10a, 0x1b01]   # DOITM in IA32_ARCH_CAPABILITIES[12], IA32_UARCH_MISC_CTL[0]
  return msrs

def cpu_peak_kernels(widths=(4, 5, 6, 8)):
  return ['peak%dwide' % x for x in widths]

def cpu_pipeline_width(all_widths=None):
  if all_widths: # TODO: eventually read from pmu-tools.
    # skylake
    full_widths = {'dsb':('IDQ.DSB_UOPS',6), 'mite':('IDQ.MITE_UOPS',5), 'decoders':('INST_DECODED.DECODERS',4), 'ms':('IDQ.MS_UOPS',4),
                   'issued':('UOPS_ISSUED.ANY',4),'executed':('UOPS_EXECUTED.THREAD',8),'retired':('UOPS_RETIRED.RETIRE_SLOTS',4)}
    if icelake():
      full_widths = {'dsb':('IDQ.DSB_UOPS',6), 'mite':('IDQ.MITE_UOPS',5), 'decoders':('INST_DECODED.DECODERS',4), 'ms':('IDQ.MS_UOPS',4),
                     'issued':('UOPS_ISSUED.ANY',5),'executed':('UOPS_EXECUTED.THREAD',10),'retired':('UOPS_RETIRED.SLOTS',8)}
    elif goldencove() or redwoodcove():
      full_widths = {'dsb':('IDQ.DSB_UOPS',8), 'mite':('IDQ.MITE_UOPS',6), 'decoders':('INST_DECODED.DECODERS',6), 'ms':('IDQ.MS_UOPS',4),
                     'issued':('UOPS_ISSUED.ANY',6),'executed':('UOPS_EXECUTED.THREAD',12),'retired':('UOPS_RETIRED.SLOTS',8)}
    elif lunarlake():
      full_widths = {'dsb':('IDQ.DSB_UOPS',12), 'mite':('IDQ.MITE_UOPS',8), 'decoders':('INST_DECODED.DECODERS',8), 'ms':('IDQ.MS_UOPS',4),
                     'issued':('UOPS_ISSUED.ANY',8),'executed':('UOPS_EXECUTED.THREAD',18),'retired':('UOPS_RETIRED.SLOTS',12)}
    return full_widths
  width = 4
  if icelake(): width = 5
  elif goldencove() or redwoodcove(): width = 6
  elif lunarlake(): width = 8
  return width

def widths_2_cmasks(widths):
  events = ""
  group_ctr=0
  if v4p(): #TODO: This will change from v4p() to pnc_on()
    max_pmus=4
  else:
    max_pmus=4  #TODO: This will eventually return vp4()
  for i in widths:
    e = widths[i][0]
    for j in range(int(widths[i][1])):
      if group_ctr == 0:
        events+="{"
      event_cmask = e + ':c' + str(j+1)
      events += perf_event(event_cmask).replace(e, event_cmask)
      if group_ctr == (max_pmus-1):
        events+="},"
        group_ctr=0
      else:
        events+=","
        group_ctr+=1
  return events[:-1]+"}"

# deeper uarch stuff

# returns MSB bit of DSB's set-index, if uarch is supported
def dsb_msb():
  return 11 if lunarlake() else 10 if goldencove() or redwoodcove() else (9 if skylake() or icelake() else None)

def dsb_set_index(ip):
  if not dsb_set_index.MSB: dsb_set_index.MSB = dsb_msb()
  mask = 2 ** (dsb_set_index.MSB + 1) - 1
  return ((ip & mask) >> 6)
dsb_set_index.MSB = None

def main():
  print(cpu(sys.argv[1] if len(sys.argv) > 1 else 'all'))

if __name__ == "__main__":
  main()
