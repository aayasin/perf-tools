#!/usr/bin/env python3
# Copyright (c) 2020-2023, Intel Corporation
# Author: Ahmad Yasin
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# studies multiple flavors of an application (with parallel post-processing)
#
from __future__ import print_function
__author__ = 'ayasin'
__version__= 0.74

import common as C, pmu, stats
import argparse, os, sys, time

def dump_sample():
  print("""#!/bin/bash
cd workloads/`echo $0 | sed 's/\.\///g' | cut -d- -f1`
a=`echo $0 | sed 's/\.\///;s/\.sh//' | cut -d- -f2`
ld=.

declare -A bins=( ["none"]="" )
bins['sse4']="${a}_r_base.ic2022.1-lin-sse4.2-rate-20220316"
bins['xspr']="${a}_r_base.ic2022.1-lin-sapphirerapids-rate-20220316"
#GCC
bins['gcc2']="exchange2_r_base.mtune_generic_o2_v2"
bins['gccf']="exchange2_r_base.march_native_ofast_lto"
B="${bins[$1]}"
cmd="./$B 6"
[[ -z "${TASKSET}" ]] || cmd="taskset $TASKSET $cmd"
log=.$B-$2-$$.log

#set -x
[[ ${NO_LLP} ]] || export LD_LIBRARY_PATH=$ld:$LD_LIBRARY_PATH
$cmd > $log 2>&1
grep -F Puzzle, $log 
""")
  C.exit()

DM=C.env2str('STUDY_MODE', 'imix-loops')
Conf = {
  'Events': {'imix-loops': 'r01c4:BR_INST_RETIRED.COND_TAKEN,r10c4:BR_INST_RETIRED.COND_NTAKEN', #'r11c4:BR_INST_RETIRED.COND'
    'imix-dsb': 'r2424:L2_RQSTS.CODE_RD_MISS,r0160:BACLEARS.ANY,r0262:DSB_FILL.OTHER_CANCEL,r01470261:DSB2MITE_SWITCHES.COUNT,'
                'FRONTEND_RETIRED.DSB_MISS,FRONTEND_RETIRED.ANY_DSB_MISS,BR_INST_RETIRED.COND_TAKEN,BR_INST_RETIRED.COND_NTAKEN,'
                'branches,IDQ.MS_CYCLES_ANY,ASSISTS.ANY,INT_MISC.CLEARS_COUNT,MACHINE_CLEARS.COUNT,MACHINE_CLEARS.MEMORY_ORDERING,UOPS_RETIRED.MS:c1',  # 4.6-nda+
    'dsb-align':  '{instructions,cycles,ref-cycles,IDQ_UOPS_NOT_DELIVERED.CORE,UOPS_ISSUED.ANY,IDQ.DSB_UOPS,FRONTEND_RETIRED.ANY_DSB_MISS},'
                  '{instructions,cycles,INT_MISC.CLEARS_COUNT,DSB2MITE_SWITCHES.PENALTY_CYCLES,INT_MISC.CLEAR_RESTEER_CYCLES,ICACHE_DATA.STALLS}',
    'dsb-glc':  '{IDQ.DSB_UOPS,r2424:L2_RQSTS.CODE_RD_MISS,r0160:BACLEARS.ANY,r01470261:DSB2MITE_SWITCHES.COUNT,'
                'FRONTEND_RETIRED.ANY_DSB_MISS,UOPS_ISSUED.ANY,INT_MISC.CLEARS_COUNT,INST_RETIRED.MACRO_FUSED}',
    #r02c0:INST_RETIRED.NOP,r10c0:INST_RETIRED.MACRO_FUSED,'\
    #,r01e5:MEM_UOP_RETIRED.LOAD,r02e5:MEM_UOP_RETIRED.STA'
    'cond-misp': 'r01c4:BR_INST_RETIRED.COND_TAKEN,r01c5:BR_MISP_RETIRED.COND_TAKEN'
                 ',r10c4:BR_INST_RETIRED.COND_NTAKEN,r10c5:BR_MISP_RETIRED.COND_NTAKEN',
    'openmp': 'r0106,r10d1:MEM_LOAD_RETIRED.L2_MISS,r3f24:L2_RQSTS.MISS,r70ec:CPU_CLK_UNHALTED.PAUSE'
              ',syscalls:sys_enter_sched_yield',
  },
  'Pebs': {'all-misp': '-b -e %s/event=0xc5,umask=0,name=BR_MISP_RETIRED/ppp -c 20003' % pmu.pmu(),
    'cond-misp': '-b -e %s/event=0xc5,umask=0x11,name=BR_MISP_RETIRED.COND/ppp -c 20003' % pmu.pmu(),
  },
  'Toplev': {'imix-loops': ' --frequency --metric-group +Summary --single-thread',
  },
  'Tune': {'dsb-align': [[':perf-record:"\' -g -c 20000003\'"']],
    'openmp': [[':perf-stat-ipc:"\'stat -e instructions,cycles,r0106\'"']],
  },
}
def modes_list():
  ms = []
  for x in Conf.keys(): ms += list(Conf[x].keys())
  assert DM in ms
  return list(set(ms))

def parse_args():
  def conf(x): return Conf[x][DM] if DM in Conf[x] else None
  ap = C.argument_parser('analyze two or more modes (configs)', mask=0x1911a,
         defs={'events': Conf['Events'][DM], 'toplev-args': conf('Toplev'), 'tune': conf('Tune')})
  ap.add_argument('config', nargs='*', default=[])
  ap.add_argument('--mode', nargs='?', choices=modes_list(), default=DM)
  ap.add_argument('-t', '--attempt', default='1')
  C.add_hex_arg(ap, '-s', '--stages', 0x1f, 'stages in study')
  ap.add_argument('--dump', action='store_const', const=True, default=False)
  ap.add_argument('--advise', action='store_const', const=True, default=False)
  ap.add_argument('--forgive', action='store_const', const=True, default=False)
  ap.add_argument('--smt', action='store_const', const=True, default=False)
  args = ap.parse_args()
  if args.dump: dump_sample()
  C.printc('mode: %s' % DM)
  def fassert(x, msg): assert x or args.forgive, msg
  assert len(args.config), "at least 2 modes are required"
  fassert(len(args.config) > 1, "at least 2 modes are required (or use --forgive)")
  assert args.app and not ' ' in args.app
  fassert(args.profile_mask & 0x100, 'args.pm=0x%x' % args.profile_mask)
  assert args.repeat > 2, "stats module requires '--repeat 3' at least"
  if DM in ('dsb-align', ): pass
  else: fassert(pmu.v5p(), "PMU version >= 5 is required for COND_[N]TAKEN events")
  return args

args = None
def app(flavor):
  if args.attempt == '-1': return args.app
  return "'%s %s %s'" % (args.app, flavor, 't%s' % args.attempt if args.attempt.isdigit() else args.attempt)

def main():
  do0 = C.realpath('do.py')
  do = do0 + ' profile'
  for x in C.argument_parser(None):
    a = getattr(args, x.replace('-', '_'))
    if a: do += ' --%s %s' % (x, "'%s'" % a if ' ' in a else a)
  if args.repeat != 3: do += ' -r %d' % args.repeat

  x = 'tune'
  a = getattr(args, x) or []
  extra = ' :sample:3 :perf-pebs:"\'%s\'" :perf-pebs-top:-1' % Conf['Pebs'][args.mode] if 'misp' in args.mode else ''
  if pmu.skylake(): extra += ' :perf-stat-add:-1'
  elif args.mode != 'imix-loops': extra += ' :perf-stat-add:0'
  a.insert(0, [':batch:1 :help:0 :loops:9 :msr:1 :dmidecode:1%s ' % extra])
  do += ' --%s %s' % (x, ' '.join([' '.join(i) for i in a]))

  if args.verbose > 1: do += ' -v %d' % (args.verbose - 1)
  do = do.replace('{', '"{').replace('}', '}"')
  def exe(c): return C.exe_cmd(c, debug=args.verbose)
  def do_cmd(c): return do.replace('profile', c).replace('batch:1', 'batch:0')

  C.fappend(' '.join([C.env2str(x, '', x) for x in ('STUDY_MODE', 'TMA_CPU', 'EVENTMAP')] + sys.argv), '.study.cmd')
  if args.stages & 0x1:
    enable_it=0
    if not args.smt and pmu.cpu('smt-on'):
      exe('%s disable-smt disable-aslr -v1' % do0)
      enable_it=1
    if args.stages & 0x8: exe(do_cmd('version log'))
    if C.any_in(('misp', 'dsb-glc'), args.mode): args.profile_mask |= 0x200
    for x in args.config: exe(' '.join([do, '-a', app(x), '-pm', '%x' % args.profile_mask, '--mode profile']))
    if enable_it: exe('%s enable-smt -v1' % do0)

  if args.stages & 0x2:
    jobs = []
    for step in ('100', '200', '8', '400'):
      if int(step, 16) & args.profile_mask:
        for x in args.config:
          jobs.append(' '.join([do, '-a', app(x), '-pm', step, '--mode process']))
    if len(jobs):
      jobs.append(jobs.pop(0))
      name = './.%s.sh' % C.command_basename(args.app + ' t%s' % args.attempt)
      exe('. ' + C.par_jobs_file(jobs, name, verbose=args.verbose))

  if args.stages & 0x4:
    if args.stages & 0x2: time.sleep(5)
    for x in args.config:
      if args.profile_mask & 0x10: stats.write_stat(app(x))
      if args.verbose > 1:
        stats.print_metrics(app(x))
    if len(args.config) == 2:
      bef, aft = args.config[0], args.config[1]
      C.printc('Speedup (%s/%s): %sx' % (aft, bef, str(round(stats.get('time', app(bef)) / stats.get('time', app(aft)),
               3 if args.verbose else 2))))

  if args.stages & 0x10:
    if args.stages & 0x2: time.sleep(60)
    exe(' '.join((do_cmd('tar'), '-a', args.app)))

if __name__ == "__main__":
  args = parse_args()
  main()
