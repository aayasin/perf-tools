#!/usr/bin/env python3
# studies multiple flavors of an application (with parallel post-processing)
# Author: Ahmad Yasin
# edited: Oct 2022
#
from __future__ import print_function
__author__ = 'ayasin'

import common as C, pmu, stats
import argparse, os, sys, time

import stats


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
  sys.exit(0)

DM='imix-loops'
Events = {'imix-loops': 'r01c4:BR_INST_RETIRED.COND_TAKEN,r10c4:BR_INST_RETIRED.COND_NTAKEN',
  #'r11c4:BR_INST_RETIRED.COND'
  #r02c0:INST_RETIRED.NOP,r10c0:INST_RETIRED.MACRO_FUSED,'\
  #,r01e5:MEM_UOP_RETIRED.LOAD,r02e5:MEM_UOP_RETIRED.STA'
}

Toplev = {'imix-loops': ' --single-thread',
}

def parse_args():
  ap = C.argument_parser('analyze two or more modes (configs)', mask=0x111a,
                         defs={'toplev-args': Toplev[DM], 'events': Events[DM]})
  ap.add_argument('config', nargs='*', default=[])
  ap.add_argument('--mode', nargs='?', choices=['imix-loops'],
                  default=DM)
  ap.add_argument('-t', '--attempt', type=int, default=1)
  C.add_hex_arg(ap, '-s', '--stages', 0x7, 'stages in study')
  ap.add_argument('--dump', action='store_const', const=True, default=False)
  ap.add_argument('--advise', action='store_const', const=True, default=False)
  ap.add_argument('--forgive', action='store_const', const=True, default=False)
  args = ap.parse_args()
  if args.dump: dump_sample()
  assert len(args.config), "at least 2 modes are required"
  if not args.forgive: assert len(args.config) > 1, "at least 2 modes are required (or use --forgive)"
  assert args.app and not ' ' in args.app
  assert args.profile_mask & 0x100 or args.forgive, 'args.pm=0x%x' % args.profile_mask
  assert pmu.v5p() # required for COND_[N]TAKEN events
  return args

args = parse_args()

do = "./do.py profile"
for x in C.argument_parser(None):
  a = getattr(args, x.replace('-', '_'))
  if a: do += ' --%s %s' % (x, "'%s'" % a if ' ' in a else a)
x = 'tune'
a = getattr(args, x) or []
a.insert(0, [':loops:10 :batch:1'])
do += ' --%s %s' % (x, ' '.join([' '.join(i) for i in a]))
if args.verbose > 1: do += ' -v %d' % (args.verbose - 1)
def exe(c): return C.exe_cmd(c, debug=args.verbose)
def app(flavor):
  if args.attempt == -1: return args.app
  return "'%s %s t%d'" % (args.app, flavor, args.attempt)

if args.stages & 0x8: exe(do.replace('profile', 'log').replace('batch:1', 'batch:0'))

if args.stages & 0x1:
  for x in args.config: exe(' '.join([do, '-a', app(x), '-pm', '%x' % args.profile_mask, '--mode profile']))

if args.stages & 0x2:
  jobs = []
  for step in ('100', '200', '8', '400'):
    if int(step, 16) & args.profile_mask:
      for x in args.config:
        jobs.append(' '.join([do, '-a', app(x), '-pm', step, '--mode process']))
  if len(jobs):
    jobs.append(jobs.pop(0))
    name = './%s.sh' % C.command_basename(args.app + ' t%d' % args.attempt)
    exe('. ' + C.par_jobs_file(jobs, name, verbose=args.verbose))

if args.stages & 0x4:
  if args.stages & 0x2: time.sleep(5)
  if len(args.config) == 2:
    bef, aft = args.config[0], args.config[1]
    C.printc('Speedup (%s/%s): %.2fx' % (aft, bef, stats.get('time', app(bef)) / stats.get('time', app(aft))))
  if args.verbose > 1:
    for x in args.config: stats.print_metrics(app(x))
