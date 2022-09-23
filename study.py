#!/usr/bin/env python3
# studies multiple flavors of an application (with parallel post-processing)
# Author: Ahmad Yasin
# edited: Sep 2022
#
from __future__ import print_function
__author__ = 'ayasin'

import common as C
import argparse, os, sys

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

def parse_args():
  ap = C.argument_parser(mask=0x111a, defs=[None, None, ' --single-thread'])
  ap.add_argument('mode', nargs='*', default=[])
  ap.add_argument('-t', '--attempt', type=int, default=1)
  ap.add_argument('--profile', type=int, default=1)
  ap.add_argument('--dump', action='store_const', const=True, default=False)
  args = ap.parse_args()
  if args.dump: dump_sample()
  assert len(args.mode) > 1
  assert args.app and not ' ' in args.app
  return args

args = parse_args()

evs = 'r02c0:INST_RETIRED.NOP,r10c0:INST_RETIRED.MACRO_FUSED,r01c4:BR_INST_RETIRED.COND_TAKEN,'
      'r10c4:BR_INST_RETIRED.COND_NTAKEN,r01e5:MEM_UOP_RETIRED.LOAD,r02e5:MEM_UOP_RETIRED.STA'
do = "./do.py profile --toplev-args '%s' --tune :loops:10" % args.toplev_args
for x in ('perf', 'pmu_tools'):
  a = getattr(args, x)
  if a: do += ' --%s %s' % (x, a)
if args.verbose > 1: do += ' -v %d' % (args.verbose - 1)

def exe(c): return C.exe_cmd(c, debug=args.verbose)
def app(flavor): return "'%s %s t%d'" % (args.app, flavor, args.attempt)

if args.profile:
  for x in args.mode: exe(' '.join([do, '-e', evs, '-a', app(x), '-pm', '%x' % args.profile_mask, '--mode profile']))

jobs = []
for step in ('100', '8'):
  for x in args.mode:
    jobs.append(' '.join([do, '-e', evs, '-a', app(x), '-pm', step, '--mode process']))
jobs.append(jobs.pop(0))

name = './%s.sh' % C.command_basename(args.app + ' t%d' % args.attempt)
exe('. ' + C.par_jobs_file(jobs, name, verbose=args.verbose))
