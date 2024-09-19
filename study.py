#!/usr/bin/env python3
# Copyright (c) 2020-2024, Intel Corporation
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
__version__= 0.94

import common as C, pmu, stats
import os, sys, time, re
from lbr.lbr import stat_name

def dump_sample():
  print(r"""#!/bin/bash
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
grep -F Puzzle, $log # replace this to grep a score (performance result) of your workload
""")
  C.exit()

DM=C.env2str('STUDY_MODE', 'imix-loops')
STUDY_PROF_MASK = 0x1911a
Conf = {
  # TODO: remaining hardcoded events to use pmu.perf_event(+ CMask support)
  'Events': {'imix-loops': 'BR_INST_RETIRED.COND_TAKEN,BR_INST_RETIRED.COND_NTAKEN', #'r11c4:BR_INST_RETIRED.COND'
    'imix-dsb': 'L2_RQSTS.CODE_RD_MISS,BACLEARS.ANY,DSB_FILL.OTHER_CANCEL,r01470261:DSB2MITE_SWITCHES.COUNT,'
                'FRONTEND_RETIRED.DSB_MISS,FRONTEND_RETIRED.ANY_DSB_MISS,BR_INST_RETIRED.COND_TAKEN,BR_INST_RETIRED.COND_NTAKEN,'
                'branches,IDQ.MS_CYCLES_ANY,ASSISTS.ANY,INT_MISC.CLEARS_COUNT,MACHINE_CLEARS.COUNT,MACHINE_CLEARS.MEMORY_ORDERING,UOPS_RETIRED.MS:c1',  # 4.6-nda+
    'dsb-align':  '{instructions,cycles,ref-cycles,IDQ_UOPS_NOT_DELIVERED.CORE,UOPS_ISSUED.ANY,IDQ.DSB_UOPS,FRONTEND_RETIRED.ANY_DSB_MISS},'
                  '{instructions,cycles,INT_MISC.CLEARS_COUNT,DSB2MITE_SWITCHES.PENALTY_CYCLES,INT_MISC.CLEAR_RESTEER_CYCLES,ICACHE_DATA.STALLS}',
    'dsb-glc':  '{IDQ.DSB_UOPS,L2_RQSTS.CODE_RD_MISS,BACLEARS.ANY,r01470261:DSB2MITE_SWITCHES.COUNT,'
                'FRONTEND_RETIRED.ANY_DSB_MISS,UOPS_ISSUED.ANY,INT_MISC.CLEARS_COUNT,INST_RETIRED.MACRO_FUSED}',
    'dsb-bw':   '{r010879:IDQ.DSB_UOPS-c1,r020879:IDQ.DSB_UOPS-c2,r030879:IDQ.DSB_UOPS-c3,IDQ.DSB_UOPS,UOPS_ISSUED.ANY,UOPS_RETIRED.SLOTS},'
                '{r040879:IDQ.DSB_UOPS-c4,r050879:IDQ.DSB_UOPS-c5,r060879:IDQ.DSB_UOPS-c6,r070879:IDQ.DSB_UOPS-c7}',
    #r02c0:INST_RETIRED.NOP,r10c0:INST_RETIRED.MACRO_FUSED,'\
    #,r01e5:MEM_UOP_RETIRED.LOAD,r02e5:MEM_UOP_RETIRED.STA'
    'cond-misp': 'BR_INST_RETIRED.COND_TAKEN,BR_MISP_RETIRED.COND_TAKEN'
                 ',BR_INST_RETIRED.COND_NTAKEN,BR_MISP_RETIRED.COND_NTAKEN',
    # TODO: remove if once event-list is updated
    'mem-bw':   '' if pmu.icelake() or pmu.alderlake() else ','.join([pmu.perf_event('L2_LINES_OUT.'+x) for x in ('USELESS_HWPF', 'NON_SILENT', 'SILENT')]),
    'openmp': 'r0106,MEM_LOAD_RETIRED.L2_MISS,L2_RQSTS.MISS,CPU_CLK_UNHALTED.PAUSE'
              ',syscalls:sys_enter_sched_yield',
  },
  'Pebs': {
    'dsb-bw': # not in eventlist pmu.event('FRONTEND_RETIRED.LATENCY_GE_2_BUBBLES_GE_4', 3),
              '-b -e %s/event=0xc6,umask=%d,frontend=0x400206,name=FRONTEND_RETIRED.LATENCY_GE_2_BUBBLES_GE_4/uppp%s'
              ' -c 100003' % (pmu.pmu(), 3 if pmu.redwoodcove_on() else 1, ' -W' if pmu.retlat() else ''),
  },
  'Toplev': {'imix-loops': ' --frequency --metric-group +Summary',
  },
  'Tune': {'dsb-align': [[':perf-record:"\' -g -c 20000003\'"']],
    'openmp': [[':perf-stat-ipc:"\'stat -e instructions,cycles,r0106\'"']],
  },
}
Conf['Events']['all-misp'] = Conf['Events']['cond-misp']
for x in ('all-misp', 'cond-misp'): Conf['Pebs'][x] = '-b -e %s -c 20003' % pmu.event(x, 3)

def modes_list():
  ms = []
  for x in Conf.keys(): ms += list(Conf[x].keys())
  assert DM in ms
  return list(set(ms))

def parse_args():
  def conf(x): return Conf[x][DM] if DM in Conf[x] else None
  ap = C.argument_parser('study two or more modes (configs)', mask=STUDY_PROF_MASK,
         defs={'events': Conf['Events'][DM], 'toplev-args': conf('Toplev'), 'tune': conf('Tune')})
  ap.add_argument('config', nargs='*', default=[])
  ap.add_argument('--mode', nargs='?', choices=modes_list(), default=DM)
  ap.add_argument('-t', '--attempt', default='1')
  C.add_hex_arg(ap, '-s', '--stages', 0x3f, 'stages in study')
  ap.add_argument('--dump', action='store_const', const=True, default=False)
  ap.add_argument('--advise', action='store_const', const=True, default=False)
  ap.add_argument('--forgive', action='store_const', const=True, default=False)
  ap.add_argument('--smt', action='store_const', const=True, default=False)

  # side-by-side comparison
  description = """
  side-by-side comparison for 2 configs:
    all configs stats are written to *stats.log side by side with diff and ratio, sorted by ratio high to low.
    output includes:
      top & bottom ratios tables after filtering (see description table below).
      table of string stats that differ between configs.
      table of loops with regression in IPC-mode.
    :var stats are excluded
    None or zero stats are excluded by default, use -sa to view them.
    
    top & bottom tables filtering:
      *group*            | *stat description*     | *diff-condition*          | *ratio-condition*     | *comment*
      ==================================================================================================================
      LBR.Glob           | info.log global stat   | >= diff-thresh after      | ratio of all info.log | starts with '[cC]ount of' and includes 'cond'/'inst'/'pairs'
                         |                        | multiplying w/ LBR factor | insts >= lbr-thresh%  |
      LBR.Metric, Metric | metric                 | -                         | -                     | starts with uppercase and doesn't include
      , Info.*           |                        |                           |                       | 'instructions'/'pairs'/'branches'/'insts-class'/'insts-subclass'
      LBR.Event, Event   | event (counter)        | >= diff-thresh            | -                     |
      LBR.Proxy          | info.log proxy stat    | -                         | -                     |
      LBR.Loop           | info.log per-loop stat | -                         | -                     | exclude it with -sl (--skip-loops)
      
  side-by-side args"""
  side_by_side = ap.add_argument_group(description)
  def add_arg(name, default, help):
    l = name.split('-')
    side_by_side.add_argument('-%s%s' % (l[0][0], l[1][0]), '--%s' % name, default=default, type=type(default), help=help)
  side_by_side.add_argument('--loop-id', default='imix-ID', choices=['imix-ID', 'srcline'],
                            help="loop stat to use as loop ID")
  add_arg('diff-threshold', 10000.0, "diff threshold to filter top & bottom tables")
  add_arg('round-factor', 3, "round factor for calculations")
  add_arg('table-size', 10, "top & bottom tables size")
  side_by_side.add_argument('-w', '--table-width', nargs='*', default=[30],
                            help="fields widths in tables, non-specified column will use the final width")
  side_by_side.add_argument('-sl', '--skip-loops', action='store_true',
                            help="skip loops stats")
  side_by_side.add_argument('-sa', '--show-all', action='store_true',
                            help='show stats with None or zero values')
  side_by_side.add_argument('--skip', nargs='*', default=['dsb-heatmap', '_2T', 'topdown-'],
                            help='stats sub-names to skip, e.g. "--skip cond" will skip all stats including "cond"')
  add_arg('lbr-threshold', 0.01, "info.log global stats are included in top & bottom tables "
                                 "if stat/all instructions in info.log > this thresh%%")
  side_by_side.add_argument('-g', '--groups', nargs='+',
                            help="run only for stats of a group with these sub-names, e.g. Bottleneck, Loop, Proxy")
  args = ap.parse_args()
  if args.dump: dump_sample()
  C.printc('mode: %s' % DM)
  def fassert(x, msg): assert x or args.forgive, msg
  assert len(args.config), "at least 2 modes are required"
  fassert(len(args.config) > 1, "at least 2 modes are required (or use --forgive)")
  assert args.app and ' ' not in args.app
  fassert(args.profile_mask & 0x100, 'args.pm=0x%x' % args.profile_mask)
  assert args.repeat > 2, "stats module requires '--repeat 3' at least"
  if DM in ('dsb-align', ): pass
  else: fassert(pmu.v5p(), "PMU version >= 5 is required for COND_[N]TAKEN, USELESS_HWPF events")
  if args.stages & 0x4 and len(args.config) == 2:
    assert sys.version_info >= (3, 0), "stage 4 requires Python 3 or above."
    for element in args.table_width:
      assert int(element) >= 15, "field width in side-by-side must be at least 15"
  return args

args = None
def app(flavor):
  if args.attempt == '-1': return args.app
  return "'%s %s%s'" % (args.app, flavor, ' t%s' % args.attempt if args.attempt.isdigit() else args.attempt)

def compare_stats(app1, app2):
  app1_str, app2_str = C.command_basename(app1), C.command_basename(app2)
  lbr_factor1 = lbr_factor2 = lbr_all_insts1 = lbr_all_insts2 = None
  all_stats = []
  # calculate diff or ratio
  def calc(value1, value2, op='ratio'):
    if not op == 'diff' and not op == 'ratio': return None
    if not value1 and value2 is None: return 'N/A'
    if not value1: return value2
    if value2 is None: return -value1 if op == 'diff' and isinstance(value1, (int, float)) else 'N/A'
    if not isinstance(value1, (int, float)) or not isinstance(value2, (int, float)): return 'N/A'
    return round(value2 - value1, args.round_factor) if op == 'diff' \
      else round(float(value2) / value1, args.round_factor)
  # considers all hiding args: --show-all, --skip and --group
  # removes ':var' stats
  def hide(key, group, value1, value2):
    return (not args.show_all and (not value1 or not value2 or ':var' in key)) or \
           C.any_in(args.skip, key) or (args.groups and (not group or not C.any_in(args.groups, group)))
  # filtering what stats get into top & bottom tables
  # see description in study.py -h
  def filter(key, group, value1, value2, diff, ratio):
    if group == 'LBR.Glob':
      if not lbr_all_insts1 or not lbr_all_insts2: return False
      if (value1 and 100*float(value1)/lbr_all_insts1 < args.lbr_threshold) or \
              (value2 and 100*float(value2)/lbr_all_insts2 < args.lbr_threshold): return False
      if value1: value1 = value1 * lbr_factor1
      if value2: value2 = value2 * lbr_factor2
      diff = calc(value1, value2, op='diff')
    info_metric = group and 'Info' in group and stats.is_metric(key)
    diff_cond = isinstance(diff, (int, float)) and \
                (group and C.any_in(('Metric', 'LBR.Metric', 'LBR.Proxy', 'LBR.Loop'), group)
                 or info_metric or abs(diff) >= args.diff_threshold)
    ratio_cond = isinstance(ratio, (int, float)) and not (not value1 and value2 == 0)
    return diff_cond and ratio_cond
  # filtering what stats get into strings table
  def filter_string(key, group, value1, value2):
    return (isinstance(value1, str) or isinstance(value2, str)) and value1 != value2 and \
        not key == 'app' and not group == 'LBR.Loop' and not group == 'LBR.Histo'
  # line format in tables
  def format_line(k, g, v1, v2, d, r):
    def fv(v): return round(v, args.round_factor) if isinstance(v, (int, float)) else str(v)
    def width(i): return int(args.table_width[i]) if len(args.table_width) > i else int(args.table_width[-1])
    return "{:>{width}}".format(k[-width(0):], width=width(0)) + " | " + \
           "{:>{width}}".format(str(g)[-width(1):], width=width(1)) + " | " + \
           "{:>{width}}".format(fv(v1), width=width(2)) + " | " + \
           "{:>{width}}".format(fv(v2), width=width(3)) + " | " + \
           "{:>{width}}".format(d, width=width(4)) + " | " + \
           "{:>{width}}".format(r, width=width(5))
  def print_list(l):
    print(header)
    print(sep)
    for k, g, v1, v2, d, r in l: print(format_line(k, g, v1, v2, d, r))
    print('\n')
  def get_info_file(app): return stats.get_file(app, 'info')
  def get_value_group(d, k):
    return (d[k][0], d[k][1]) if k in d else (None, None)
  # print table of loops with regressed IPC between configs
  def print_regressed_ipcs():
    loops_num = len([key for key in stats1 if re.search("Loop#[0-9]+ ip", key)])
    regress_ipcs, loops_paired = [], []
    # vars to check if first 10 loops have matching IDs between configs
    ids_to_check, diff_ids = loops_num if loops_num < 10 else 10, 0
    for i1 in range(1, loops_num+1):
      ipc1, group = get_value_group(stats1, 'Loop#%s IPC-mode' % i1)
      if not ipc1: continue
      id = stats1['Loop#%s ID' % i1][0]
      id2 = get_value_group(stats2, 'Loop#%s ID' % i1)[0]
      if i1 <= ids_to_check and id != id2: diff_ids += 1
      if id == id2 and i1 not in loops_paired: i2 = i1
      else:
        i2 = None
        for key in stats2:
          if re.search("Loop#[0-9]+ ID", key) and stats2[key][0] == id:
            n = int(key.split()[0].replace('Loop#', ''))
            if n not in loops_paired:
              i2 = n
              break
      if not i2: continue
      ipc2 = get_value_group(stats2, 'Loop#%s IPC-mode' % i2)[0]
      if ipc2 and ipc1 > ipc2 or args.show_all:
        key = 'Loop:%s #%s #%s IPC-mode' % (id, i1, i2)
        if not C.any_in(args.skip, key):
          regress_ipcs.append((key, group, ipc1, ipc2, calc(ipc1, ipc2, op='diff'), calc(ipc1, ipc2)))
          loops_paired.append(i2)
    if len(regress_ipcs) > 0:
      print("Loops with regressed IPC:")
      print_list(regress_ipcs)
    if ids_to_check and float(diff_ids)/ids_to_check >= 0.5:
      C.warn("Loops seem to be non-matching between configs!")

  # compare_stats() starts here
  C.printc('\tconfigs side-by-side', C.color.BOLD)
  info1, info2 = get_info_file(app1), get_info_file(app2)
  # adding info files stats
  if info1 and info2:
    stats.sDB[app1_str].update(stats.read_info(info1, read_loops=not args.skip_loops, loop_id=args.loop_id))
    stats.sDB[app2_str].update(stats.read_info(info2, read_loops=not args.skip_loops, loop_id=args.loop_id))
    lbr_all_insts_key = stat_name('ALL', ratio_of=('ALL', ))
    lbr_all_insts1, lbr_all_insts2 = stats.get(lbr_all_insts_key, app1), stats.get(lbr_all_insts_key, app2)
    msg = "LBR run & stats aren't complete, check "
    if lbr_all_insts1: lbr_factor1 = float(stats.get('instructions', app1)) / lbr_all_insts1
    else: C.warn(msg + info1)
    if lbr_all_insts2: lbr_factor2 = float(stats.get('instructions', app2)) / lbr_all_insts2
    else: C.warn(msg + info2)
  stats1, stats2 = stats.sDB[app1_str], stats.sDB[app2_str]
  header = format_line('Stat', 'Group', app1, app2, 'Diff', 'Ratio')
  sep = '-' * len(header)
  for key in stats1:
    value1, group = get_value_group(stats1, key)
    value2 = get_value_group(stats2, key)[0]
    if not hide(key, group ,value1, value2):
      all_stats.append((key, group, value1, value2, calc(value1, value2, op='diff'), calc(value1, value2)))
  # passing on elements of stats2 that aren't in stats1
  if args.show_all:
    for key in stats2:
      value2, group = get_value_group(stats2, key)
      if key not in stats1 and not hide(key, group, None, value2):
        all_stats.append((key, group, None, value2, calc(None, value2, op='diff'), calc(None, value2)))
  # sorting stats high to low by ratio
  all_stats.sort(key=lambda item: float(item[5]) if isinstance(item[5], (int, float)) else float('-inf'), reverse=True)
  # generating side-by-side all stats log
  out_file = f"{app1_str}_{app2_str}.stats.log"
  with open(out_file, 'w') as f:
    f.write(header + '\n')
    f.write(sep + '\n')
    for (k, g, v1, v2, d, r) in all_stats: f.write(format_line(k, g, v1, v2, d, r) + '\n')
  print(f"Full side-by-side stats written to '{out_file}'\n")
  # print top and bottom ratios tables after filtering
  filtered_stats = [(k, g, v1, v2, d, r) for k, g, v1, v2, d, r in all_stats if filter(k, g, v1, v2, d, r)]
  if len(filtered_stats) <= args.table_size: top, bottom = filtered_stats, filtered_stats[::-1]
  else:
    bottom = filtered_stats[-args.table_size:][::-1]
    top = filtered_stats[:args.table_size]
  print(f'Top {args.table_size}:')
  print_list(top)
  print(f'Bottom {args.table_size}:')
  print_list(bottom)
  # print diff string stats table
  strings_stats = [(k, g, v1, v2, d, r) for k, g, v1, v2, d, r in all_stats if filter_string(k, g, v1, v2)]
  if len(strings_stats) > 0:
    print('String diffs:')
    print_list(strings_stats)
  # print table of loops with regressed IPC
  if not args.skip_loops: print_regressed_ipcs()

def main():
  do0 = C.realpath('do.py')
  do = do0 + ' profile'
  for x in C.argument_parser(None):
    a = getattr(args, x.replace('-', '_'))
    if a: do += ' --%s %s' % (x, "'%s'" % a if ' ' in a else a)
  if args.repeat != 3: do += ' -r %d' % args.repeat

  x = 'tune'
  a = getattr(args, x) or []
  extra = ' :sample:3' if C.any_in(['dsb', 'misp'], args.mode) else ''
  if args.mode in Conf['Pebs'].keys(): extra += ' :perf-pebs:"\'%s\'" :perf-pebs-top:-1' % Conf['Pebs'][args.mode]
  if pmu.skylake(): extra += ' :perf-stat-add:-1'
  elif args.mode != 'imix-loops': extra += ' :perf-stat-add:0'
  a.insert(0, [':batch:1 :help:0 :lbr-jcc-erratum:1 :loops:%d :msr:1 :dmidecode:1%s ' % (
    int(pmu.cpu('corecount')/2), extra)])
  do += ' --%s %s' % (x, ' '.join([' '.join(i) for i in a]))

  if args.verbose > 1: do += ' -v %d' % (args.verbose - 1)
  elif args.verbose == -1: do += ' --print-only'
  do = do.replace('{', '"{').replace('}', '}"')
  def exe(c): return C.exe_cmd(c, debug=args.verbose)
  def do_cmd(c): return do.replace('profile', c).replace('batch:1', 'batch:0')

  C.fappend(' '.join([C.env2str(x, '', x) for x in ('STUDY_MODE', 'TMA_CPU', 'EVENTMAP')
                      ] + sys.argv + ['# version %.2f' % __version__]), '.study.cmd')
  if args.stages & 0x1:
    enable_it=0
    if not args.smt and pmu.cpu('smt-on'):
      exe('%s disable-smt disable-aslr -v1' % do0)
      enable_it=1
    if args.stages & 0x8: exe(do_cmd('version log'))
    if args.profile_mask == STUDY_PROF_MASK and C.any_in(('misp', 'dsb'), args.mode): args.profile_mask |= 0x200
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
      compare_stats(app(bef), app(aft))

  if args.stages & 0x10:
    if args.stages & 0x2: time.sleep(60)
    exe(' '.join((do_cmd('tar'), '-a', args.app)))

  if args.stages & 0x20:
    for x in args.config:
      exe(' '.join((do_cmd('analyze'), '-a', app(x))))

if __name__ == "__main__":
  args = parse_args()
  main()
