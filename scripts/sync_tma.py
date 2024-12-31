#!/usr/bin/env python3
# Sync TMA support in perf-tools
# Author: Ahmad Yasin
# December 2024

# TODO: perf-tools
# - enable bottlenecks-view by default
# - generalize & assert bot-levels == 5 in this release
# - modernize arguments; convert C.arg* to argparser
from __future__ import print_function
__author__ = 'ayasin'
__version__ = 0.51

import os, re, sys

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/..')
import common as C, pmu, tma

if sys.version_info[0] < 3:
  raise Exception("Must be using Python 3")

def exe(x): return C.exe_cmd(x, debug=1)

def gen_perf(emon, to='settings/bottlenecks'):
  assert os.path.isfile(emon)
  name = emon.split('/')[2].split('_')
  # ../SPR_TMA_emon_min_groups.cfg
  assert name[3] == 'min'
  model = name[0]
  group = ''
  groups = []
  fixed = tma.fixed_metrics()[0]
  # 4.8: (tma.fixed_metrics(True) if model in ('ICX', 'TGL') else tma.fixed_metrics(True, True))[0]
  for l in C.file2lines(emon):
    if re.match(r'^([#\-)]|UNC)', l): continue
    if re.match(r'^$', l):
      group += '}'
      if len(group) > 1: groups += [group]
      group = ''
    else:
      x = re.match(r'^([^,]+),', l)
      assert x, '#%s#' % l
      event = x.group(1)
      if C.any_in(pmu.fixed_events(True), event): continue
      if not len(group): group = '{'+C.chop(fixed, '{}')
      group = ','.join((group, event))
  if len(groups):
    out = '%s/%s.txt' % (to, model)
    with open(out, 'w') as f:
      f.write('\n'.join(groups))
      print('wrote: ', out)

def main(comm):
  R = C.env2str('TRC_AREA', 'ayasin@10.184.76.216:/nfs/site/home/ayasin/r')
  if comm.startswith('copy'):
    B = C.arg(4)
    assert B, "must provide 4 args: copy version subversion bott[012]"
    full = "%s/%s/%s/full/%s/full" % (R, C.arg(2), C.arg(3), B)
    if comm == 'copy':
      exe(f'mkdir ../{B} && scp "{full}/*min_groups.cfg" ../{B}')
    elif comm == 'copy-csv':
      exe(f'scp "{full}/{{multi_group_metrics.txt,ZeroOk_metrics.txt}}" ..') 
      exe('dos2unix ../*metrics.txt && '
                'mv ../multi_group_metrics.txt settings/tma-many-counters.csv && '
                'mv ../ZeroOk_metrics.txt settings/tma-zero-ok.csv')
  elif comm == 'bott-all':
    B = C.arg(2)
    assert B, "must provide 2 args: bott-all bott[012]"
    for c in C.glob(f'../{B}/*min_groups.cfg'): gen_perf(c)
  elif comm == 'bott-one':
    gen_perf('../%s_TMA_emon_min_groups.cfg' % C.arg(2))
  elif comm == 'bott.1': # e.g. DS=1
    for c in C.glob('../bott1/*min_groups.cfg'): gen_perf(c, to='settings/bottlenecks.1')
  elif comm == 'pre':
      update_TMA(int(C.arg(2)))
  elif comm == 'post':
      test()
  elif comm == 'bott':
      update_bott()

def update_bott():
  sample = """Here is a sample:
scripts/sync_tma.py copy 5.0 922 bott0
scripts/sync_tma.py copy-csv 5.0 922 bott0
scripts/sync_tma.py bott-all bott0
    """
  print('To update settings/bottlenecks/, set TRC_AREA and run sync_tma with desired versions.\n' + sample)

def update_TMA(pmu_tools=True):
  if pmu_tools:
    exe('cp -r pmu-tools pmu-tools.x')
    exe('./do.py tools-update:0x10')
  assert pmu.goldencove()
  assert pmu.server()
  # tma.py : dict: version, # mux groups
  tma_settings = 'settings/tma.csv'
  exe("grep ^# run-mem-bw.toplev-mvl6-nomux.log | head -1 | cut -d' ' -f-2 | sed 's/#/version/;s/ /,/g' > " + tma_settings)
  exe("grep ^RUN run-mem-bw.toplev-mvl6-nomux.log | tail -1 | cut -d' ' -f-2 | sed 's/#//;s/RUN/num-mux-groups/;s/ /,/g' >> " + tma_settings)
  C.fappend('num-levels,6', tma_settings)
  exe("head " + tma_settings)
  # settings/bottlenecks/*
  update_bott()
  return 0

def test():
  exe('make test-pmu-tools')
  exe('make test-pmu-tools PMUTOOLS=%s/pmu-tools.x' % C.dirname())
  return None

if __name__ == "__main__":
  main(C.arg(1, 'no'))

