#!/usr/bin/env python3
# A module for handling counters and profiling logs
# Author: Ahmad Yasin
# edited: Oct 2022
# A stat is any of: counter, metric
#
from __future__ import print_function
__author__ = 'ayasin'

import common as C
import re

debug = 0
sDB = {}
def rollup(c, perf_stat_file=None):
  if c in sDB: return
  if not perf_stat_file: perf_stat_file = c + '.perf_stat-r3.log'
  # TODO: call do.profile to get file names
  sDB[c] = read_perf(perf_stat_file)
  sDB[c].update(read_toplev(c + '.toplev-vl6.log'))
  if debug: print(c, sDB[c])

def get_stat_int(s, c, val=-1):
  rollup(c)
  try:
    val = sDB[c][s]
  except KeyError:
    C.warn('KeyError for stat: %s, in config: %s' % (s, c))
  return val

def get_stat_log(s, perf_stat_file):
  repeat = re.findall('.perf_stat-r([0-9]+).log', perf_stat_file)[0]
  print(perf_stat_file, repeat)
  return get_stat_int(s, perf_stat_file.replace('.perf_stat-r%s.log' % repeat, ''))

def get(s, app):
  print('get::', s, app, C.command_basename(app))
  return get_stat_int(s, C.command_basename(app))

def read_perf(f):
  d = {}
  if debug: print(f)
  for l in C.file2lines(f, fail=True):
    try:
      name, val, var, met, mval = parse(l)
      if name:
        d[name] = val
        d[name+':var'] = var
        if name == 'r2424': d['L2MPKI_Code'] = 1000 * val / d['instructions']
      if met: d[met] = mval
    except ValueError:
      C.warn("cannot parse: '%s' in %s" % (l, f))
  if debug > 2: print(d)
  return d

def parse(l):
  Renames = {'insn-per-cycle': 'IPC',
             'GHz': 'Frequency'}
  def get_var(i=1): return float(l.split('+-')[i].strip().split('%')[0]) if '+-' in l else None
  items = l.strip().split()
  name, val, var, met, mval = None, -1, -1, None, -1
  if 'time elapsed' in l:
    name = 'time'
    val = float(items[0])
    var = get_var(2)
  elif '#' in l:
    name_idx = 2 if 'cpu-clock' in l else 1
    name = items[name_idx]
    val = items[0].replace(',', '')
    val = float(val) if name_idx == 2 else int(val)
    var = get_var()
    metric_idx = name_idx + 3
    if name == 'cycles:k': pass
    elif not C.any_in(('/sec', 'of'), items[metric_idx]):
      mval = items[name_idx + 2]
      met = '-'.join(items[metric_idx:]).split('(')[0][:-1]
      if '%' in mval:
        mval = mval.replace('%', '')
        met = met.replace('-', ' ').title()
      elif met in Renames: met = Renames[met]
      mval = float(mval)
  return name, val, var, met, mval

def read_toplev(f):
  d = {}
  if debug: print(f)
  try:
    for l in C.file2lines(f):
      items = l.strip().split()
      if items[0].startswith('Info.B'):
        d[items[1]] = float(items[3])
  except ValueError:
    C.warn("cannot parse: '%s'" % l)
  except AttributeError:
    C.warn("empty file: '%s'" % f)
  if debug > 1: print(d)
  return d