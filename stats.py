#!/usr/bin/env python3
# Copyright (c) 2020-2023, Intel Corporation
# Author: Ahmad Yasin
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT # ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# A module for handling counters and profiling logs
# A stat is any of: counter, metric
#
from __future__ import print_function
__author__ = 'ayasin'
__version__= 0.53

import common as C
import re, os.path

def get_stat_log(s, perf_stat_file):
  repeat = re.findall('.perf_stat-r([1-9]).log', perf_stat_file)[0]
  return get_stat_int(s, perf_stat_file.replace('.perf_stat-r%s.log' % repeat, ''), perf_stat_file)

def get(s, app):
  return get_stat_int(s, C.command_basename(app))

def print_metrics(app):
  c = C.command_basename(app)
  rollup(c)
  return print_DB(c)

# internal methods
def get_stat_int(s, c, val=-1, stat_file=None):
  rollup(c, stat_file)
  try:
    val = sDB[c][s]
  except KeyError:
    C.warn('KeyError for stat: %s, in config: %s' % (s, c))
  return val

debug = 0
sDB = {}
def rollup(c, perf_stat_file=None):
  if c in sDB: return
  if not perf_stat_file: perf_stat_file = c + '.perf_stat-r3.log'
  # TODO: call do.profile to get file names
  sDB[c] = read_perf(perf_stat_file)
  sDB[c].update(read_toplev(c + '.toplev-vl6.log'))
  sDB[c].update(read_toplev(c + '.toplev-mvl2.log'))
  if debug: print_DB(c)

def print_DB(c):
  d = {}
  for x in sDB[c].keys():
    if x.endswith(':var') or x.startswith('topdown-') or '.' in x or x in ['branch-misses']: continue
    v = sDB[c][x]
    if x in read_perf(None): v = float('%.2f' % v)
    val = '%18s' % C.float2str(v) if C.is_num(v) else v
    if x+':var' in sDB[c] and sDB[c][x+':var']: val += ' +- %s%%' % sDB[c][x+':var']
    d['%30s' % x] = val
  print(c, '::\n', C.dict2str(d, '\t\n').replace("'", ""))
  return d

def read_perf(f):
  d = {}
  def calc_metric(e, v=None):
    if e == None: return ['IpMispredict', 'IpUnknown_Branch', 'L2MPKI_Code', 'UopPI']
    if not 'instructions' in d: return None
    inst = float(d['instructions'])
    if e == 'branch-misses': d['IpMispredict'] = inst / v
    if e == 'r0160': d['IpUnknown_Branch'] = inst / v
    if e == 'r2424': d['L2MPKI_Code'] = 1000 * val / inst
    if e == 'topdown-retiring': d['UopPI'] = v / inst
  if f == None: return calc_metric(None) # a hack!
  if debug > 2: print('reading %s' % f)
  lines = C.file2lines(f)
  if len(lines) < 5: C.error("invalid perf-stat file: %s" % f)
  for l in lines:
    if debug > 3: print('debug:', l)
    try:
      name, val, var, name2, val2, name3, val3 = parse(l)
      if name:
        d[name] = val
        d[name+':var'] = var
        calc_metric(name, val)
      if name2: d[name2] = val2
      if name3: d[name3] = val3
    except ValueError or IndexError:
      C.warn("cannot parse: '%s' in %s" % (l, f))
  if debug > 1: print(d)
  return d

def parse(l):
  Renames = {'insn-per-cycle': 'IPC',
             'GHz': 'Frequency'}
  def get_var(i=1): return float(l.split('+-')[i].strip().split('%')[0]) if '+-' in l else None
  items = l.strip().split()
  name, val, var, name2, val2, name3, val3 = None, -1, None, None, -1, None, -1
  if not re.match(r'^[1-9 ]', l): pass
  elif 'Performance counter stats for' in l:
    name = 'App'
    val = l.split("'")[1]
    name2 = '#-runs'
    val2 = int(l.split("(")[1].split(' ')[0])
  elif 'time elapsed' in l:
    name = 'time'
    val = float(items[0])
    var = get_var(2)
  elif '#' in l:
    name_idx = 2 if '-clock' in l else 1
    name = items[name_idx]
    val = items[0].replace(',', '')
    val = float(val) if name_idx == 2 else int(val)
    var = get_var()
    metric_idx = name_idx + 3
    if name == 'cycles:k': pass
    elif l.count('#') == 2: # TMA-L2 metrics of Golden Cove
      val2 = float(items[name_idx+2].replace('%', ''))
      val3 = float(items[name_idx+6].replace('%', ''))
      name2 = ' '.join(items[metric_idx:metric_idx+2]).title()
      name3 = ' '.join(items[metric_idx+4:metric_idx+6]).title()
    elif not C.any_in(('/sec', 'of'), items[metric_idx]):
      val2 = items[name_idx + 2]
      name2 = '-'.join(items[metric_idx:]).split('(')[0][:-1]
      if '%' in val2:
        val2 = val2.replace('%', '')
        name2 = name2.replace('-', ' ').title()
      elif name2 in Renames: name2 = Renames[name2]
      val2 = float(val2)
  return name, val, var, name2, val2, name3, val3

# Should move this to a new analysis module
Key2group = {
  'BAD':      'Bad',
  'BE':       None,
  'BE/Core':  'Cor',
  'BE/Mem':   'Mem',
  'FE':       'Fed',
  'RET':      'Ret',
}

def read_toplev(filename, metric=None):
  d = {}
  if debug > 2: print('reading %s' % filename)
  assert os.path.exists(filename), 'file does not exist: %s' % filename
  for l in C.file2lines(filename):
    try:
      if not re.match(r"^(FE|BE|BAD|RET|Info)", l): continue
      items = l.strip().split()
      if debug > 3: print('debug:', len(items), items, l)
      if 'Info.Bot' in items[0]:
        d[items[1]] = float(items[3])
      elif '<==' in l:
        d['Critical-Group'] = Key2group[ items[0] ]
        d['Critical-Node'] = items[1]
      else:
        for m in ('IpTB', 'UopPI'):
          if m in items[1]: d[items[1]] = float(items[3])
    except ValueError:
      C.warn("cannot parse: '%s'" % l)
    except AttributeError:
      C.warn("empty file: '%s'" % filename)
  if debug > 1: print(d)
  if metric:
    r = d[metric] if metric in d else None
    if debug: print('stats.read_toplev(filename=%s, metric=%s) = %s' % (filename, metric, str(r)))
    return r
  return d
