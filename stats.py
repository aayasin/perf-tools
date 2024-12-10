#!/usr/bin/env python3
# Copyright (c) 2020-2024, Intel Corporation
# Author: Ahmad Yasin
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# A module for handling counters and profiling logs
# A stat is any of: counter, metric
#
from __future__ import print_function
__author__ = 'ayasin'
__version__= 1.06

import common as C, pmu, tma
import csv, json, os.path, re, sys

# FIXME:01: add a "namer" module to assign filename for all logs;
#       to replace this function, so analyze.ext() can call it directly, many in do.py, and
#       to replace other instances of finding filename below:
#         get_stat_log()
#         get_TSC()
#         rollup_all()
#         rollup() (start and toward end)
#         return from csv2stat() which removed common.toplev_log2csv too!
def get_file(app, ext): return get_file_int(C.command_basename(app), '.perf.data.' + ext)

def get_stat_log(s, perf_stat_file):
  repeat = re.findall('.perf_stat-r([1-9]).log', perf_stat_file)[0]
  return get_stat_int(s, perf_stat_file.replace('.perf_stat-r%s.log' % repeat, ''), perf_stat_file)

def get(s, app):
  return get_stat_int(s, C.command_basename(app))

def get_val(s, c):
  val = None
  try:
    val = sDB[c][s][0]
  except KeyError:
    if s in tma.estimate(None, None):
      val = tma.estimate(s, strip(sDB[c]))
      sDB[c][s] = (val, 'Bottleneck')
    else: C.warn('KeyError for stat: %s, in config: %s' % (s, c))
  if debug > 0: print('stats: get_val(%s, %s) = %s' % (s, c, str(val)))
  return val

def strip(d): return {k: v[0] for k, v in d.items()}

def print_metrics(app):
  c = C.command_basename(app)
  rollup(c)
  return print_DB(c)

def write_stat(app): return csv2stat(C.command_basename(app) + '.toplev-vl6-perf.csv')

debug = C.env2int('STATS_DBG')
sDB = {}
stats = {'verbose': 0}

# internal methods
def get_file_int(prefix, ext):
  for filename in C.glob(prefix + '*', True):
    if re.search("%s-janysave_type-e([a-z0-9_]+)ppp-c([0-9]+)(\-a)?%s.log" % (prefix, ext), filename):
      return filename
  return None

def get_stat_int(s, c, stat_file=None, val=-1):
  if not c in sDB and stat_file and s in ('CPUs_Utilized', ): return read_perf(stat_file)[s][0]
  rollup(c, stat_file)
  return get_val(s, c)

def rollup_all(stat=None):
  sDB['ALL'], csv_file, reload = {}, 'rollup.csv', None 
  for a in sys.argv[1:]:
    if not reload:
      reload = re.findall("-janysave_type-er20c4ppp-c([0-9]+).perf.data.info.log", a)
    c = a.replace("-janysave_type-er20c4ppp-c%s.perf.data.info.log" % reload, "")
    sDB[c] = {}
    d = read_info(a)
    sDB[c].update(d)
    for s in d.keys():
      if s in sDB['ALL']: sDB['ALL'][s] += d[s]
      else: sDB['ALL'][s] = d[s]
    if stat: return sDB['ALL'][stat]
  import pandas as pd
  df = pd.DataFrame(sDB)
  df.to_csv(csv_file)
  print('wrote:', csv_file)
  print(C.dict2str(sDB['ALL']))

def convert(v, adjust_percent=True):
  if not type(v) is str: return v
  v = v.strip()
  m = 1
  if v.startswith('-'):
    m = -1
    v = v.lstrip('-')
  if v.isdigit(): return m * int(v)  # e.g. 13
  if v.replace('.', '', 1).isdigit(): return m * float(v)  # e.g. 1.13
  v2 = v.replace(',', '')
  if v2.isdigit() or v2.replace('.', '', 1).isdigit(): return m * convert(v2)  # e.g. 12,122,321 -> 12122321
  if '%' in v:  # e.g. 1.3% -> 1.3 or 0.013
    v = float(v.replace('%', ''))
    return v / 100 if adjust_percent else v
  return str(v)

def file2lines(f, pop=False): return C.file2lines(f, fail=True, pop=pop, debug=debug > 3)
def open_r(f): return C.open_r(f, debug=debug > 3)

def read_loops_info(info, loop_id='imix-ID', as_loops=False, sep=None, groups=True):
  assert os.path.isfile(info), 'Missing file: %s' % info
  d = {}
  loops = C.exe_output(C.grep('Loop#', info), sep='\n')
  if loops != '':  # loops stats found
    for loop in loops.split('\n'):
      if loop_id == 'srcline' and 'srcline:' not in loop:
        C.warn('Must run with srcline for loops stats, run with --tune :srcline:1')
        break
      key = loop.split(':')[0].strip()
      loop_attrs = re.split(r',(?![^\[]*\])', loop[loop.index('[') + 1:-1])
      if as_loops: d[key] = {}
      for attr in loop_attrs:
        attr_list = attr.split(':')
        stat, val = attr_list[0].strip(), convert(attr_list[1].strip())
        stat_name = 'ID' if loop_id == stat else stat
        if as_loops: d[key][stat_name] = val
        else: d['%s%s%s' % (key, sep if sep else ' ', stat_name)] = (val, 'LBR.Loop') if groups else val
  return d

def read_funcs_info(log, as_funcs=False, sep=None, groups=True):
  assert os.path.isfile(log), 'Missing file: %s' % log
  d = {}
  funcs = C.exe_output(C.grep('function#', log), sep='\n')
  if funcs != '':  # funcs stats found
    for func in funcs.split('\n'):
      key = func.split(':')[0].strip()
      # FIXME:05: extract flows properly
      func_attrs = re.split(r',', func[func.index('{') + 1:-1])
      if as_funcs: d[key] = {}
      for attr in func_attrs:
        attr_list = attr.split(':')
        stat, val = attr_list[0].strip(), convert(attr_list[1].strip())
        if as_funcs: d[key][stat] = val
        else: d['%s%s%s' % (key, sep if sep else ' ', stat)] = (val, 'LBR.func') if groups else val
      # FIXME:06: read flows themselves into func dictionary
  return d

def grep_histo(histo, info):
  return C.grep_start_end('%s histogram:' % histo, '%s histogram summary' % histo, info)

def is_metric(s):
  return s[0].isupper() and not s.isupper() and \
         not s.lower().endswith(('instructions', 'pairs', 'branches', 'insts-class', 'insts-subclass'))

def read_histos(info, as_histos=False, groups=False):
  d = {}
  histo = None
  g = 'LBR.Histo'
  def add(k, v):
    if as_histos:
      if histo not in d: d[histo] = {}
      d[histo][k] = v
    else: d[k] = (v, g) if groups else v
  def rgx(): return histo == 'inst-per-leaf-func-name'
  for l in file2lines(info):
    if 'IPC histogram of' in l: break  # stops upon detailed loops stats
    if 'WARNING' in l: pass
    if debug > 5: print('debug:', l)
    l = l.strip()
    if 'histogram:' in l:  # histogram start
      histo = '%s' % l.split()[0].replace(C.color.DARKCYAN, '')
      continue
    if 'summary:' in l:  # histogram end
      if rgx(): # FIXME:07 this code doesn't work for a study on permute workload
        histo = None
        continue
      if not histo: histo = l.split()[0]
      l_list = l.split('{')[1][:-1].split(',')
      for e in l_list:
        e_list = re.split(r'(?<!:):(?!:)', e) if rgx() else e.split(':')
        k = e_list[0].strip()
        v = convert(e_list[1].strip())
        if not as_histos: k = '%s%s_%s' % ((g + '.') if not groups else '', histo, k)
        add(k, v)
      histo = None
      continue
    if histo:  # histogram line
      l_list = re.split(r'\s{2,}', l) if rgx() and 'other' not in l else l.split()
      k = l_list[0]
      if k == 'IPC': continue # skip IPC histo header
      k = k[:-1]
      if not as_histos: k = '%s%s_[%s]' % ((g + '.') if not groups else '', histo, k)
      v = convert(l_list[1])
      add(k, v)
  return d

def read_info(info, read_loops=False, loop_id='imix-ID', sep=None, groups=True):
  d = {}
  for l in file2lines(info):
    if 'histogram' in l: break  # stops upon global histograms
    s = v = None
    g = 'LBR.'
    if 'WARNING' in l: pass
    elif re.findall('([cC]ount|estimate) of', l):
      l = l.split(':')
      s = l[0].strip()#' '.join(l[0].split()) # re.sub('  +', ' ', l[0])
      if sep: s = C.chop(re.sub(r'[\s\-]+', sep, s))
      v = convert(l[1])
    if not v is None:
      if groups and g == 'LBR.':
        if re.search('([cC]ount) of', s) and C.any_in(['cond', 'inst', 'pairs'], s):
          g += 'Glob'
        elif is_metric(s): g += 'Metric'
        elif s.startswith('proxy count'): g += 'Proxy'
        else: g += 'Event'
      d[s] = (v, g) if groups else v
  d.update(read_histos(info, groups=groups))
  if read_loops: d.update(read_loops_info(info, loop_id, sep=sep, groups=groups))
  return d

def rollup(c, perf_stat_file=None):
  if c in sDB: return
  perf_stat_file, info, vl6 = perf_stat_file or c + '.perf_stat-r3.log', c + '.toplev-mvl2.log', c + '.toplev-vl6.log'
  perf_stat_lbr = get_file_int(c + '.perf_stat', '')
  sDB[c] = read_perf(perf_stat_file) if C.isfile(perf_stat_file) else {}
  if C.isfile(vl6): sDB[c].update(read_toplev(vl6))
  elif C.isfile(perf_stat_lbr): sDB[c].update(read_perf(perf_stat_lbr))
  if C.isfile(info):
    sDB[c].update(read_toplev(info))
    sDB[c]['sig-misp'] = (read_mispreds(info.replace('.info', '.mispreds')), 'list')
  if debug > 1: print_DB(c)

def read_mispreds(mispreds_file, sig_threshold=1.0):
  misp, sig = file2lines(mispreds_file, pop=True), []
  while len(misp):
    b = C.str2list(misp.pop())
    val = b[0][:-1]
    if not C.is_num(val) or float(val) < sig_threshold: break
    sig += [b[3].lstrip('0')]
  return sig

def print_DB(c):
  d = {}
  for x in sDB[c].keys():
    if x.endswith(':var') or x.startswith('topdown-') or '.' in x or x in ['branch-misses']: continue
    v = sDB[c][x][0]
    if not v and not stats['verbose']: continue
    if x in read_perf(None): v = float('%.2f' % v)
    val = '%18s' % C.float2str(v) if C.is_num(v) else v
    if x+':var' in sDB[c]: val += ' +- %s%%' % sDB[c][x+':var'][0]
    d['%30s' % x] = val
  print(c, '::\n', C.dict2str(d, '\t\n').replace("'", ""), sep='')
  return d

def get_TSC(f):
  tsc = read_perf(f.replace('.log', '-C0.log'))['msr/tsc/'][0]
  # FIXME:02: support apart from -r3 or -r1
  if f.endswith('-r3.log'): tsc = int(tsc / 3)
  return tsc

def read_perf(f):
  d = {}
  def calc_metric(e, v=None):
    if e == None: return ['IpMispredict', 'IpUnknown_Branch', 'L2MPKI_Code', 'UopPI']
    if not 'instructions' in d: return None
    inst = convert(d['instructions'][0])
    group = 'Metric'
    if e == 'branch-misses': d['IpMispredict'] = (inst / v, group)
    if e == 'r0160': d['IpUnknown_Branch'] = (inst / v, group)
    if e == 'r2424': d['L2MPKI_Code'] = (1000 * val / inst, group)
    if e == 'topdown-retiring': d['UopPI'] = (v / inst, group)
    if e == 'ref-cycles':
      d['TSC'] = (get_TSC(f), 'Event')
      d['CPUs_Utilized'] = (v / d['TSC'][0], group)
    if e == 'L2_LINES_OUT.SILENT': d['Useless_HWPF'] = (
      d['L2_LINES_OUT.USELESS_HWPF'][0] / (d['L2_LINES_OUT.SILENT'][0] + d['L2_LINES_OUT.NON_SILENT'][0]), group)
  if f is None: return calc_metric(None) # a hack!
  lines = file2lines(f)
  if len(lines) < 5: C.error("invalid perf-stat file: %s" % f)
  for l in lines:
    if 'atom' in l: continue
    try:
      name, group, val, var, name2, group2, val2, name3, group3, val3 = parse_perf(l)
      if name:
        if name.startswith('cpu_core/'): name = name[9:-1]
        d[name] = (val, group)
        if var: d[name + ':var'] = (var, group)
        calc_metric(name, val)
      if name2: d[name2] = (val2, group2)
      if name3: d[name3] = (val3, group3)
    except ValueError or IndexError:
      C.warn("cannot parse: '%s' in %s" % (l, f))
  if debug > 2: print(d)
  return d

Renames = {'insn-per-cycle': 'IPC',
           'GHz': 'Frequency'}
def parse_perf(l):
  if debug > 5: print('debug:', l)
  multirun = '+-' in l
  def get_var(i=1): return float(l.split('+-')[i].strip().split('%')[0]) if multirun else None
  items = l.strip().split()
  name = name2 = name3 = group = group2 = group3 = var = None
  val = val2 = val3 = -1
  def get_group(n): return 'Metric' if is_metric(n) else 'Event'
  if not re.match(r'^\s*[0-9P]', l) or len(items) == 1: pass
  elif 'Performance counter stats for' in l:
    name = 'app'
    val = l.split("'")[1]
    if 'runs)' in l:
      name2 = '#-runs'
      val2 = int(l.split("(")[2 if 'CPU' in l else 1].split(' ')[0]) if '(' in l else 1
  elif 'seconds' in l:
    name = items[4 if multirun else 2]
    val = convert(items[0])
    var = get_var(2)
  else:
    name_idx = 2 if '-clock' in l else 1
    name = items[name_idx]
    if name.count('_') >= 1 and name.islower() and not name.startswith(('cpu_core/', 'perf_metrics', 'unc_', 'sys')): # hack ocperf lower casing!
      base_event = name.split(':')[0]
      Name = name.replace(base_event, pmu.toplev2intel_name(base_event))
      assert ':C1' not in Name # Name = Name.replace(':C1', ':c1')
      if stats['verbose']: print(name, '->', Name)
      name = Name
    group = get_group(name)
    val = convert(items[0])
    var = get_var()
    metric_idx = name_idx + 3
    if name == 'cycles:k' or l.count('#') == 0: pass
    elif l.count('#') == 2: # TMA-L2 metrics of Golden Cove
      val2 = convert(items[name_idx+2], adjust_percent=False)
      val3 = convert(items[name_idx+6], adjust_percent=False)
      name2 = ' '.join(items[metric_idx:metric_idx+2]).title()
      name3 = ' '.join(items[metric_idx+4:metric_idx+6]).title()
    elif not C.any_in(('/sec', 'of'), items[metric_idx]):
      val2 = items[name_idx + 2]
      name2 = '-'.join(items[metric_idx:])
      if multirun: name2 = name2.split('(')[0][:-1]
      if '%' in val2: name2 = name2.title()
      elif name2 in Renames: name2 = Renames[name2]
      val2 = convert(val2, adjust_percent=False)
      name2 = name2.replace('-', '_')
  if name2: group2 = get_group(name2)
  if name3: group3 = get_group(name3)
  if debug > 6: print('debug:', name, group, val, var, name2, group2, val2, name3, group3, val3)
  return name, group, val, var, name2, group2, val2, name3, group3, val3

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
  for l in file2lines(filename):
    try:
      if not re.match(r"^(|core )(FE|BE|BAD|RET|Bottleneck|Info|warning.*zero)", l): continue
      l = l.replace('% ', '%_')
      items = l.strip().split()
      if debug > 5: print('debug:', len(items), items, l)
      if items[0] == 'core': items.pop(0)
      if l.startswith('warning'):
        d['zero-counts'] = (l.split(':')[2].strip(), None)
      elif 'Uncore_Frequency' not in l:
        name, group = items[1], items[0]
        if not l.startswith('Info') and not l.startswith('Bottleneck'):
          name, group = items[1].split('.')[-1], 'TMA'
        d[name] = (convert(items[3]), group)  # (value, group)
        if '<==' in l:
          d['Critical-Group'] = (Key2group[items[0]], None)
          d['Critical-Node'] = (items[1], None)
    except ValueError:
      C.warn("cannot parse: '%s'" % l)
    except AttributeError:
      C.warn("empty file: '%s'" % filename)
  if debug > 2: print(d)
  if metric:
    r = d[metric][0] if metric in d else None
    if debug > 0: print('stats: read_toplev(filename=%s, metric=%s) = %s' % (filename, metric, str(r)))
    return r
  return d

def read_perf_toplev(filename):
  perf_fields_tl = ['Timestamp', 'CPU', 'Group', 'Event', 'Value', 'Perf-event', 'Index', 'STDDEV', 'MULTI', 'Nodes']
  d = {'num_zero_stats': 0, 'num_not_counted_stats': 0, 'num_not_supported_stats': 0}
  with open_r(filename) as csvfile:
    reader = csv.DictReader(csvfile, fieldnames=perf_fields_tl, delimiter=';')
    for r in reader:
      if r['Event'] in ('Event', 'dummy', 'msr/tsc/'): continue
      if debug > 6: print('debug:', r)
      x = r['Event']
      if '<not counted>' in r['Value']:
        d['num_not_counted_stats'] += 1
        continue
      if '<not supported>' in r['Value']:
        d['num_not_supported_stats'] += 1
        continue
      v = int(float(r['Value']))
      if v == 0: d['num_zero_stats'] += 1
      elif x == 'duration_time':
        x = 'DurationTimeInMilliSeconds'
        v = float(v/1e6)
        d[x] = v
        continue
      elif '.' in x or any(x.startswith(p) for p in ['cpu/topdown-', 'cycles', 'unc_']): pass
      else: C.printf("unrecognized Event '%s' in reading %s\n" % (r['Event'], filename))
      b = re.match(r"[a-zA-Z\.0-9_]+:?", x).group(0)
      for i in (b, ':sup', ':user'): x = x.replace(i, i.upper())
      if v == 0 and x in d and d[x] != 0: C.warn('skipping zero override in: ' + str(r), level=1)
      else: d[x] = v
  return d

def read_retlat_json(filename):
  d = {}
  if debug > 3: print('reading %s' % filename)
  with open_r(filename) as file:
    data = json.load(file)
    for e in data['Data'].keys():
      d[e + '__retire_latency_MEAN'] = data['Data'][e]['MEAN']
  return d

def patch_metrics(d):
  SLOTS = 'TOPDOWN.SLOTS'
  if SLOTS not in d: return {}
  slots = d[SLOTS]
  del d[SLOTS]
  d[SLOTS + ':perf_metrics'] = slots
  fields = ['BACKEND_BOUND', 'FRONTEND_BOUND', 'RETIRING', 'BAD_SPECULATION']
  l2map = (('MEMORY_BOUND', 'mem-bound'), ('FETCH_LATENCY', 'fetch-lat'), ('HEAVY_OPERATIONS', 'heavy-ops'),
           ('BRANCH_MISPREDICTS', 'br-mispredict'))
  for (x, y) in l2map:
    if 'PERF_METRICS.' + x in d or 'perf_metrics_'+x.lower() in d: fields += [x]
  p = 'cpu/topdown-'.upper()
  if p + 'fetch-lat/'.upper() in d:
    for (x, y) in l2map:
      k = '%s%s/' % (p, y.upper())
      if k in d:
        d['PERF_METRICS.' + x] = d[k]
        fields += [x]
        del d[k]
  for k in fields:
    m = n = 'PERF_METRICS.' + k
    if m not in d:
      n = m.lower().replace('.', '_')
    d[m] = int(255.0 * d[n] / slots)
    if m != n: del d[n]
  return d

def csv2stat(filename):
  if not filename.endswith('.csv'): C.error("Expecting csv format: '%s'" % filename)
  d = read_perf_toplev(filename)
  NOMUX = 'vl6-nomux-perf.csv'
  def nomux(): return filename.endswith(NOMUX)
  def basename():
    x = re.match(r'.*(\.toplev\-[m]?vl\d(\-nomux)?\-perf\.csv)', filename)
    if not x: C.error('stats.csv2stat(): unexpected filename: %s' % filename)
    return filename.replace(x.group(1), '')
  d = patch_metrics(d)
  base = basename()
  retlat = base + '-retlat.json'
  if os.path.isfile(retlat): d.update(read_retlat_json(retlat))
  tl_info = base + '.toplev-mvl2-perf.csv'
  if not nomux():
    if not os.path.isfile(tl_info): C.warn('file is missing: ' + tl_info)
    else: d.update(read_perf_toplev(tl_info))
  # add info.log globals stats
  info = r"%s-janysave_type-er20c4ppp-c([0-9]+)\.perf\.data\.info\.log" % (basename()[:-1])
  info_files = [f for f in os.listdir() if re.match(info, f)]
  if len(info_files):
    info = info_files[0]
    if len(info_files) > 1:
      C.warn('multiple info.log files exist for same app, %s will be added to .stat file' % info)
    d.update(read_info(info, sep='_', groups=False))
  return perf_log2stat(base + '.perf_stat-r3.log', read_toplev(C.toplev_log2csv(filename), 'SMT_on'), d)

def perf_log2stat(log, smt_on, d={}):
  suff = re.findall('(.perf_stat(-B)?-r[1-9].log)', log)[0]
  base, bottlenecks = log.replace(suff[0], ''), len(d) == 0
  def params(smt_on):
    d['knob.ncores'] = int(pmu.cpu('corecount') / pmu.cpu('socketcount'))
    d['knob.nsockets'] = pmu.cpu('socketcount')
    d['knob.nthreads'] = 2 if smt_on else 1
    d['knob.forcecpu'] = 1 if C.env2str('FORCECPU') else 0
    d['knob.tma_version'] = pmu.cpu('TMA version') or C.env2str('TMA_VER', tma.get('version'))
    d['knob.uarch'] = pmu.cpu('CPU')
    return d['knob.uarch'] or pmu.cpu_CPU()
  def user_events(f):
    ue = {}
    if not os.path.isfile(f): C.warn('file is missing: '+f); return ue
    for l in file2lines(f):
      if re.match('^\s*$', l) or 'perf stat ' in l: continue # skip empty lines
      name, group, val, etc, name2, group2, val2 = parse_perf(l)[0:7]
      if name: ue[name.replace('-', '_')] = val.replace(' ', '-') if type(val) == str else val
      if name2 in ('Frequency', ): ue[name2] = val2
    ue['TSC'] = get_TSC(f)
    return ue
  uarch = params(smt_on)
  d.update(user_events(log))
  if bottlenecks:
    d = patch_metrics(d)
    d['DurationTimeInMilliSeconds'] = d['time'] * 1000
  stat = '.'.join((base + ('-bottlenecks' if bottlenecks else ''), uarch, 'stat'))
  with open(stat, 'w') as out:
    for x in sorted(d.keys(), reverse=True):
      out.write('%s %s\n' % (x, str(d[x])))
  print('wrote:', stat)
  return stat

def main():
  a1 = C.arg(1)
  if a1.endswith('.info.log'): return rollup_all()
  if ' ' in a1: return print_metrics(a1)
  stats['verbose'] = 1
  print(pmu.cpu('eventlist'))
  s = csv2stat(a1)
  C.exe_cmd("echo scp $USER@`hostname -A | cut -d' ' -f1`:$PWD/%s ." % s)

if __name__ == "__main__":
  main()
