#!/usr/bin/env python3
# Copyright (c) 2020-2023, Intel Corporation
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
__version__= 0.90

import common as C, pmu
import csv, re, os.path, sys
from lbr import print_stat
from kernels import x86

def get_stat_log(s, perf_stat_file):
  repeat = re.findall('.perf_stat-r([1-9]).log', perf_stat_file)[0]
  return get_stat_int(s, perf_stat_file.replace('.perf_stat-r%s.log' % repeat, ''), perf_stat_file)

def get(s, app):
  return get_stat_int(s, C.command_basename(app))

def print_metrics(app):
  c = C.command_basename(app)
  rollup(c)
  return print_DB(c)

def write_stat(app): return csv2stat(C.command_basename(app) + '.toplev-vl6-perf.csv')

# internal methods
def get_stat_int(s, c, stat_file=None, val=-1):
  rollup(c, stat_file)
  try:
    val = sDB[c][s]
  except KeyError:
    C.warn('KeyError for stat: %s, in config: %s' % (s, c))
  return val

debug = 0
sDB = {}
stats = {'verbose': 0}

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

def cc(x): return x.replace(',', '')
def read_info(info):
  assert os.path.isfile(info), 'Missing file: %s' % info
  d = {}
  for l in C.file2lines(info):
    if 'IPC histogram' in l: break
    s, v = (None, ) * 2
    if 'WARNING' in l: pass
    elif re.findall('([cC]ount|estimate) of', l):
      l = l.split(':')
      s = l[0]#' '.join(l[0].split()) # re.sub('  +', ' ', l[0])
      v = cc(l[1])
    if v: d[s] = float(v) if '.' in v else int(v)
  return d

def rollup(c, perf_stat_file=None):
  if c in sDB: return
  #sDB[c]={}; sDB[c].update(read_info(c + "-janysave_type-er20c4ppp-c700001.perf.data.info.log")); return
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
      name, val, var, name2, val2, name3, val3 = parse_perf(l)
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

def parse_perf(l):
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
    val2 = int(l.split("(")[1].split(' ')[0]) if '(' in l else 1
  elif 'time elapsed' in l:
    name = 'time'
    val = float(items[0])
    var = get_var(2)
  elif '#' in l:
    name_idx = 2 if '-clock' in l else 1
    name = items[name_idx]
    if name.count('_') > 1 and name.islower() and not re.match('^(perf_metrics|unc_|sys)', name): # hack ocperf lower casing!
      base_event = name.split(':')[0]
      Name = name.replace(base_event, pmu.toplev2intel_name(base_event))
      assert not ':C1' in Name # Name = Name.replace(':C1', ':c1')
      if stats['verbose']: print(name, '->', Name)
      name = Name
    val = cc(items[0])
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
        name2 = name2.title()
      elif name2 in Renames: name2 = Renames[name2]
      name2 = name2.replace('-', '_')
      val2 = float(val2)
  if debug > 4: print('debug:', name, val, var, name2, val2, name3, val3)
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
  if not os.path.exists(filename): return d
  for l in C.file2lines(filename):
    try:
      if not re.match(r"^(FE|BE|BAD|RET|Info|warning.*zero)", l): continue
      items = l.strip().split()
      if debug > 3: print('debug:', len(items), items, l)
      if 'Info.Bot' in items[0]:
        d[items[1]] = float(items[3])
      elif '<==' in l:
        d['Critical-Group'] = Key2group[ items[0] ]
        d['Critical-Node'] = items[1]
      elif l.startswith('warning'):
        d['zero-counts'] = l.split(':')[2].strip()
      elif l.startswith('Info'):
        for m in ('Instructions', 'IpTB', 'UopPI', 'SMT_on'):
          if m in items[1]: d[items[1]] = float(cc(items[3]))
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

def read_perf_toplev(filename):
  perf_fields_tl = ['Timestamp', 'CPU', 'Group', 'Event', 'Value', 'Perf-event', 'Index', 'STDDEV', 'MULTI', 'Nodes']
  d = {}
  if debug > 2: print('reading %s' % filename)
  with open(filename) as csvfile:
    reader = csv.DictReader(csvfile, fieldnames=perf_fields_tl, delimiter=';')
    for r in reader:
      if r['Event'] in ('Event', 'dummy'): continue
      x = r['Event']
      v = int(float(r['Value']))
      if x == 'msr/tsc/': x = 'tsc'
      elif x == 'duration_time':
        x = 'DurationTimeInMilliSeconds'
        v = float(v/1e6)
        d[x] = v
        continue
      elif '.' in x or x.startswith('cpu/topdown-') or x == 'cycles': pass
      else: C.printf("unrecognized Event '%s' in reading %s\n" % (r['Event'], filename))
      b = re.match(r"[a-zA-Z\.0-9_]+:?", x).group(0)
      for i in (b, ':sup', ':user'): x = x.replace(i, i.upper())
      if v == 0 and x in d and d[x] != 0: C.warn('skipping zero override in: ' + str(r), level=1)
      else: d[x] = v
  return d

def csv2stat(filename):
  if not filename.endswith('.csv'): C.error("Expecting csv format: '%s'" % filename)
  d = read_perf_toplev(filename)
  def params(smt_on):
    d['knob.ncores'] = pmu.cpu('corecount')
    d['knob.nsockets'] = pmu.cpu('socketcount')
    d['knob.nthreads'] = 2 if smt_on else 1
    d['knob.tma_version'] = pmu.cpu('TMA version') or C.env2str('TMA_VER', '4.5-full-perf')
    d['knob.uarch'] = pmu.cpu('CPU')
    return d['knob.uarch'] or C.env2str('TMA_CPU', 'UNK')
  def patch_metrics(SLOTS='TOPDOWN.SLOTS'):
    if not (SLOTS in d and 'PERF_METRICS.FRONTEND_BOUND' in d): return
    slots = d[SLOTS]
    del d[SLOTS]
    d[SLOTS + ':perf_metrics'] = slots
    fields = ['BACKEND_BOUND', 'FRONTEND_BOUND', 'RETIRING', 'BAD_SPECULATION']
    l2map = (('MEMORY_BOUND', 'mem-bound'), ('FETCH_LATENCY', 'fetch-lat'), ('HEAVY_OPERATIONS', 'heavy-ops'), ('BRANCH_MISPREDICTS', 'br-mispredict'))
    for (x, y) in l2map:
      if 'PERF_METRICS.'+x in d: fields += [x]
    p = 'cpu/topdown-'.upper()
    if p + 'fetch-lat/'.upper() in d:
      for (x, y) in l2map:
        k = '%s%s/' % (p, y.upper())
        if k in d:
          d['PERF_METRICS.' + x] = d[k]
          fields += [x]
          del d[k]
    for k in fields:
      m = 'PERF_METRICS.' + k
      d[m] = int(255.0 * d[m] / slots)
  def user_events(f):
    ue = {}
    if not os.path.isfile(f): C.warn('file is missing: '+f); return ue
    if debug > 2: print('reading %s' % f)
    for l in C.file2lines(f):
      name, val, etc, name2, val2 = parse_perf(l)[0:5]
      if name: ue[name] = val.replace(' ', '-') if type(val) == str else val
      if name2 in ('CPUs_utilized', 'Frequency'): ue[name2] = val2
    return ue
  NOMUX = 'vl6-nomux-perf.csv'
  def nomux(): return filename.endswith(NOMUX)
  def basename():
    x = re.match(r'.*\.(toplev\-[m]?vl\d(\-nomux)?\-perf\.csv)', filename)
    if not x: C.error('stats.csv2stat(): unexpected filename: %s' % filename)
    return filename.replace(x.group(1), '')
  patch_metrics()
  base = basename()
  uarch = params(read_toplev(C.toplev_log2csv(filename), 'SMT_on'))
  if not nomux(): d.update(read_perf_toplev(base + 'toplev-mvl2-perf.csv'))
  d.update(user_events(base + 'perf_stat-r3.log'))
  stat = base + uarch + '.stat'
  with open(stat, 'w') as out:
    for x in sorted(d.keys(), reverse=True):
      out.write('%s %s\n' % (x, str(d[x])))
  print('wrote:', stat)
  return stat

def inst_fusions(hitcounts, info):
  stats_data = {'LD-OP': 0,
                'MOV-OP': 0}
  def calc_stats():
    block = hotness_key = None
    hotness = lambda s: C.str2list(s)[0]
    is_mov = lambda l: 'mov' in l and not x86.is_mem_store(l)
    cands_log = hitcounts.replace(".log", "-candidates.log")
    def find_cand(lines):
      patch = lambda s: s.replace(s.split()[0], '')
      if len(lines) < 3: return None  # need 3 insts at least
      mov_line = patch(lines[0])
      dest_reg = x86.get('dst', mov_line)
      dest_subs = x86.sub_regs(dest_reg)
      # dest reg in 2nd line -> no candidate
      # a. if dest reg is dest in 2nd line and fusion occurs -> not candidate
      # b. if dest reg is dest in 2nd line and no fusion ->
      # no candidate and disables next OPs to be candidates because dest reg got modified
      # c. if dest reg is src in 2nd line -> dest reg value is used before OP, cancels candidate
      if C.any_in(dest_subs, lines[1]): return None
      to_check = lines[2:]
      for i, line in enumerate(to_check):
        line = patch(line)
        if x86.get('dst', line) == dest_reg:  # same dest reg
          # jcc macro-fusion disables candidate
          if i < len(to_check) - 1 and x86.is_jcc_fusion(line, patch(to_check[i+1])): return None
          ld_fusion, mov_fusion = x86.is_ld_op_fusion(mov_line, line), x86.is_mov_op_fusion(mov_line, line)
          if not ld_fusion and not mov_fusion: return None
          # check if dest reg was used as src before OP or OP src reg was ever modified
          srcs = x86.get('srcs', line)
          assert len(srcs) == 1
          src_reg = srcs[0]
          for x in range(1, i + 2):
            if re.search(x86.CMOV, x86.get('inst', lines[x])): return None  # CMOV will use wrongly modified RFLAGS
            if x86.is_sub_reg(x86.get('dst', lines[x]), src_reg): return None  # OP src reg was modified before OP
            if C.any_in(dest_subs, lines[x]): return None  # dest reg used before OP
          # candidate found
          new_hotness = int(hotness(lines[0]))
          if ld_fusion: stats_data['LD-OP'] += new_hotness
          else: stats_data['MOV-OP'] += new_hotness
          # append candidate block to log
          header, tail = lines[0][:25] + "\n", lines[i+2][:25] + "z\n"  # headers to differentiate blocks
          block_list = [header] + lines[0:i+3] + [tail]
          C.fappend(''.join(block_list), cands_log, end='')
      return None
    if os.path.exists(cands_log): os.remove(cands_log)
    # for each hotness block, create a list of the lines then check
    with open(hitcounts, "r") as hits:
      for line in hits:
        def restart(): return [[line], hotness(line)] if is_mov(line) else [None, None]
        # check blocks starting with not store MOV
        if not is_mov(line) and not block: continue
        if not block:  # new block first line found
          block, hotness_key = restart()
          continue
        # append lines from the same basic block (by hotness)
        if hotness(line) == hotness_key: block.append(line)
        else:  # basic block end, check candidates
          for i, block_line in enumerate(block):
            if is_mov(block_line): find_cand(block[i:])
          hotness_key, block = restart()  # restart for next block
  total = int(C.exe_one_line(C.grep(' ALL instructions:', info)).split(':')[1].strip())
  calc_stats()
  for stat, value in stats_data.items():
    print_stat('%s fusible-candidate' % stat, value, ratio_of=('ALL', total), log=info)

def main():
  if C.arg(1).endswith('.info.log'): return rollup_all()
  stats['verbose'] = 1
  print(pmu.cpu('eventlist'))
  s = csv2stat(C.arg(1))
  C.exe_cmd("echo scp $USER@`hostname -A | cut -d' ' -f1`:$PWD/%s ." % s)

if __name__ == "__main__":
  main()
