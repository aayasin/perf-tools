#!/usr/bin/env python
# A module for processing LBR streams
# Author: Ahmad Yasin
# edited: May 2022
#
from __future__ import print_function
__author__ = 'ayasin'
__version__= 0.63

import common as C
import pmu
import os, re, sys

hitcounts = C.envfile('PTOOLS_HITS')
debug = os.getenv('DBG')
verbose = os.getenv('VER')
use_cands = os.getenv('USE_CANDS')

def hex(ip): return '0x%x'%ip if ip else '-'
def inc(d, b): d[b] = d.get(b, 0) + 1
def ratio(a, b): return '%.2f%%' % (100.0 * a / b)
def read_line(): return sys.stdin.readline()

def exit(x, sample, label):
  C.annotate(x, label)
  print_sample(sample, 0)
  C.printf(debug+'\n')
  sys.exit()

def str2int(ip, plist):
  try:
    return int(ip, 16)
  except ValueError:
    print_sample(plist[2])
    assert 0, "expect address in '%s' of '%s'" % (ip, plist[0])

def skip_sample(s):
  line = read_line()
  while not re.match(r"^$", line):
    line = read_line()
    assert line, 'was input truncated? sample:\n%s'%s
  return 0

def header_ip(line):
  x = is_header(line)
  assert x, "Not a head of sample: " + line
  return str2int(C.str2list(line)[6 if '[' in x.group(1) else 5], (line, None))

def line_ip(line, sample=None):
  x = re.match(r"\s+(\S+)\s+(\S+)", line)
  assert x, 'expect <address> at left of %s'%line
  ip = x.group(1).lstrip("0")
  return str2int(ip, (line, sample))

def line_timing(line):
  x = re.match(r"[^#]+# (\S+) (\d+) cycles \[\d+\] ([0-9\.]+) IPC", line)
  # note: this ignores timing of 1st LBR entry (has cycles but not IPC)
  assert x, 'Could not match IPC in:\n%s' % line
  ipc = round(float(x.group(3)), 1)
  cycles = int(x.group(2))
  return cycles, ipc

def tripcount(ip, loop_ipc, state):
  if state == 'new' and loop_ipc in loops:
    if not 'tripcount' in loops[loop_ipc]: loops[loop_ipc]['tripcount'] = {}
    state = 'valid'
  elif type(state) == int:
    if ip == loop_ipc: state += 1
    elif not is_in_loop(ip, loop_ipc):
      inc(loops[loop_ipc]['tripcount'], str(state))
      state = 'done'
  elif state == 'valid':
    if ip == loop_ipc:
      state = 1
  return state

def loop_stats(line, loop_ipc, tc_state):
  def mark(regex, tag):
    if re.findall(regex, line):
      if not loop_stats.atts or not tag in loop_stats.atts:
        loop_stats.atts = ';'.join((loop_stats.atts, tag)) if loop_stats.atts else tag
  def vec_reg(i): return '%%%smm' % chr(ord('x') + i)
  def vec_len(i): return 'vec%d' % (128 * (i + 1))
  # loop-body stats, FIXME: on the 1st encoutered loop in a new sample for now
  if loop_stats_en and tc_state == 'new' and is_loop(line):
    loop_stats.id = line_ip(line)
    loop_stats.atts = ''
  if loop_stats.id:
    if not is_in_loop(line_ip(line), loop_stats.id): #just exited a loop
      if len(loop_stats.atts) > len(loops[loop_stats.id]['attributes']):
        loops[loop_stats.id]['attributes'] = loop_stats.atts
      loop_stats.atts = ''
      loop_stats.id = None
    else:
      mark(r"(jmp|call)\s%", 'indirect')
      for i in range(loop_stats_vec):
        mark(r"[^k]p[sdh]\s+" + vec_reg(i), vec_len(i) + '-fp')
        mark(r"\s%sp.*%s" % ('(v)' if i==0 else 'v', vec_reg(i)), vec_len(i) + '-int')
  return tripcount(line_ip(line), loop_ipc, tc_state)
loop_stats.id = None
loop_stats.atts = ''
loop_stats_en = False
loop_stats_vec = 3 if pmu.cpu_has_feature('avx512vl') else 2

bwd_br_tgts = [] # better make it local to read_sample..
loop_cands = []
def detect_loop(ip, lines, loop_ipc,
  MOLD=4e4): #Max Outer Loop Distance
  global loop_cycles, bwd_br_tgts, loop_cands # unlike nonlocal, global works in python2 too!
  def find_block_ip():
    x = len(lines)-2
    while x>=0:
      if is_taken(lines[x]):
        return line_ip(lines[x+1])
      x -= 1
    return 0
  def has_ip(at):
    while at > 0:
      if is_callret(lines[at]): return False
      if line_ip(lines[at]) == ip: return True
      at -= 1
    return False
  
  if ip in loops:
    loop = loops[ip]
    loop['hotness'] += 1
    if ip == loop_ipc and is_taken(lines[-1]):
      if not 'IPC' in loop: loop['IPC'] = {}
      begin = find_block_ip()
      if begin == ip and has_timing(lines[-1]):
        cycles, ipc = line_timing(lines[-1])
        inc(loop['IPC'], ipc)
        loop_cycles += cycles
    if not loop['size'] and not loop['outer'] and len(lines)>2 and line_ip(lines[-1]) == loop['back']:
      size = 0
      x = len(lines)-1
      while x >= 1:
        size += 1
        inst_ip = line_ip(lines[x])
        if inst_ip == ip:
          loop['size'] = size
          break
        elif inst_ip < ip or inst_ip > loop['back']:
          break
        x -= 1
    if not loop['entry-block'] and not is_taken(lines[-1]):
      loop['entry-block'] = find_block_ip()
    return
  
  # only simple loops, of these attributes, are supported:
  # * are entirely observed in a single sample (e.g. tripcount < 32)
  # * a tripcount > 1 is observed
  # * no function calls
  if is_taken(lines[-1]):
    xip = line_ip(lines[-1])
    if xip <= ip: pass # not a backward jump
    elif (use_cands and ip in loop_cands) or (not use_cands and ip in bwd_br_tgts):
      if use_cands: loop_cands.remove(ip)
      else: bwd_br_tgts.remove(ip)
      inner, outer = 0, 0
      ins, outs = set(), set()
      for l in loops:
        if ip > l and xip < loops[l]['back']:
          inner += 1
          outs.add(hex(l))
          loops[l]['outer'] = 1
          loops[l]['inner-loops'].add(hex(ip))
        if ip < l and xip > loops[l]['back']:
          outer = 1
          ins.add(hex(l))
          loops[l]['inner'] += 1
          loops[l]['outer-loops'].add(hex(ip))
      loops[ip] = {'back': xip, 'hotness': 1, 'size': None, 'attributes': '',
        'entry-block': 0 if xip > ip else find_block_ip(),
        'inner': inner, 'outer': outer, 'inner-loops': ins, 'outer-loops': outs
      }
      return
    elif use_cands and len(lines) > 2 and ip in bwd_br_tgts and has_ip(len(lines)-2):
      bwd_br_tgts.remove(ip)
      loop_cands += [ip]
    elif (((xip - ip) < MOLD) and
        not is_callret(lines[-1]) and # requires --xed
        not ip in bwd_br_tgts and
        (use_cands or has_ip(len(lines)-2))):
      bwd_br_tgts += [ip]

LBR_Event = pmu.lbr_event()[:-4]
lbr_events = []
loops = {}
stat = {x: 0 for x in ('bad', 'bogus', 'total', 'total_cycles')}
stat['IPs'] = {}
stat['events'] = {}
stat['size'] = {'min': 0, 'max': 0, 'avg': 0}
size_sum=0
loop_cycles=0
dsb = {}
footprint = set()

def read_sample(ip_filter=None, skip_bad=True, min_lines=0, labels=False,
                loop_ipc=0, lp_stats_en=False, event = LBR_Event):
  global lbr_events, size_sum, bwd_br_tgts, loop_stats_en
  valid, lines, bwd_br_tgts = 0, [], []
  size_stats_en = skip_bad and not labels
  loop_stats_en = lp_stats_en
  edge_en = event.startswith(LBR_Event) and not ip_filter and not loop_ipc # config good for edge-profile
  if stat['total']==0 and edge_en and pmu.dsb_msb() and not pmu.cpu('smt-on'):
    #dsb_heat_en = 1; len(dsb) == dsb_heat_en
    dsb['heatmap'] = {}
    if debug: C.printf('DBG=%s\n' % debug)
  
  while not valid:
    valid, lines, bwd_br_tgts = 1, [], []
    xip, timestamp = None, None
    tc_state = 'new'
    stat['total'] += 1
    if stat['total'] % (1e4 if loop_ipc else 1000) == 0: C.printf('.')
    while True:
      line = read_line()
      # input ended
      if not line:
        if size_stats_en:
          total = stat['IPs'][ip_filter] if ip_filter else stat['total']
          stat['size']['avg'] = round(size_sum / (total - stat['bad'] - stat['bogus']), 1)
        if len(lines): stat['bogus'] += 1
        if stat['total'] == stat['bogus']:
          print_all()
          C.error('No LBR data in profile')
        if not loop_ipc: C.printf(' .\n')
        return lines if len(lines) and not skip_bad else None
      header = is_header(line)
      if header:
        # first sample here (of a given event)
        ev = header.group(3)[:-1]
        if not ev in lbr_events:
          lbr_events += [ev]
          x = 'events= %s @ %s' % (str(lbr_events), header.group(1).split(' ')[-1])
          if len(lbr_events) == 1: x += ' primary= %s' % event
          if ip_filter: x += ' ip_filter= %s' % ip_filter
          if loop_ipc: x += ' loop= %s' % hex(loop_ipc)
          C.printf(x+'\n')
        inc(stat['events'], ev)
        if debug: timestamp = header.group(1).split()[-1]
      # a new sample started
      # perf  3433 1515065.348598:    1000003 EVENT.NAME:      7fd272e3b217 __regcomp+0x57 (/lib/x86_64-linux-gnu/libc-2.23.so)
        if ip_filter:
          if not ip_filter in line:
            valid = skip_sample(line)
            break
          inc(stat['IPs'], ip_filter)
      # a sample ended
      if re.match(r"^$", line):
        len_m1 = 0
        if len(lines): len_m1 = len(lines)-1
        if len_m1 == 0 or\
           min_lines and (len_m1 < min_lines) or\
           header_ip(lines[0]) != line_ip(lines[len_m1]):
          valid = 0
          stat['bogus'] += 1
          if debug and debug == timestamp:
            exit((line.strip(), len(lines)), lines, 'a bogus sample ended')
        elif len_m1 and type(tc_state) == int and is_in_loop(line_ip(lines[-1]), loop_ipc):
          if tc_state == 31 or verbose:
            inc(loops[loop_ipc]['tripcount'], '%d+' % (tc_state + 1))
          # else: note a truncated tripcount, i.e. unknown in 1..31, is not accounted for by default.
        if debug and debug == timestamp:
          exit((line.strip(), len(lines)), lines, 'sample-of-interest ended')
        break
      elif header and len(lines): # sample had no LBR data; new one started
        # exchange2_r_0.j 57729 3736595.069891:    1000003 r20c4:pp:            41f47a brute_force_mp_brute_+0x43aa (/home/admin1/ayasin/perf-tools/exchange2_r_0.jmpi4)
        # exchange2_r_0.j 57729 3736595.069892:    1000003 r20c4:pp:            41fad4 brute_force_mp_brute_+0x4a04 (/home/admin1/ayasin/perf-tools/exchange2_r_0.jmpi4)
        lines = []
        stat['bogus'] += 1 # for this one
        stat['total'] += 1 # for new one
      # invalid sample is about to end
      if skip_bad and 'not reaching sample' in line:
        valid = 0
        stat['bad'] += 1
        assert re.match(r"^$", read_line())
        break
      # a line with a label
      if not labels and is_label(line):
        continue
      # e.g. "        prev_nonnote_           addb  %al, (%rax)"
      if skip_bad and len(lines) and not line.strip().startswith('0'):
        if debug and debug == timestamp:
          exit(line, lines, "bad line")
        valid = skip_sample(lines[0])
        stat['bogus'] += 1
        break
      ip = None if header or is_label(line) else line_ip(line, lines)
      new_line = is_line_start(ip, xip)
      if edge_en and new_line: footprint.add(ip >> 6)
      if len(lines) and not is_label(line):
        # a 2nd instruction
        if len(lines) > 1:
          detect_loop(ip, lines, loop_ipc)
          if len(dsb) and (is_taken(lines[-1]) or new_line):
            inc(dsb['heatmap'], pmu.dsb_set_index(ip))
        tc_state = loop_stats(line, loop_ipc, tc_state)
      if len(lines) or event in line:
        line = line.rstrip('\r\n')
        if has_timing(line):
          cycles = line_timing(line)[0]
          stat['total_cycles'] += cycles
        lines += [ line ]
      xip = ip
  if size_stats_en:
    size = len(lines) - 1
    if size_sum == 0: stat['size']['min'] = stat['size']['max'] = size
    else:
      if stat['size']['min'] > size: stat['size']['min'] = size
      if stat['size']['max'] < size: stat['size']['max'] = size
    size_sum += size
  return lines

def is_callret(l):    return re.findall(r"(call|ret)", l)

def is_header(line): return re.match(r"([^:]*):\s+(\d+)\s+(\S*)\s+(\S*)", line)

def is_jmp_next(br, # a hacky implementation for now
  JS=2,             # short direct Jump Size
  CDLA=16):         # compiler default loops alignment
  mask = ~(CDLA - 1)
  return (br['to'] == (br['from'] + JS)) or (
         (br['to'] & mask) ==  ((br['from'] & mask) + CDLA))

def has_timing(line): return line.endswith('IPC')
def is_line_start(ip, xip): return (ip >> 6) ^ (xip >> 6) if ip and xip else False
def is_label(line):   return line.strip().endswith(':')
def is_loop(line):    return line_ip(line) in loops
def is_taken(line):   return '#' in line
def is_in_loop(ip, loop): return ip >= loop and ip <= loops[loop]['back']
def get_loop(ip):     return loops[ip] if ip in loops else None

def get_taken(sample, n):
  assert n in range(-32, 0), 'invalid n='+str(n)
  i = len(sample)-1
  frm, to = -1, -1
  while i >= 0:
    if is_taken(sample[i]):
      n += 1
      if n==0:
        frm = line_ip(sample[i])
        if i < (len(sample)-1): to = line_ip(sample[i+1])
        break
    i -= 1
  return {'from': frm, 'to': to, 'taken': 1}

def get_loop_hist(loop_ipc, name, weighted=False, sortfunc=None):
  loop = loops[loop_ipc]
  assert name in loop
  return (loop[name], name, loop, loop_ipc, sortfunc, weighted)

def print_hist(hist_t):
  if not hist_t[0]: return -1
  hist, name = hist_t[0], hist_t[1]
  loop, loop_ipc, sorter, weighted = (None, ) * 4
  if len(hist_t) > 2: (loop, loop_ipc, sorter, weighted) = hist_t[2:]
  tot = sum(hist.values())
  if not tot: return 0
  if loop:
    shist = sorted(hist.items(), key=lambda x: x[1])
    loop['%s-most' % name] = str(shist[-1][0])
    loop['%s-num-buckets' % name] = len(hist)
  C.printc('%s histogram%s:' % (name, ' of loop %s' % hex(loop_ipc) if loop_ipc else ''))
  for k in sorted(hist.keys(), key=sorter): print('%4s: %6d%6.1f%%' % (k, hist[k], 100.0 * hist[k] / tot))
  print('')
  return sum(hist[k] * int(k.split('+')[0]) for k in hist.keys()) if weighted else tot

def print_all(nloops=10, loop_ipc=0):
  stat['detected-loops'] = len(loops)
  if not loop_ipc: print('LBR samples:', stat)
  if len(footprint): print('code footprint estimate: %.2f KB\n' % (len(footprint) / 16.0))
  if len(dsb): print_hist((dsb['heatmap'], 'DSB-Heatmap'))
  sloops = sorted(loops.items(), key=lambda x: loops[x[0]]['hotness'])
  if loop_ipc:
    if loop_ipc in loops:
      lp = loops[loop_ipc]
      tot = print_hist(get_loop_hist(loop_ipc, 'IPC'))
      if tot:
        lp['cyc/iter'] = '%.2f' % (loop_cycles/float(tot))
        lp['full-loop_cycles%'] = ratio(loop_cycles, stat['total_cycles'])
      tot = print_hist(get_loop_hist(loop_ipc, 'tripcount', True, lambda x: int(x.split('+')[0])))
      if tot: lp['tripcount-coverage'] = ratio(tot, lp['hotness'])
      if hitcounts and lp['size']:
        C.exe_cmd('egrep -B1 -A%d 0%x %s' % (lp['size'], loop_ipc, hitcounts),
          'Hitcounts & ASM of loop %s' % hex(loop_ipc))
      find_print_loop(loop_ipc, sloops)
    else:
      C.warn('Loop %s was not observed'%hex(loop_ipc))
  if nloops and len(loops):
    if os.getenv("LBR_LOOPS_LOG"):
      log = open(os.getenv("LBR_LOOPS_LOG"), 'w')
      num = len(loops)
      for l in sloops:
        print_loop(l[0], num, log)
        num -= 1
      log.close()
    ploops = sloops
    if len(loops) > nloops: ploops = sloops[-nloops:]
    else: nloops = len(ploops)
    C.printc('top %d loops:' % nloops)
    for l in ploops:
      print_loop(l[0], nloops)
      nloops -=  1

def print_br(br):
  print('[from: 0x%x, to: 0x%x, taken: %d]'%(br['from'], br['to'], br['taken']))

def find_print_loop(ip, sloops):
  num = 1
  for l in reversed(sloops):
    if l[0] == ip:
      print_loop(l[0], num, detailed=True)
      print('\n'*2)
      return
    num += 1

def print_loop(ip, num=0, print_to=sys.stdout, detailed=False):
  if not isinstance(ip, int): ip = int(ip, 16) #should use (int, long) but fails on python3
  def printl(s, end='\n'): return print(s, file=print_to, end=end)
  if not ip in loops:
    printl('No loop was detected at %s!'%hex(ip))
    return
  loop = loops[ip].copy()
  def set2str(s, top=0 if detailed else 3):
    new = loop[s]
    if top and len(new) > top:
      n = len(new) - top
      new = set()
      while top > 0:
        new.add(loop[s].pop())
        top -= 1
      new.add('.. %d more'%n)
    loop[s] = C.chop(str(sorted(new, reverse=True)), (")", 'set('))
  printl('Loop#%d: [ip: %s, hotness: %6d, size: %s, ' %
    (num, hex(ip), loop['hotness'], '%d'%loop['size'] if loop['size'] else '-'), '')
  if not loop_stats_en: del loop['attributes']
  elif not len(loop['attributes']): loop['attributes'] = '-'
  elif ';' in loop['attributes']: loop['attributes'] = ';'.join(sorted(loop['attributes'].split(';')))
  for x in ('hotness', 'size'): del loop[x]
  for x in ('back', 'entry-block'):
    printl('%s: %s, '%(x, hex(loop[x])), '')
    del loop[x]
  for x in ('inn', 'out'): set2str(x + 'er-loops')
  for x in ('IPC', 'tripcount'):
    if x in loop: del loop[x]
  printl(C.chop(str(loop), "'{}\"") + ']')

def print_sample(sample, n=10):
  if not len(sample): return
  C.printf('\n'.join(('sample#%d'%stat['total'], sample[0], '\n')))
  print('\n'.join(sample[-n:] if n else sample) + '\n')
  sys.stdout.flush()

def print_header():
  C.printc('Global stats:')
  print("perf-tools' lbr.py module version %.2f" % __version__)
