#!/usr/bin/env python
# A module for processing LBR streams
# Author: Ahmad Yasin
# edited: March 2022
#
from __future__ import print_function
__author__ = 'ayasin'
debug = 0

import common as C
import pmu
import re, sys

def hex(ip): return '0x%x'%ip if ip else '-'
def inc(d, b): d[b] = d.get(b, 0) + 1
def read_line(): return sys.stdin.readline()

def skip_sample(s):
  line = read_line()
  while not re.match(r"^$", line):
    line = read_line()
    assert line, 'was input truncated? sample:\n%s'%s
  return 0

def header_ip(line):
  x = is_header(line)
  assert x, "Not a head of sample: " + line
  return int(C.str2list(line)[6 if '[' in x.group(1) else 5], 16)

def line_ip(line):
  x = re.match(r"\s+(\S+)\s+(\S+)", line)
  assert x, 'expect <address> at left of %s'%line
  ip = x.group(1).lstrip("0")
  return int(ip, 16)

def line_timing(line):
  x = re.match(r"[^#]+# (\S+) (\d+) cycles \[\d+\] ([0-9\.]+) IPC", line)
  assert x, 'Could not match IPC in:\n%s'%line
  ipc = round(float(x.group(3)), 1)
  cycles = int(x.group(2))
  return cycles, ipc

def tripcount(ip, loop_ipc, state):
  if state == 'new' and loop_ipc in loops:
    state = 'invalid' if is_in_loop(ip, loop_ipc) else 'valid'
  elif type(state) == int:
    if ip == loop_ipc: state += 1
    elif not is_in_loop(ip, loop_ipc):
      if not 'tripcount' in loops[loop_ipc]: loops[loop_ipc]['tripcount'] = {}
      inc(loops[loop_ipc]['tripcount'], state)
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
      mark(r"p[sdh]\s+%xmm", 'vec128-fp')
      mark(r"p[sdh]\s+%ymm", 'vec256-fp')
      mark(r"p[sdh]\s+%zmm", 'vec512-fp')
  return tripcount(line_ip(line), loop_ipc, tc_state)
loop_stats.id = None
loop_stats.atts = ''
loop_stats_en = False

bwd_br_tgts = [] # better make it local to read_sample..
def detect_loop(ip, lines, loop_ipc,
  MOLD=4e4): #Max Outer Loop Distance
  global loop_cycles, bwd_br_tgts #unlike nonlocal, global works in python2 too!
  def find_block_ip():
    x = len(lines)-2
    while x>=0:
      if is_taken(lines[x]):
        return line_ip(lines[x+1])
      x -= 1
    return 0
  
  if ip in loops:
    loop = loops[ip]
    loop['hotness'] += 1
    if ip == loop_ipc and is_taken(lines[-1]):
      if not 'IPC' in loop: loop['IPC'] = {}
      begin = find_block_ip()
      if begin == ip and 'IPC' in lines[-1]:
        cycles, ipc = line_timing(lines[-1])
        inc(loop['IPC'], ipc)
        loop_cycles += cycles
    if not loop['size'] and not loop['outer'] and len(lines)>2 and\
      line_ip(lines[-1]) == loop['back']:
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
  xip = line_ip(lines[-1])
  # only simple loops that are entirely observed in a single sample are supported
  if is_taken(lines[-1]):
    if ip in bwd_br_tgts:
      inner, outer = 0, 0
      ins, outs = set(), set()
      for l in loops:
        if ip > l and xip < loops[l]['back']:
          inner += 1
          outs.add(hex(l))
          loops[l]['outer'] = 1
          loops[l]['size'] = None #no support yet
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
      bwd_br_tgts.remove(ip)
      return
    if ip < xip and\
      ((xip - ip) < MOLD) and\
      not ('call' in lines[-1] or 'ret' in lines[-1]): #these require --xed with perf script
      bwd_br_tgts += [ip]

LBR_Event = pmu.lbr_event()[:-4]
lbr_events = []
loops = {}
stat = {x: 0 for x in ('bad', 'bogus', 'total')}
stat['IPs'] = {}
stat['events'] = {}
stat['size'] = {'min': 0, 'max': 0, 'avg': 0}
size_sum=0
loop_cycles=0
dsb_heatmap = {}
dsb_heat_en = False
footprint = set()

def read_sample(ip_filter=None, skip_bad=True, min_lines=0, labels=False,
                loop_ipc=0, lp_stats_en=False, event = LBR_Event):
  global lbr_events, size_sum, bwd_br_tgts, loop_stats_en, dsb_heat_en
  valid, lines, bwd_br_tgts = 0, [], []
  size_stats_en = skip_bad and not labels
  loop_stats_en = lp_stats_en
  edge_en = event.startswith(LBR_Event) and not ip_filter # config good for edge-profile
  if stat['total']==0: dsb_heat_en = edge_en and pmu.goldencove() and not pmu.cpu('smt-on')
  
  while not valid:
    valid, lines, bwd_br_tgts = 1, [], []
    header, xip = True, None
    tc_state = 'new'
    stat['total'] += 1
    if stat['total'] % 1000 == 0: C.printf('.')
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
        C.printf(' .\n')
        return lines if len(lines) and not skip_bad else None
      if header:
        # first sample here (of a given event)
        x = is_header(line)
        assert x, "expect <event> in:\n%s"%line
        ev = x.group(3)[:-1]
        if not ev in lbr_events:
          lbr_events += [ev]
          x = 'events= %s @ %s' % (str(lbr_events), x.group(1).split(' ')[-1])
          if len(lbr_events) == 1: x += ' primary= %s' % event
          if ip_filter: x += ' ip_filter= %s'%ip_filter
          C.printf(x+'\n')
        inc(stat['events'], ev)
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
          if debug:
            C.annotate((line.strip(), len(lines)), 'a sample ended')
            print_sample(lines)
        break
      elif is_header(line) and len(lines): # sample had no LBR data; new one started
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
        if debug:
          x='DBG: %s %s\n\n\n'%(line, lines[0])
          C.printf(x)
          print(stat)
          print_sample(lines)
        valid = skip_sample(lines[0])
        stat['bogus'] += 1
        break
      ip = None if header or is_label(line) else line_ip(line)
      new_line = is_line_start(ip, xip)
      if edge_en and new_line: footprint.add(ip >> 6)
      if len(lines) and not is_label(line):
        # a 2nd instruction
        if len(lines) > 1:
          detect_loop(ip, lines, loop_ipc)
          if dsb_heat_en and (is_taken(lines[-1]) or new_line):
            inc(dsb_heatmap, ((ip & 0x7ff) >> 6))
        tc_state = loop_stats(line, loop_ipc, tc_state)
      if len(lines) or event in line:
        lines += [ line.rstrip('\r\n') ]
      xip = ip
      header = False
  if size_stats_en:
    size = len(lines) - 1
    if size_sum == 0: stat['size']['min'] = stat['size']['max'] = size
    else:
      if debug and size < 64:
        print(stat['total'])
        print_sample(lines)
      if stat['size']['min'] > size: stat['size']['min'] = size
      if stat['size']['max'] < size: stat['size']['max'] = size
    size_sum += size
  return lines

def is_header(line): return re.match(r"([^:]*):\s+(\d+)\s+(\S*)\s+(\S*)", line)

def is_jmp_next(br, # a hacky implementation for now
  JS=2,             # short direct Jump Size
  CDLA=16):         # compiler default loops alignment
  mask = ~(CDLA - 1)
  return (br['to'] == (br['from'] + JS)) or (
         (br['to'] & mask) ==  ((br['from'] & mask) + CDLA))

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

def get_hist(loop_ipc, name):
  loop = loops[loop_ipc]
  return (loop[name], name, loop, loop_ipc) if name in loop else (None, ) * 4

def print_hist(hist_t):
  if not hist_t[0]: return 0
  hist, name, loop, loop_ipc = hist_t[0], hist_t[1], hist_t[2], hist_t[3]
  tot = sum(hist.values())
  if not tot: return 0
  shist = sorted(hist.items(), key=lambda x: x[1])
  if loop: loop['%s-most' % name] = str(shist[-1][0])
  C.printc('%s histogram%s:' % (name, ' of loop %s' % hex(loop_ipc) if loop_ipc else ''))
  for k in sorted(hist.keys()):
    print('%4s: %6d%6.1f%%'%(k, hist[k], 100.0*hist[k]/tot))
  print('')
  return tot

def print_all(nloops=10, loop_ipc=0):
  stat['detected-loops'] = len(loops)
  print('LBR samples:', stat)
  if len(footprint): print('code footprint estimate: %.2f KB' % (len(footprint) / 16.0))
  if len(dsb_heatmap): print_hist((dsb_heatmap, 'DSB-Heatmap', None, None))
  if loop_ipc:
    if loop_ipc in loops:
      tot = print_hist(get_hist(loop_ipc, 'IPC'))
      if tot: loops[loop_ipc]['cyc/iter'] = '%.2f'%(loop_cycles/float(tot))
      print_hist(get_hist(loop_ipc, 'tripcount'))
    else:
      C.warn('Loop %s was not observed'%hex(loop_ipc))
  if len(loops):
    C.printc('top %d loops:'%nloops)
    sloops = sorted(loops.items(), key=lambda x: loops[x[0]]['hotness'])#, reverse=True)
    for l in sloops[-nloops:] if len(loops) > nloops else sloops:
      print_loop(l[0])

def print_br(br):
  print('[from: 0x%x, to: 0x%x, taken: %d]'%(br['from'], br['to'], br['taken']))

def print_loop(ip):
  if not isinstance(ip, int): ip = int(ip, 16) #should use (int, long) but fails on python3
  if not ip in loops:
    print('No loop was detected at %s!'%hex(ip))
    return
  loop = loops[ip]
  def set2str(s, top=3):
    new = loop[s]
    if len(new) > top:
      n = len(new) - top
      new = set()
      while top > 0:
        new.add(loop[s].pop())
        top -= 1
      new.add('.. %d more'%n)
    loop[s] = C.chop(str(sorted(new, reverse=True)), (")", 'set('))
  print('[ip: %s, hotness: %6d, size: %s, '%(hex(ip), loop['hotness'], '%d'%loop['size'] if loop['size'] else '-'), end='')
  if not loop_stats_en: del loop['attributes']
  elif not len(loop['attributes']): loop['attributes'] = '-'
  elif ';' in loop['attributes']: loop['attributes'] = ';'.join(sorted(loop['attributes'].split(';')))
  for x in ('hotness', 'size'): del loop[x]
  for x in ('back', 'entry-block'):
    print('%s: %s, '%(x, hex(loop[x])), end='')
    del loop[x]
  for x in ('inn', 'out'): set2str(x + 'er-loops')
  for x in ('IPC', 'tripcount'):
    if x in loop: del loop[x]
  print(C.chop(str(loop), "'{}\"") + ']')

def print_sample(sample, n=10):
  if not len(sample): return
  print('sample#%d'%stat['total'], sample[0], sep='\n')
  print('\n'.join(sample[-n:] if n else sample))
  sys.stdout.flush()

