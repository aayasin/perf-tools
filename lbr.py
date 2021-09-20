#!/usr/bin/env python
# A module for processing LBR streams
# Author: Ahmad Yasin
# edited: Sep. 2021
#
from __future__ import print_function
__author__ = 'ayasin'

import common as C
import re, sys

def read_line():
  line = sys.stdin.readline()
  return line

def skip_sample():
  line = read_line()
  while not re.match(r"^$", line):
    line = read_line()
    assert line, 'was input truncated?'

def print_sample(sample, n=10):
  print(sample[0])
  print('\n'.join(sample[-n:]))

def line_ip(line):
  x = re.match(r"\s+(\S+)\s+(\S+)", line)
  assert x, 'expect <address> at left of %s'%line
  ip = x.group(1).lstrip("0")
  return int(ip, 16)


loops = {}
stat = {x: 0 for x in ('bad', 'total')}
stat['IPs'] = {}

def read_sample(ip_filter=None, skip_bad=True, min_lines=0, labels=False):
  valid, lines = 0, []
  def process_insn(line):
    ip = line_ip(line)
    xip = line_ip(lines[-1])
    # only simple loop-backs are supported
    if not ip in loops and is_taken(lines[-1]) and ip < xip:
      loops[ip] = {'back': xip}
      #todo: +loop length
  
  while not valid:
    valid = 1
    stat['total'] += 1
    while True:
      line = read_line()
      # input ended
      if not line:
        if len(lines): stat['bad'] += 1
        return None if skip_bad else lines
      # a new sample started
      if ip_filter and len(lines) == 0:
        if not ip_filter in line:
          valid = 0
          skip_sample()
          break
        if not ip_filter in stat['IPs']: stat['IPs'][ip_filter] = 0
        stat['IPs'][ip_filter] += 1
      # a sample ended
      if re.match(r"^$", line):
        if min_lines and (len(lines)-1) < min_lines:
          valid, lines = 0, []
          stat['bad'] += 1
        break
      # invalid sample is about to end
      if skip_bad and 'not reaching sample' in line:
        valid, lines = 0, []
        stat['bad'] += 1
        assert re.match(r"^$", read_line())
        break
      # a line with a label
      if not labels and is_label(line):
        continue
      # an instruction following a taken
      if len(lines) > 1 and not is_label(line) and is_taken(lines[-1]):
        process_insn(line)
      lines += [ line.rstrip('\r\n') ]
  return lines

def is_label(line):   return ':' in C.str2list(line)[0]

def is_loop(line):    return line_ip(line) in loops

def is_taken(line):   return '#' in line

def get_loop(ip):     return loops[ip] if ip in loops else None

def get_taken(sample, n):
  assert n in range(-32, -1), 'invalid n='+str(n)
  i = len(sample)-1
  frm, to = 0, 0
  while i >= 0:
    if is_taken(sample[i]):
      n += 1
      if n==0:
        frm = line_ip(sample[i])
        to = line_ip(sample[i+1])
        break
    i -= 1
  return {'from': frm, 'to': to, 'taken': 1}

def print_br(br):
  print('[from: 0x%x, to: 0x%x, taken: %d]'%(br['from'], br['to'], br['taken']))

def print_loop(ip):
  print('[ip: 0x%x, back: 0x%x, %s]'%(ip, loops[ip]['back'], str(loops[ip])))

