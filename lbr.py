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

stat = {x: 0 for x in ('bad', 'total')}
stat['IPs'] = {}
def read_sample(ip_filter=None, skip_bad=True, min_lines=0, labels=False):
  valid, lines = 0, []
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
      lines += [ line.rstrip('\r\n') ]
  return lines

def is_taken(line):   return '#' in line

def is_label(line):   return ':' in C.str2list(line)[0]

