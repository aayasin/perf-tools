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

stat = {x: 0 for x in ('bad', 'total')}
def read_sample(skip_bad=True, min_lines=0, labels=False):
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

