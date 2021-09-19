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

def read_sample(skip_bad=True, labels=False):
  valid, lines = 0, []
  while not valid:
    valid = 1
    while True:
      line = read_line()
      # input ended
      if not line:
        return None if skip_bad else lines
      # sample ended
      if re.match(r"^$", line):
        break
      # invalid sample is about to end
      if skip_bad and 'not reaching sample' in line:
        valid, lines = 0, []
        assert re.match(r"^$", read_line())
        break
      # a line with a label
      if not labels and ':' in C.str2list(line)[0]:
        continue
      lines += [ line.rstrip('\r\n') ]
  return lines

