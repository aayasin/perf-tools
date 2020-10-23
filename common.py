#!/usr/bin/env python2
# common functions for logging, system commands and file I/O.
# Author: Ahmad Yasin
# edited: October 2020
__author__ = 'ayasin'

import sys, os


# logging
#
class color:
  PURPLE = '\033[95m'
  CYAN = '\033[96m'
  DARKCYAN = '\033[36m'
  BLUE = '\033[94m'
  GREEN = '\033[92m'
  YELLOW = '\033[93m'
  RED = '\033[91m'
  BOLD = '\033[1m'
  UNDERLINE = '\033[4m'
  END = '\033[0m'

def printc(msg, col=color.RED): 
  print col + msg + color.END

def warn(msg):
  printc('WARNING: %s !'%msg, color.CYAN)

def error(msg):
  printc('ERROR: %s !'%msg)
  sys.exit(' !')


# system
#
def exe_cmd(x, msg=None, redir_out=None, debug=False):
  if redir_out: x = x.replace('|', redir_out + ' |', 1) if '|' in x else x + redir_out
  if msg: printc(msg + ' ..', color.BOLD)
  if debug: printc(x, color.BLUE)
  sys.stdout.flush()
  ret = os.system(x)
  if ret!=0: error("Command failed: " + x.replace("\n", "\\n"))

import subprocess
def get_out(x):
  out = subprocess.check_output(x)
  return out.replace('\n', '')

def file2str(f):
  out = file2lines(f)
  return out[0].replace('\n', '')

# files
#
def file2lines(filename):
  with open(filename) as f:
    return f.read().splitlines()

import csv
def read_perf_toplev(filename):
  perf_fields_tl = ['Timestamp', 'CPU', 'Group', 'Event', 'Value', 'Perf-event', 'Index', 'STDDEV', 'MULTI', 'Nodes']
  d = {}
  with open(filename) as csvfile:
    reader = csv.DictReader(csvfile, fieldnames=perf_fields_tl)
    for r in reader:
      x = r['Event']
      if x in ('Event', 'dummy') : continue
      if x == 'msr/tsc/': x='tsc'
      elif not '.' in x: print x
      d[x.upper()] = int(float(r['Value']))
  return d


