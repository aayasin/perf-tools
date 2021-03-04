#!/usr/bin/env python2
# common functions for logging, system commands and file I/O.
# Author: Ahmad Yasin
# edited: Mar. 2021
__author__ = 'ayasin'

import sys, os, re

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

#colored printing
def printc(msg, col=color.DARKCYAN):
  print col + msg + color.END

def warn(msg):
  printc('WARNING: %s !'%msg, color.CYAN)

def error(msg):
  printc('ERROR: %s !'%msg, color.RED)
  log = re.match(r".*(>|tee) (.*).log.*", msg)
  if log: exe_cmd("cat %s.log"%log.group(2), debug=True)
  sys.exit(' !')

#print (to stderr) and flush
def printf(x, flush=True, std=sys.stderr):
  std.write(x)
  if flush: std.flush()

def exit(msg=''):
  printc('%s ..'%msg, color.GREEN)
  sys.exit('exiting')

# system
#

# exe_cmd - execute system command(s) with logging support
# @x:     command to be executed
# @msg:   an informative message to display. @ hints for a "slave" command
# @debug: print the command before its execution
# @redir_out:  redirect output of the (first non-piped) command as specified
# @run:   do run the specified command
def exe_cmd(x, msg=None, redir_out=None, debug=False, run=True):
  if redir_out: x = x.replace('|', redir_out + ' |', 1) if '|' in x else x + redir_out
  if msg:
    if '@' in msg: msg='\t'+msg.replace('@', '')
    else: msg = msg + ' ..'
    printc(msg, color.BOLD)
  if debug: printc(x, color.BLUE)
  sys.stdout.flush()
  ret = os.system(x) if run else 0
  if ret!=0: error("Command failed: " + x.replace("\n", "\\n"))

from subprocess import check_output
def exe_output(x, sep=';'):
  out = check_output(x, shell=True)
  return out.replace('\n', sep)

def file2str(f):
  out = file2lines(f)
  return out[0].replace('\n', '') if out[0] else None

import glob as python_glob
def glob(regex):
  fs = python_glob.glob(regex)
  if len(fs) is 0: error("could not find files: %s"%regex)
  return sorted(fs)

# files
#
def file2lines(filename):
  try:
    with open(filename) as f:
      return f.read().splitlines()
  except IOError:
    warn('cannot open %s'%filename)
    return [None]

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


# auxiliary: strings, Hexa masks
#

# chop - clean a list of charecters from a string
# @s:     input string
# @chars: input charecters
def chop(s, chars):
  r=s
  for i in range(len(chars)): r=r.replace(chars[i], '')
  return r

def commands_list():
  return exe_output("egrep 'elif c (==|in) ' %s | cut -d\\' -f2 | sort"%sys.argv[0], sep=' ')

def hex_en(mask, bit):
  return int(mask, 16) & 2**bit

