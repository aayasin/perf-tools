#!/usr/bin/env python
# common functions for logging, debug, strings, system commands and file I/O.
# Author: Ahmad Yasin
# edited: April 2022
from __future__ import print_function
__author__ = 'ayasin'

import sys, os, re, pickle
from subprocess import check_output, Popen

# logging
#
class color:
  BLUE      = '\033[94m'
  CYAN      = '\033[96m'
  DARKCYAN  = '\033[36m'
  GREY      = '\033[90m'
  GREEN     = '\033[92m'
  PURPLE    = '\033[95m'
  RED       = '\033[91m'
  YELLOW    = '\033[93m'
  BOLD = '\033[1m'
  UNDERLINE = '\033[4m'
  END = '\033[0m'

# colored printing
def printc(msg, col=color.DARKCYAN, log_only=False):
  msg = col + msg + color.END
  if not log_only: print(msg)
  if log_stdout:
    file1 = open(log_stdout, "a")
    file1.write(msg+'\n')
    file1.close()
log_stdout=None

def info(msg, bold=False, col=color.GREY):
  if bold: col += color.BOLD
  printc('INFO: %s .'%msg, col)

def warn(msg, bold=False, col=color.CYAN):
  if bold: col += color.BOLD
  printc('WARNING: %s !'%msg, col)

dump_stack_on_error = 0
def error(msg):
  printc('ERROR: %s !'%msg, color.RED)
  logs = [log[1] for log in re.findall(r"(>|tee) (\S+\.log)", msg)]
  if len(logs): exe_cmd('tail ' + ' '.join(logs), debug=True)
  if dump_stack_on_error: print(let_python_fail)
  sys.exit(' !')

def exit(msg=''):
  printc('%s ..'%msg, color.GREEN)
  sys.exit('exiting')

#debug
#
#print (to stderr) and flush
def printf(x, flush=True, std=sys.stderr):
  if std == sys.stderr: x = color.GREY + x + color.END
  std.write(x)
  if flush: std.flush()

def annotate(stuff, label=''):
  xs = stuff if type(stuff) is tuple else [stuff]
  printf('%s: '%label, flush=False)
  for x in xs: printf('%s of %s; '%(str(x), type(x)), flush=False)
  printf('.\n')

# system
#
# exe_cmd - execute system command(s) with logging support
# @x:     command to be executed
# @msg:   an informative message to display. @ hints for a "slave" command
# @debug: print the command before its execution
# @redir_out:  redirect output of the (first non-piped) command as specified
# @run:   do run the specified command
# @background: run the specified command in background (do not block)
def exe_cmd(x, msg=None, redir_out=None, debug=False, run=True, background=False):
  if redir_out: x = x.replace(' |', redir_out + ' |', 1) if '|' in x else x + redir_out
  if msg:
    if '@' in msg: msg='\t'+msg.replace('@', '')
    else: msg = msg + ' ..'
    printc(msg, color.BOLD)
  if debug: printc(x, color.BLUE)
  sys.stdout.flush()
  if log_stdout: x = x + ' | tee -a ' + log_stdout
  if background: return Popen(x.split())
  ret = os.system(x) if run else 0
  if ret!=0: error("Command failed: " + x.replace("\n", "\\n"))

def exe_output(x, sep=";"):
  out = check_output(x, shell=True)
  if isinstance(out, (bytes, bytearray)):
    out = out.decode()
  return out.replace("\n", sep)

def exe2list(x): return str2list(exe_output(x, ' '))

def exe_one_line(x, field=None):
  res = exe_output(x, '')
  if field is not None: res = str2list(res)[field]
  return res

import glob as python_glob
def glob(regex):
  fs = python_glob.glob(regex)
  if len(fs) == 0: error("could not find files: %s"%regex)
  return sorted(fs)

# OS
#
def os_installer():
  installer='yum'
  name = file2str('/etc/os-release')
  if 'Ubuntu' in name: installer='apt-get'
  if 'CentOS' in name: installer='dnf'
  return installer

# files
#
def file2lines(filename, fail=False):
  try:
    with open(filename) as f:
      return f.read().splitlines()
  except IOError:
    if fail: error('cannot open %s'%filename)
    else:
      warn('cannot open %s'%filename, bold=True)
      return [None]

def file2str(f):
  out = file2lines(f)
  return out[0].replace('\n', '') if out[0] else None

import csv
def read_perf_toplev(filename):
  perf_fields_tl = ['Timestamp', 'CPU', 'Group', 'Event', 'Value', 'Perf-event', 'Index', 'STDDEV', 'MULTI', 'Nodes']
  d = {}
  with open(filename) as csvfile:
    reader = csv.DictReader(csvfile, fieldnames=perf_fields_tl)
    for r in reader:
      if r['Event'] in ('Event', 'dummy'): continue
      x = r['Event']
      v = int(float(r['Value']))
      if x == 'msr/tsc/': x='tsc'
      elif x == 'duration_time':
        x='DurationTimeInMilliSeconds'
        v=float(v/1e6)
        d[x] = v
        continue
      elif '.' in x or x.startswith('cpu/topdown-'): pass
      else: print(r['Event'])
      x = x.upper()
      if v == 0 and x in d and d[x] != 0: warn('skipping zero override in: '+str(r))
      else: d[x] = v
  return d

# auxiliary: strings, argv, python-stuff
#

# python dictionaries
def dict_save(d, f):
  fo = open(f, 'wb')
  pickle.dump(d, fo, protocol=pickle.HIGHEST_PROTOCOL)
  fo.close()
  printf('wrote: %s\n'%f)

def dict_load(f):
  with open(f, 'rb') as fo:
    d = pickle.load(fo)
    fo.close()
    return d

# chop - clean a list of charecters from a string
# @s:     input string
# @stuff: input charecters as string, or a first item in a tuple of strings
def chop(source, stuff):
  r, chars = source, stuff
  items = []
  if type(stuff) is tuple:
    items = [ stuff[x] for x in range(1, len(stuff)) ]
    chars = stuff[0]
  for i in range(len(chars)): items += [chars[i]]
  for x in items: r = r.replace(x, '')
  return r.strip()

def str2list(s):
  return ' '.join(s.split()).split(' ')

def arg(num, default=None):
  if len(sys.argv) <= num and not default: error("must provide %d parameters"%num)
  a = sys.argv[num] if len(sys.argv) > num else default
  return a.replace('./', '') if num == 0 else a

def argv2str(start=0):
  res = []
  for a in sys.argv[start:]:
    res.append("\"%s\""%a if "'" in a else "'%s'"%a if (' ' in a or a == '') else a)
  return ' '.join(res)

def args_parse(d, args):
  for x in args.split(','):
    if len(x):
      assert '=' in x, "expect '=' as deliminer in '%s'"%args
      arg, val = x.split('=')
      assert arg in d, "unknown option '%s' in '%s'!"%(arg, args)
      d[arg] = int(val) if val.isdigit() else val
  return d

def commands_list():
  return chop(exe_output("egrep 'elif c (==|in) ' %s | cut -d\\' -f2- | cut -d: -f1 | sort"%sys.argv[0], sep=' '), "),'")

def command_basename(comm, iterations=None):
  if comm is None: return 'run%d'%os.getpid()
  name = comm.strip().split(' ')
  for x in ('taskset', 'bash'):
    if x in name[0]: name = name[2:]
  if 'omp-bin' in name[0]: name = name[1:]
  if '/' in name[0]:
    if not os.access(name[0], os.X_OK): error("user-app '%s' is not executable"%name[0])
    name[0] = name[0].split('/')[-1].replace('.sh', '')
  if len(name) == 1 and ('kernels' in comm or iterations): name.append(iterations)
  namestr = name.pop(0)
  for x in name: namestr += "%s%s"%('' if x.startswith('-') else '-', x)
  return chop(namestr, './~<>=\'{};|')

# stats
def ratio(x, histo, denom='total'):
  return '%s-ratio: %.1f%%'%(x, 100.0*histo[x]/max(histo[denom], 1))

