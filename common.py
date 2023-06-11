#!/usr/bin/env python
# Copyright (c) 2020-2023, Intel Corporation
# Author: Ahmad Yasin
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# common functions for logging, debug, arg-parsing, strings, system commands and file I/O.
#
from __future__ import print_function
__author__ = 'ayasin'

import os, pickle, re, subprocess, sys

# logging
#
class color:
  BLUE      = '\033[94m'
  CYAN      = '\033[96m'
  DARKCYAN  = '\033[36m'
  GREY      = '\033[90m'
  GREEN     = '\033[92m'
  ORANGE    = '\033[33m'
  PURPLE    = '\033[95m'
  RED       = '\033[91m'
  YELLOW    = '\033[93m'
  BOLD = '\033[1m'
  UNDERLINE = '\033[4m'
  END = '\033[0m'

Globals = {'llvm-mca': '/usr/local/bin/llvm-mca',
  'xed':           '/usr/local/bin/xed'
}

# append to a file
def fappend(text, filename):
  with open(filename, 'a') as f: f.write(text + '\n')

# colored printing, writes to outfile or log_stdio
def printc(msg, col=color.DARKCYAN, log_only=False, outfile=None):
  msg = col + msg + color.END
  if not log_only: print(msg)
  if not outfile: outfile = log_stdio
  if outfile: fappend(msg, outfile)
log_stdio=None

def info(msg, bold=False, col=color.GREY):
  if bold: col += color.BOLD
  printc('INFO: %s .'%msg, col)

warn_db = {}
def warn(msg, bold=False, col=color.ORANGE, level=0, suppress_after=3):
  inc(warn_db, msg)
  if suppress_after and warn_db[msg] > suppress_after: return
  WARN = env2int('WARN')
  if bold: col += color.BOLD
  if level <= WARN: printc('WARNING: %s%s' % (msg, '; suppressing' if warn_db[msg]==suppress_after else ''), col)
def warn_summary():
  if len(warn_db): print('Top warnings: (%d total unique)\n' % len(warn_db), hist2str(warn_db))

dump_stack_on_error = 0
def error(msg):
  printc('ERROR: %s !'%msg, color.RED)
  logs = [log[1] for log in re.findall(r"(>|tee) (\S+\.log)", msg) if log[1][0].isalpha()]
  if len(logs): exe_cmd('tail ' + ' '.join(set(logs)), debug=True)
  if dump_stack_on_error: print(let_python_fail)
  sys.exit(' !')

def exit(msg=None):
  printc('%s ..' % str(msg), color.GREEN)
  sys.exit('exiting' if msg else 0)

#debug
#
#print (to stderr) and flush
def printf(x, flush=True, std=sys.stderr, col=color.GREY):
  std.write(col + x + color.END)
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
# @log:   log the commands's output into log_stdio (if any)
# @fail:  exit with error if command fails
# @background: run the specified command in background (do not block)
def exe_cmd(x, msg=None, redir_out=None, debug=False, run=True, log=True, fail=True, background=False):
  if redir_out: x = x.replace(' |', redir_out + ' |', 1) if '|' in x else x + redir_out
  if msg:
    if '@' in msg: msg='\t' + msg.replace('@', '')
    else: msg = msg + ' ..'
    if run or msg.endswith('..'): printc(msg, color.BOLD)
  if debug: printc(x, color.BLUE)
  sys.stdout.flush()
  if background: return subprocess.Popen(x.split())
  ret = 0
  if run:
    if log and log_stdio:
      if not '2>&1' in x: x = x + ' 2>&1'
      x = x + ' | tee -a ' + log_stdio
      ret = subprocess.call(['/bin/bash', '-c', 'set -o pipefail; ' + x])
    else:
      ret = os.system(x)
  if ret != 0:
    msg = "Command \"%s\" failed with '%d'" % (x.replace("\n", "\\n"), ret)
    error(msg) if fail else warn(msg)
  return ret

def exe_output(x, sep=";"):
  out = subprocess.check_output(x, shell=True)
  if isinstance(out, (bytes, bytearray)):
    out = out.decode()
  return out.replace("\n", sep)

def exe2list(x, sep=' ', debug=False):
  res = str2list(exe_output(x, sep))
  if debug: printc('exe2list(%s) = %s' % (x, str(res).replace(', u', ', ')), color.BLUE)
  return res

def exe_one_line(x, field=None, debug=False):
  def print1(x): printf(x, std=sys.stdout, col=color.BLUE) if debug else None
  x_str = 'exe_one_line(%s, f=%s)' % (x, str(field))
  print1('%s = ' % x_str)
  try:
    res = exe_output(x, '')
  except subprocess.CalledProcessError:
    warn('%s failed!' % x_str)
    res = 'N/A'
  if field is not None: res = str2list(res)[field]
  print1('%s\n' % res)
  return res

def par_jobs_file(commands, name=None, verbose=False, shell='bash'):
  if not name: name = './.p%d.sh' % os.getpid()
  cmds = open(name, 'w')
  head = ["#!/bin/%s" % shell, "ulimit -s unlimited"]
  if verbose: head += ["set -x"]
  cmds.write('\n'.join(head + [""]))
  while len(commands) > 1:
    cmds.write("%s &\n" % commands.pop(0))
  cmds.write('\n'.join((commands.pop(), '', '')))
  cmds.close()
  return name

import glob as python_glob
def glob(regex):
  fs = python_glob.glob(regex)
  if len(fs) == 0: error("could not find files: %s" % regex)
  return sorted(fs)

# OS
#
def os_installer():
  installer='yum'
  name = file2str('/etc/os-release', 1)
  if 'Ubuntu' in name: installer='apt-get'
  if 'CentOS' in name: installer='dnf'
  return installer

def check_executable(x):
  if not (os.path.isfile(x) and os.access(x, os.X_OK)): error("'%s' is not executable" % x)

def dirname(): return os.path.dirname(__file__)
def realpath(x): return os.path.join(dirname(), x)
def env2int(x, default=0, base=10): y=os.getenv(x); return int(y, base) if y else default
def env2str(x, default=0, prefix=0): y = os.getenv(x); return '%s%s' % (x+'=' if prefix else '', y) if y else default
def env2list(x, default): y = os.getenv(x); return y.split() if y else default
def envfile(x): x = os.getenv(x); return x if x and os.path.isfile(x) else None

def print_env(std=sys.stderr):
  for k, v in sorted(os.environ.items()):
    std.write('%s: %s\n' % (k, v))

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

def file2str(f, lines=0):
  out = file2lines(f)
  return ';'.join(out[:lines] if lines else out).replace('\n', '') if out[0] else None

# (colored) grep with 0 exit status
def grep(what, file='', flags='', color=False):
  cmd = "egrep %s '%s' %s" % (flags, what, file)
  if color: cmd = 'script -q /dev/null -c "%s"' % cmd.replace('egrep', 'egrep --color')
  return "(%s || true)" % cmd

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

def iter2str(x, sep=",\n\t"):
  return str(x).replace("', ", ":\t").replace("), ('", sep).replace("[('", '').replace(')]', '\n')
def dict2str(d, sep=",\n\t"): return iter2str(sorted(d.items()), sep)
def hist2str(h, top=20): return iter2str(hist2slist(h)[-top:])
def hist2slist(h): return sorted(h.items(), key=lambda x: x[1])

# chop - clean a list of charecters from a string
# @s:     input string
# @stuff: input charecters as string, or a first item in a tuple of strings
CHOP_STUFF='./~<>=,;{}|"\': '
def chop(source, stuff=CHOP_STUFF):
  r, chars = source, stuff
  items = []
  if type(stuff) is tuple:
    items = [ stuff[x] for x in range(1, len(stuff)) ]
    chars = stuff[0]
  for i in range(len(chars)): items += [chars[i]]
  for x in items: r = r.replace(x, '')
  return r.strip()

def any_in(l, s):
  for i in l:
    if i in s: return 1
  return 0

def is_num(x, hex=False):
  try:
    int(x, 16) if hex else float(x)
    return True
  except ValueError:
    return False

def float2str(f): return f if not is_num(f) else '{:,}'.format(f)
def flag2str(prefix, flag): return '%s%s' % (prefix, str(flag).replace('True', '')) if flag else ''
def flag_value(s, f, sep=' '): return s.split(f)[1].split(sep)[1] if f in s else None
def str2list(s):  return ' '.join(s.split()).split(' ')

def arg(num, default=None):
  if len(sys.argv) <= num and not default: error("must provide %d parameters" % num)
  a = sys.argv[num] if len(sys.argv) > num else default
  return a.replace('./', '') if num == 0 else a

def argv2str(start=0):
  res = []
  for a in sys.argv[start:]:
    res.append("\"%s\"" % a if "'" in a else "'%s'" % a if (' ' in a or a == '') else a)
  return ' '.join(res)

def args_parse(d, args):
  for x in args.split(','):
    if len(x):
      assert '=' in x, "expect '=' as deliminer in '%s'" % args
      arg, val = x.split('=')
      assert arg in d, "unknown option '%s' in '%s'!" % (arg, args)
      d[arg] = int(val) if val.isdigit() else val
  return d

import argparse
RUN_DEF = './run.sh'
TOPLEV_DEF=' --frequency --metric-group +Summary'
  #' --no-uncore' # https://github.com/andikleen/pmu-tools/issues/450
PROF_MASK_DEF=0x317F
def add_hex_arg(ap, n, fn, d, h):
  ap.add_argument(n, fn, type=lambda x: int(x, 16), default=d, help='mask to control ' + h)
def argument_parser(usg, defs=None, mask=PROF_MASK_DEF, fc=argparse.ArgumentDefaultsHelpFormatter):
  ap = argparse.ArgumentParser(usage=usg, formatter_class=fc) if usg else argparse.ArgumentParser(formatter_class=fc)
  common_args = []
  def common_def(a):
    common_args.append(a)
    return defs[a] if defs and a in defs else None
  def add_argument(a, h): ap.add_argument('--' + a, default=common_def(a), help=h)
  def add_argument2(a, h, d=None): ap.add_argument('--'+a, '-'+a[0], default=common_def(a), help=h)
  add_argument('perf', 'use a custom perf tool')
  add_argument('pmu-tools', 'use a custom pmu-tools')
  add_argument('toplev-args', 'arguments to pass-through to toplev')
  add_argument2('events', 'user events to pass to perf-stat\'s -e')
  add_argument2('metrics', 'user metrics to pass to perf-stat\'s -M')
  add_argument2('nodes', 'user metrics to pass to toplev\'s --nodes')
  if not usg: return common_args
  ap.add_argument('-r', '--repeat', default=3, type=int, help='times to run per-app counting and topdown-primary profile steps')
  ap.add_argument('-a', '--app', default=RUN_DEF, help='name of user-application/kernel/command to profile')
  ap.add_argument('-v', '--verbose', type=int, default=0, help='verbose level; 0:none, 1:commands, '
    '2:+verbose-on metrics|build|sub-commands, 3:+toplev --perf|ASM on kernel build, 4:+args parsing, '
    '5:+event-groups, 6:ocperf verbose, .. 9:anything')
  add_hex_arg(ap, '-pm', '--profile-mask', mask, 'stages in the profile command. See profile-mask-help.md for details')
  ap.add_argument('--tune', nargs='+', help=argparse.SUPPRESS, action='append') # override global variables with python expression
  return ap

def commands_list():
  return chop(exe_output("egrep 'elif c (==|in) ' %s | cut -d\\' -f2- | cut -d: -f1 | sort"%sys.argv[0], sep=' '), "),'")

def command_basename(comm, iterations=None):
  if comm is None or comm.isdigit(): return 'run%d' % (int(comm) if comm else os.getpid())
  name = comm.strip().split(' ')
  if not len(name) or not len(name[0]): error("empty command/name")
  elif len(name) > 2:
    for x in ('taskset', 'bash', 'omp-bin', 'n-copies', 'n-loop'):
      if x == name[0] or name[0].endswith('/'+x):
        assert (not name[2].startswith('-') or len(name) > 4), "invalid syntax for '%s'" % name[0]
        name = name[(4 if name[2].startswith('-') else 2):]
        break
  if '/' in name[0]:
    check_executable(name[0].replace("'", ''))
    name[0] = name[0].split('/')[-1].replace('.sh', '')
  if len(name) == 1 and ('kernels' in comm or iterations): assert iterations; name.append(iterations)
  namestr = name.pop(0)
  for x in name: namestr += "-%s" % x.strip('-')
  return chop(namestr.strip('-'))

# stats
def inc(d, b, i=1): d[b] = d.get(b, 0) + i
def ratio(a, b, denom='total'):
  r = '%.1f%%' % (100.0 * b[a] / max(b[denom], 1) if type(b) is dict else 100.0 * a / b)
  return '%s-ratio: %s' % (a, r) if type(b) is dict else r
