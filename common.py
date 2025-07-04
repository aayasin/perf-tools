#!/usr/bin/env python3
# Copyright (c) 2020-2024, Intel Corporation
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

import os, pickle, re, subprocess, sys, inspect
from datetime import datetime

# logging
#
class color:
  BLACK     = '\033[0m'
  BLUE      = '\033[94m'
  CYAN      = '\033[96m'
  DARKCYAN  = '\033[36m'
  DARKGREEN = '\033[32;1m'
  GREY      = '\033[90m'
  GREEN     = '\033[92m'
  MAGENTA   = '\033[35m'
  ORANGE    = '\033[33m'
  PURPLE    = '\033[95m'
  RED       = '\033[91m'
  YELLOW    = '\033[93m'
  BLINK = '\033[5m'
  BOLD = '\033[1m'
  UNDERLINE = '\033[4m'
  END = '\033[0m'

Globals = {'exe-prefix': '',
           'llvm-mca':   '/usr/local/bin/llvm-mca',
           'time':       '/usr/bin/time',
           'uica':       'uiCA/uiCA.py',
           'xed':        '/usr/local/bin/xed',
}

# append to a file
def fappend(text, filename, end='\n'):
  with open(filename, 'a') as f: f.write(text + end)

# colored printing, writes to outfile or log_stdio
def printc(msg, col=color.DARKCYAN, log_only=False, outfile=None):
  msg = col + msg + color.END
  if not log_only: print(msg)
  if not outfile: outfile = log_stdio
  if outfile: fappend(msg, outfile)
  return msg
log_stdio=None
# colored & timestamped printing
def printct(msg, col=color.DARKCYAN, log_only=False):
  return printc(msg.replace('@@', datetime.now().strftime('%Y-%m-%d %H:%M:%S')), col=col, log_only=log_only)

log_db = {'info': {}, 'warn': {}}
def warning(type='warn'): return ('warning' if type == 'warn' else type).upper()
def warn(msg, bold=False, col=color.ORANGE, level=0, suppress_after=3, type='warn', extra=None):
  inc(log_db[type], msg)
  if suppress_after and log_db[type][msg] > suppress_after: return
  if bold: col += color.BOLD
  if type == 'warn':
    WARN = env2int('WARN')
    if level > WARN: return
  suffix = extra if type == 'info' else ('; suppressing' if log_db[type][msg] == suppress_after else '')
  printc('%s: %s%s' % (warning(type), msg, suffix), col)
  if env2int('TRACEBACK'):
    frame = inspect.currentframe().f_back
    printc("Traceback (most recent call last):\n" + ''.join(traceback.format_stack(frame)))
def warn_summary(type='warn', top=20):
  if len(log_db[type]): print('Top %ss: (%d total unique)\n' % (warning(type), len(log_db[type])), hist2str(log_db[type], top))
def info_p(msg, extra):
  return warn(msg, col=color.GREY, type='info', suppress_after=1, extra='; %s' % extra if extra else '.')
def info(msg):  return info_p(msg, None)

def error(msg):
  # get caller info
  frame = inspect.currentframe().f_back
  module = inspect.getmodule(frame).__name__
  if module == '__main__': module = os.path.basename(sys.argv[0]).replace('.py', '')
  to_print = ''
  if env2int('TRACEBACK'):
    to_print += "Traceback (most recent call last):\n" + ''.join(traceback.format_stack(frame))
  to_print += printc('ERROR in module %s at function %s() in line %s: %s !' %
         (module, inspect.getframeinfo(frame).function, frame.f_lineno, msg), color.RED, log_only=True)
  logs = [log[1] for log in re.findall(r"(>|tee) (\S+\.log)", msg) if log[1][0].isalpha()]
  if len(logs): exe_cmd('tail ' + ' '.join(set(logs)), debug=True)
  sys.exit(to_print)

def exit(msg=None):
  printc('%s ..' % str(msg), color.GREEN)
  sys.exit('exiting' if msg else 0)

# OS
#
def os_release(): return file2str('/etc/os-release', 1)
def os_installer():
  installer, name = 'yum', os_release()
  if 'Ubuntu' in name or 'Debian' in name: installer='apt-get'
  if 'CentOS' in name: installer='dnf'
  if 'SUSE' in name: installer='zypper'
  return installer

def check_executable(x):
  if not (os.path.isfile(x) and os.access(x, os.X_OK)): error("'%s' is not executable" % x)

def dirname(): return os.path.dirname(__file__)
def realpath(x): return os.path.join(dirname(), x)
def env2int(x, default=0, base=10): y=os.getenv(x); return int(y, base) if y else default
def env2float(x, default=0): y=os.getenv(x); return float(y) if y else default
def env2str(x, default=0, prefix=0): y = os.getenv(x); return '%s%s' % (x+'=' if prefix else '', y) if y else default
def env2list(x, default): y = os.getenv(x); return y.split() if y else default
def envfile(x): x = os.getenv(x); return x if isfile(x) else None
def env2int_bo(x, val, base=10): return int(env2int(x)) | val # read & return a bitwise-or (bo) of int env var

def print_env(std=sys.stderr):
  for k, v in sorted(os.environ.items()):
    std.write('%s: %s\n' % (k, v))

#debug
#
#print (to stderr) and flush
def printf(x, flush=True, std=sys.stderr, col=color.GREY):
  std.write(col + x + color.END)
  if flush: std.flush()

import traceback
def annotate(stuff, label='', stack=False):
  xs = stuff if type(stuff) is tuple else [stuff]
  printf('%s: '%label, flush=False)
  if stack: traceback.print_stack()
  for x in xs: printf('%s of %s; '%(str(x), type(x)), flush=False)
  printf('.\n')

def log_callchain():
  tb=traceback.format_list(traceback.extract_stack())
  t = [x.split('\n')[1].strip() for x in tb[:-2]]
  printc('\t==> '.join(t), col=color.GREY)

# cpu type
#
Globals['cputype'] = env2str('CPUTYPE', 'core')

def cputype_prefix():
  t = Globals['cputype']
  if t == 'core': return ''
  elif t == 'atom':
    for c in subprocess.check_output([os.path.dirname(os.path.realpath(__file__)) +
      "/pmu-tools/cputop", "offline", "online"]).decode().strip().split('\n'):
      os.system(c)
    return subprocess.check_output(
      os.path.dirname(os.path.realpath(__file__)) +
      "/pmu-tools/cputop atom taskset", shell=True).decode().strip() + ' '
  else: error('unrecognized CPUTYPE value')
def main_core():
  pre = cputype_prefix()
  return '0' if pre == '' else pre.replace('taskset -c', '').strip().split(',')[0]
Globals['exe-prefix'] = cputype_prefix()

def append_prefix(cmd):
  cmd, pre = bash(cmd), ''
  if 'taskset' in Globals['exe-prefix'] and not Globals['exe-prefix'] in cmd:
    # deal with leading env variables
    match = re.match(r'^((?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s*)+)', cmd)
    env = match.group(1).strip() if match else ''
    cmd = cmd.replace(env, '')
    pre = '%s%s' % (env, (' ' if env != '' else '') + Globals['exe-prefix'])
  return cmd.replace('(', '(%s' % pre, 1) if cmd.startswith('(') else pre + cmd

# system
#
def bash(x, win=False, px=None):
  if 'bash -c' in x: return x
  opers = ('&&', '||', ';', '&', '|', '>', '<', 'cmd', '*', '?', '~')
  cond = (('tee >(' in x or x.startswith(Globals['time']) or px) and not win) or (win and px) \
         or ('taskset' in Globals['exe-prefix'] and
             ('builtin' in subprocess.check_output
             ('bash -c "type %s" 2>&1' % x.split()[0].replace('(', ''), shell=True).decode() or
              any_in(opers, x)))
  if cond: x = x.replace(Globals['exe-prefix'], '')
  return '%s bash -c "%s" 2>&1' % (px or '', x.replace('"', '\\"').replace('$', '\$')) if cond else x

# exe_cmd - execute system command(s) with logging support
# @x:     command to be executed
# @msg:   an informative message to display. @ hints for a "slave" command
# @debug: print the command before its execution
# @redir_out:  redirect output of the (first non-piped) command as specified
# @run:   do run the specified command
# @log:   log the command's output into log_stdio (if any)
# @fail:  1: exit with error if command fails; 0: warn; -1: no-warn
# @background: run the specified command in background (do not block)
def exe_cmd(x, msg=None, redir_out=None, debug=0, run=True, log=True, fail=1, background=False):
  if redir_out: x = x.replace(' |', redir_out + ' |', 1) if '|' in x else x + redir_out
  x = x.replace('| ./', '| %s/' % dirname())
  if x.startswith('./'): x = x.replace('./', '%s/' % dirname(), 1)
  if msg:
    if '@' in msg: msg='\t' + msg.replace('@', '')
    else: msg = msg + ' ..'
    if run or msg.endswith('..'): printc(msg, color.BOLD)
  x = append_prefix(x)
  if debug > 1: printct('@@\t' + x, color.BLUE)
  elif debug: printc(x, color.BLUE)
  sys.stdout.flush()
  if background: return subprocess.Popen(x.split())
  ret = 0
  if run:
    if log and log_stdio:
      if '2>&1' not in x: x = x + ' 2>&1'
      x = x + ' | tee -a ' + log_stdio
      ret = subprocess.call(['/bin/bash', '-c', 'set -o pipefail; ' + x])
    else:
      ret = os.system(x)
  if ret != 0:
    msg = "Command \"%s\" failed with '%d'" % (x.replace("\n", "\\n"), ret)
    error(msg) if fail > 0 else (None if fail else warn(msg))
  return ret

def exe_output(x, sep=";"):
  x = append_prefix(x)
  out = subprocess.check_output(x, shell=True)
  if isinstance(out, (bytes, bytearray)):
    out = out.decode()
  return out.replace("\n", sep).strip(sep)

def exe2list(x, sep=' ', debug=False):
  x = append_prefix(x)
  res = str2list(exe_output(x, sep))
  if debug: printc('exe2list(%s) = %s' % (x, str(res).replace(', u', ', ')), color.BLUE)
  return res

# @fail:  1: exit with error if command fails; 0: warn
def exe_one_line(x, field=None, debug=False, fail=0):
  x = append_prefix(x)
  def print1(x): printf(x, std=sys.stdout, col=color.BLUE) if debug else None
  x_str = 'exe_one_line(%s, f=%s)' % (x, str(field))
  cached = x in exe_one_line.cache
  if cached:
    res = exe_one_line.cache[x]
  else:
    print1('%s = ' % x_str)
    try:
      res = exe_output(x, '')
    except subprocess.CalledProcessError:
      (error if fail else warn)('%s failed!' % x_str)
      res = 'N/A'
    exe_one_line.cache[x] = res
  if field is not None: res = str2list(res)[field]
  if not cached: print1('%s\n' % res)
  return res
exe_one_line.cache = {}

def isfile(f): return f and os.path.isfile(f)
def ptage(r=2): return 'PTAGE_R=%d %s/ptage' % (r, dirname())
def tail(f=''): return "tail -11 %s | %s" % (f, grep('=total|^\s+0', flags='-v'))

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
def glob(regex, forgive=0):
  fs = python_glob.glob(regex)
  if len(fs) == 0 and not forgive: error("could not find files: %s" % regex)
  return sorted(fs)

# files
#
def open_r(filename, debug=False):
  if debug: print('reading %s' % filename)
  return open(filename, mode='r')

def file2lines(filename, fail=False, pop=False, debug=False):
  try:
    with open_r(filename, debug) as f:
      lines = f.read().splitlines()
      if pop: lines.pop()
      return lines
  except IOError:
    if fail: error('cannot open %s'%filename)
    else:
      warn('cannot open %s'%filename, bold=True)
      return [None]

def file2str(f, lines=0):
  out = file2lines(f)
  return ';'.join(out[:lines] if lines else out).replace('\n', '') if out[0] else None

def csv2dict(f):
  d = {}
  for l in file2lines(f):
    k = l.split(',')[0]
    #if not re.match(r'^[A-Z]', k): k = k[1:]
    d[k] = l.split(',')[1]
  return d

def zprefix(file): return 'z' if file.endswith(('.gz', '.zip')) else ''

# (colored) grep with 0 exit status
def grep(what, file='', flags='', color=False, empty_lines=True):
  cmd = "%sgrep -E %s '%s' %s%s" % (zprefix(file), flags, what, file, "" if empty_lines else " | grep -v '^$'")
  if color: cmd = 'script -q /dev/null -c "%s"' % cmd.replace('grep', 'grep --color')
  return "(%s || true)" % cmd
# grep lines from start till end or max lines
def grep_start_end(start, end, log, max=33):
  return "%s | sed '/%s/q'" % (grep(start, log, '-A%d' % max, empty_lines=False), end)

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
  return str(x).replace("', ", ":\t").replace("), ('", sep).replace("[('", '\t').replace(')]', '\n')
def dict2str(d, sep=",\n\t"): return iter2str(sorted(d.items()), sep)
def hist2str(h, top=20): return iter2str(hist2slist(h)[-top:])
def hist2slist(h): return sorted(h.items(), key=lambda x: x[1])

# chop - clean a list of characters from a string
# @s:     input string
# @stuff: input characters as string, or a first item in a tuple of strings
CHOP_STUFF='/~<>=,;{}[]()|"\': '
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
    if i in s: return True
  return False

# 0-9 -> 0-9
# 10-35 -> a-z
# 36-63 -> A-Z
def num2char(n):
  if n < 10: return str(n)
  if n < 36: return chr(ord('a') + n - 10)
  return chr(ord('A') + n - 36)

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
  a = sys.argv[num] if len(sys.argv) > num and sys.argv[num] != '-' else default
  return a.replace('./', '') if num == 0 else a

def argv2str(start=0):
  res = []
  for a in sys.argv[start:]:
    res.append("\"%s\"" % a if "'" in a else "'%s'" % a if (any(x in a for x in "'{ ") or a == '') else a)
  return ' '.join(res)

def args_parse(d, args):
  for x in args.split(','):
    if len(x):
      assert '=' in x, "expect '=' as delimiter in '%s'" % args
      arg, val = x.split('=')
      assert arg in d, "unknown option '%s' in '%s'!" % (arg, args)
      d[arg] = int(val) if val.isdigit() else val
  return d

import argparse
RUN_DEF = './run.sh'
TOPLEV_DEF=' --frequency --metric-group +Summary'
  #' --no-uncore' # https://github.com/andikleen/pmu-tools/issues/450
PROF_MASK_DEF = 0x313F if Globals['cputype'] == 'core' else 0x10F
  # FIXME: enable topdown steps by default for atom

class CustomFormatter(argparse.ArgumentDefaultsHelpFormatter,
                      argparse.RawDescriptionHelpFormatter):
  pass
def argument_parser(usg, defs=None, mask=PROF_MASK_DEF, fc=CustomFormatter, epilog=None):
  ap = argparse.ArgumentParser(usage=usg, formatter_class=fc, epilog=epilog) if usg else argparse.ArgumentParser(formatter_class=fc)
  common_args = []
  def common_def(a): common_args.append(a); return def_value(a)
  def def_value(a, dv=None): return defs[a] if defs and a in defs else dv
  def add_argument(a, h): ap.add_argument('--' + a, default=common_def(a), help=h)
  def add_argument2(a, h): ap.add_argument('--'+a, '-'+a[0], default=common_def(a), help=h)
  def add_prof_arg(a): ap.add_argument('--'+a, '-'+a[0], type=float, default=common_def(a),
                                       help=a.replace('sys-', 'system-') + ' profiling for x seconds (float ok too)')
  add_argument('perf', 'use a custom perf tool')
  add_argument('pmu-tools', 'use a custom pmu-tools')
  add_argument('toplev-args', 'arguments to pass-through to toplev')
  add_argument2('events', 'user events to pass to perf-stat\'s -e')
  add_argument2('metrics', 'user metrics to pass to perf-stat\'s -M')
  add_argument2('nodes', 'user metrics to pass to toplev\'s --nodes')
  add_prof_arg('sys-wide')
  add_prof_arg('delay')
  ap.add_argument('--cpu', '-C', help='filter profiling on selected CPUs')
  if not usg: return common_args
  ap.add_argument('-r', '--repeat', default=3, type=int, help='times to run per-app counting and topdown-primary profile steps')
  ap.add_argument('-a', '--app', default=def_value('app', RUN_DEF), help='name of user-application/kernel/command to profile')
  ap.add_argument('-v', '--verbose', type=int, default=def_value('verbose', 0),
    help='verbose level; -1: quiet; 0:info, 1:commands, '
    '2:+verbose-on metrics|build|sub-commands, 3:+toplev --perf|ASM on kernel build|greedy lbr.py, 4:+args parsing, '
    '5:+event-groups|+perf-script timing, 6:ocperf verbose, .. 9:anything')
  argp_add_hex_arg(ap, '-pm', '--profile-mask', mask, 'stages in the profile command. See profile-mask-help.md for details')
  ap.add_argument('--tune', nargs='+', default=common_def('tune'), help=argparse.SUPPRESS, action='append') # override global variables with python expression
  return ap
def argp_add_hex_arg(ap, n, fn, d, h):
  ap.add_argument(n, fn, type=lambda x: int(x, 16), default=d, help='mask to control ' + h)
def argp_get_common(args):
  r = ''
  for x in argument_parser(None):
    a = getattr(args, x.replace('-', '_'))
    if a: r += ' --%s %s' % (x, "'%s'" % a if type(a) is str and any_in(' {', a) else str(a))
  return r
def argp_tune_prepend(args, prep):
  tune = getattr(args, 'tune') or []
  tune.insert(0, [prep])
  return ' --tune ' + ' '.join([' '.join(i) for i in tune])

def commands_list(extra_cmds):
  return ' '.join(chop(exe_output("grep -E 'elif c (==|in) ' %s | cut -d\\' -f2- | cut -d: -f1 | sort" % sys.argv[0], sep=' '), "),'").split() +
         [("%s-" % c) + x[:-1].replace("'", '') for x in exe_output(grep('com2cond =', sys.argv[0]), sep='').split()
         if x.endswith(':') for c in ['enable', 'disable', 'suspend']] + extra_cmds)

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
    if not name[0] == RUN_DEF: check_executable(name[0].replace("'", ''))
    name[0] = name[0].split('/')[-1].replace('.sh', '').replace('.py', '')
  if len(name) == 1 and ('kernels' in comm or iterations): assert iterations; name.append(iterations)
  namestr = name.pop(0)
  for x in name: namestr += "-%s" % x.strip('-')
  return chop(namestr.strip('-'))

# stats
def inc(d, b, i=1): d[b] = d.get(b, 0) + i
def ratio(a, b, denom='total'):
  r = '%.1f%%' % (100.0 * b[a] / max(b[denom], 1) if type(b) is dict else 100.0 * a / b)
  return '%s-ratio: %s' % (a, r) if type(b) is dict else r
