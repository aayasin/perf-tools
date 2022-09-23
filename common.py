#!/usr/bin/env python
# common functions for logging, debug, strings, system commands and file I/O.
# Author: Ahmad Yasin
# edited: Sep 2022
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
  ORANGE    = '\033[33m'
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

def warn(msg, bold=False, col=color.ORANGE, level=0):
  WARN = env2int('WARN')
  if bold: col += color.BOLD
  if level <= WARN: printc('WARNING: %s' % msg, col)

dump_stack_on_error = 0
def error(msg):
  printc('ERROR: %s !'%msg, color.RED)
  logs = [log[1] for log in re.findall(r"(>|tee) (\S+\.log)", msg) if log[1][0].isalpha()]
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
# @log:   log the commands's output into log_stdout (if any)
# @background: run the specified command in background (do not block)
def exe_cmd(x, msg=None, redir_out=None, debug=False, run=True, log=True, background=False):
  if redir_out: x = x.replace(' |', redir_out + ' |', 1) if '|' in x else x + redir_out
  if msg:
    if '@' in msg: msg='\t' + msg.replace('@', '')
    else: msg = msg + ' ..'
    if run or msg.endswith('..'): printc(msg, color.BOLD)
  if debug: printc(x, color.BLUE)
  sys.stdout.flush()
  if log and log_stdout: x = x + ' | tee -a ' + log_stdout
  if background: return Popen(x.split())
  ret = os.system(x) if run else 0
  if ret!=0: error("Command failed: " + x.replace("\n", "\\n"))

def exe_output(x, sep=";"):
  out = check_output(x, shell=True)
  if isinstance(out, (bytes, bytearray)):
    out = out.decode()
  return out.replace("\n", sep)

def exe2list(x, debug=False):
  res = str2list(exe_output(x, ' '))
  if debug: printc('exe2list(%s) = %s' % (x, str(res).replace(', u', ', ')), color.BLUE)
  return res

def exe_one_line(x, field=None, debug=False):
  res = exe_output(x, '')
  if field is not None: res = str2list(res)[field]
  if debug: printc('exe_one_line(%s, f=%s) = %s' % (x, str(field), res), color.BLUE)
  return res

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
  if not os.access(x, os.X_OK): error("'%s' is not executable" % x)

def dirname(): return os.path.dirname(__file__)

def env2int(x, default=0, base=10):
  return int(os.getenv(x), base) if os.getenv(x) else default

def env2str(x):
  y = os.getenv(x)
  return '%s=%s' % (x, y) if y else ''

def envfile(x):
  x = os.getenv(x)
  return x if x and os.path.isfile(x) else None

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

def dict2str(d):
  return str(sorted(d.items())).replace("', ", ":\t").replace("), ('", ",\n\t").replace("[('", '\t').replace(')]', '\n')

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
def chop_app(a): return chop(a, './~<>=,;{}|"\'')

def any_in(l, s):
  for i in l:
    if i in s: return 1
  return 0

def flag_value(s, f, v='', sep=' '):
  if f in s: v = s.split(f)[1].split(sep)[1]
  return v

def str2list(s):
  return ' '.join(s.split()).split(' ')

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

def commands_list():
  return chop(exe_output("egrep 'elif c (==|in) ' %s | cut -d\\' -f2- | cut -d: -f1 | sort"%sys.argv[0], sep=' '), "),'")

def command_basename(comm, iterations=None):
  if comm is None or comm.isdigit(): return 'run%d' % (int(comm) if comm else os.getpid())
  name = comm.strip().split(' ')
  for x in ('taskset', 'bash', 'omp-bin', 'n-copies', 'n-loop'):
    if x in name[0]: name = name[(4 if name[2].startswith('-') else 2):]
  if '/' in name[0]:
    check_executable(name[0])
    name[0] = name[0].split('/')[-1].replace('.sh', '')
  if len(name) == 1 and ('kernels' in comm or iterations): name.append(iterations)
  namestr = name.pop(0)
  for x in name: namestr += "-%s" % x.strip('-')
  return chop_app(namestr.strip('-'))

# stats
def ratio(x, histo, denom='total'):
  return '%s-ratio: %.1f%%'%(x, 100.0*histo[x]/max(histo[denom], 1))

