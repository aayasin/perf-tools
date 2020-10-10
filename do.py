#!/usr/bin/env python2
# Misc utilities for CPU performance analysis on Linux
# Author: Ahmad Yasin
# edited: October 2020
# TODO list:
#   check sudo permissions
#   auto-produce options for 'command' help
__author__ = 'ayasin'

import argparse, sys
from os import system
#from subprocess import check_output

do = {'no-mux': 1,
      'run':    './run.sh',
      'info-metrics': "--nodes '+CoreIPC,+UPI,+Time,+MUX'",
      'kernel-iterations': 1000000000
}
args = []

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

def exe(x, msg='Null', redir_out=' 2>&1'):
  x = x.replace('|', redir_out + ' |', 1) if '|' in x else x + redir_out
  if not msg == 'Null':
      print color.BOLD + msg.replace('@', '') + ' ..' + color.END
      if '@' in msg: print '\t%s'%x
      sys.stdout.flush()
  return system(x)

def parse_args():
  def get_commands():
      #return check_output("grep elif %s | cut -d\\' -f2"%sys.argv[0], shell=True)
      exe("grep elif %s | grep -v grep | cut -d' ' -f8"%sys.argv[0])
  ap = argparse.ArgumentParser()
  ap.add_argument('command', nargs='+', help='supported options: ' \
      'setup-perf log profile tar, all (for these 4)' \
      '\n\t\t\t[disable|enable]-smt tools-update build')
  ap.add_argument('--perf', default='perf', help='use a custom perf tool')
  ap.add_argument('-g', '--gen-args', help='args to gen-kernel.py')
  ap.add_argument('-a', '--app-name', help='name of kernel')
  x = ap.parse_args()
  return x

def tools_update():
  exe('git pull')
  exe('git submodule update --remote')
  exe("./pmu-tools/event_download.py")

def setup_perf():
  exe("printf ''", 'setting up perf')
  cmds=["echo 0     | sudo tee /proc/sys/kernel/nmi_watchdog",
    "echo 0     | sudo tee /proc/sys/kernel/soft_watchdog",
    "echo 0     | sudo tee /proc/sys/kernel/kptr_restrict",
    "echo -1    | sudo tee /proc/sys/kernel/perf_event_paranoid",
    "echo 100   | sudo tee /sys/devices/cpu/perf_event_mux_interval_ms",
    "echo 60000 | sudo tee /proc/sys/kernel/perf_event_mlock_kb"]
  for c in cmds: exe(c)

def smt(x='off'):
  exe('echo %s | sudo tee /sys/devices/system/cpu/smt/control'%x)

def profile():
  perf=args.perf
  r = do['run']
  exe(perf + ' stat '+r+' | tee run-perf_stat.log | egrep "seconds|CPUs|GHz|insn"', 'basic counting')
  exe(perf + ' record -g '+r, 'sampling w/ stacks')
  exe(perf + " report --stdio --hierarchy --header | grep -v '0\.0.%' | tee run-perf-modules.log " \
    "| grep -A11 Overhead", '\treport modules')
  exe(perf + " annotate --stdio | c++filt | tee run-perf-code.log " \
    "| egrep -v -E ' 0\.[0-9][0-9] :|^\s+:($|\s+(Disassembly of section .text:|//|#include))' " \
    "| tee run-perf-code_nonzero.log | head -20", '\tannotate code', '2>/dev/null')
  
  toplev = '' if perf is 'perf' else 'PERF=%s '%perf
  toplev+= './pmu-tools/toplev.py --no-desc --no-perf %s'%do['info-metrics']
  grep_bk= "egrep '<==|MUX'"
  exe(toplev+' -vl6 -- '+r+' | tee run-toplev-vl6.log | %s'%grep_bk, 'topdown full')
  exe(toplev+'  -l3 -- '+r+' | tee run-toplev-l3.log', '@topdown 3-levels')
  exe(toplev+' -vl3 -- '+r+' > run-toplev-vl3.log', 'topdown 3-levels unfiltered')
  out = 'run-toplev-vl6-nomux.log'
  if do['no-mux']: exe(toplev+' -vl6 --metric-group +Summary,+HPC --no-multiplex -- '+r+' | tee %s ' \
    '| grep RUN && %s %s'%(out, grep_bk, out), 'topdown full no multiplexing')

def log_setup():
  exe('lscpu > setup-lscpu.log', 'logging setup')
  out = 'setup-system.log'
  exe('uname -a > ' + out)
  exe('%s --version >> '%args.perf + out)
  exe('cat /etc/os-release >> ' + out)
  #exe('cat /etc/lsb-release >> ' + out)
  exe('numactl -H >> ' + out)

def gen_tar():
  exe('tar -czvf results.tar.gz run.sh *.log')

def build_kernel():
  app = args.app_name
  exe('./kernels/gen-kernel.py %s > ./kernels/%s.c'%(args.gen_args, app), 'building kernel: ' + app)
  exe('head -2 ./kernels/%s.c'%(app))
  exe('gcc -g -O2 -o ./kernels/%s ./kernels/%s.c'%(app, app))
  do['run'] = './kernels/%s %d'%(app, do['kernel-iterations'])

def main():
  global args
  args = parse_args()
  for c in args.command:
    if   c == 'forgive-me':   pass
    elif c == 'setup-perf':   setup_perf()
    elif c == 'tools-update': tools_update()
    elif c == 'disable-smt':  smt()
    elif c == 'enable-smt':   smt('on')
    elif c == 'log':          log_setup()
    elif c == 'profile':      profile()
    elif c == 'tar':          gen_tar()
    elif c == 'all':
      setup_perf()
      log_setup()
      profile()
      gen_tar()
    elif c == 'build':        build_kernel()
    else:
      sys.exit("Unknown command: '%s' !"%c)
      return -1
  return 0

if __name__ == "__main__":
    main()

