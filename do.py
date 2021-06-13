#!/usr/bin/env python
# Misc utilities for CPU performance analysis on Linux
# Author: Ahmad Yasin
# edited: Jun. 2021
# TODO list:
#   add trials support
#   control prefetches, log msrs
#   quiet mode
#   convert verbose to a bitmask
#   add test command to gate commits to this file
#   support disable nmi_watchdog in CentOS
#   check sudo permissions
from __future__ import print_function
__author__ = 'ayasin'

import argparse, os, sys
import common as C
from platform import python_version

TOPLEV_DEF="--metric-group +Summary,+HPC"
do = {'run':        './run.sh',
  'super':          0,
  'toplev':         TOPLEV_DEF,
  'toplev-levels':  2,
  'nodes':          "+CoreIPC,+Instructions,+CORE_CLKS,+CPU_Utilization,+Time,+MUX", #,+UPI once ICL mux fixed
  'metrics':        "+IpTB,+L2MPKI",
  'extra-metrics':  "+Mispredictions,+IpTB,+BpTkBranch,+IpCall,+IpLoad,+ILP,+UPI",
  'perf-stat-def':  'cpu-clock,context-switches,cpu-migrations,page-faults,instructions,cycles,ref-cycles,branches,branch-misses', #,cycles:G
  'perf-record':    '', #'-e BR_INST_RETIRED.NEAR_CALL:pp ',
  'sample':         1,
  'tee':            1,
  'gen-kernel':     1,
  'numactl':        1,
  'dmidecode':      0,
  'pin':            'taskset 0x4',
  'xed':            0,
  'compiler':       'gcc', #~/tools/llvm-6.0.0/bin/clang',
  'python':         sys.executable,
  'cmds_file':      None,
  'package-mgr':    'apt-get' if 'Ubuntu' in C.file2str('/etc/os-release') else 'yum',
  'pmu':            C.pmu_name(),
}
args = argparse.Namespace()

def exe(x, msg=None, redir_out=' 2>&1', verbose=False, run=True):
  if not do['tee'] and redir_out: x = x.split('|')[0]
  if len(vars(args))>0:
    do['cmds_file'].write(x + '\n')
    verbose = args.verbose > 0
    run = not args.print_only
  return C.exe_cmd(x, msg, redir_out, verbose, run)
def exe_to_null(x): return exe(x + ' > /dev/null', redir_out=None)
def exe_v0(x='true', msg=None): return C.exe_cmd(x, msg)

def icelake(): return C.pmu_icelake()

def uniq_name():
  return C.command_basename(args.app_name, iterations=(args.app_iterations if args.gen_args else None))

def tools_install(installer='sudo %s install '%do['package-mgr'], packages=['numactl', 'dmidecode']):
  if args.install_perf: packages += ['linux-tools-generic && sudo find / -name perf -executable -type f']
  for x in packages:
    exe(installer + x, 'installing ' + x.split(' ')[0])
  if do['super']: exe('./build-xed.sh', 'installing xed')

def tools_update(kernels=[]):
  ks = [''] + [x+'.c' for x in (C.cpu_peak_kernels() + ['jumpy5p14', 'sse2avx'])] + kernels
  exe('git pull')
  exe('git checkout HEAD run.sh' + ' kernels/'.join(ks))
  exe('git submodule update --remote')
  if do['super']: exe(args.pmu_tools + "/event_download.py ") # requires sudo; add '-a' to download all CPUs

def setup_perf(actions=('set', 'log'), out=None):
  def set_it(p, v): exe_to_null('echo %d | sudo tee %s'%(v, p))
  TIME_MAX = '/proc/sys/kernel/perf_cpu_time_max_percent'
  perf_params = [
    ('/proc/sys/kernel/perf_event_paranoid', -1, ),
    ('/proc/sys/kernel/perf_event_mlock_kb', 60000, ),
    ('/proc/sys/kernel/perf_event_max_sample_rate', int(1e9), 1),
    ('/sys/devices/cpu/perf_event_mux_interval_ms', 100, ),
    ('/proc/sys/kernel/kptr_restrict', 0, ),
    ('/proc/sys/kernel/nmi_watchdog', 0, ),
    ('/proc/sys/kernel/soft_watchdog', 0, ),
  ]
  if 'set' in actions: exe_v0(msg='setting up perf')
  superv = 'sup' in actions or do['super']
  if superv:
    set_it(TIME_MAX, 25)
    perf_params += [('/sys/devices/cpu/rdpmc', 1, ),
      ('/sys/bus/event_source/devices/cpu/rdpmc', 2, )]
  perf_params += [(TIME_MAX, 0, 1)] # has to be last
  for x in perf_params: 
    if (len(x) == 2) or superv:
      param, value = x[0], x[1]
      if 'set' in actions: set_it(param, value)
      if 'log' in actions: exe_v0('printf "%s : %s \n"'%(param, C.file2str(param)) + 
                                  (' >> %s'%out if out != None else ''))

def smt(x='off'):
  exe('echo %s | sudo tee /sys/devices/system/cpu/smt/control'%x)
def atom(x='offline'):
  exe(args.pmu_tools + "/cputop 'type == \"atom\"' %s"%x)

def log_setup(out = 'setup-system.log'):
  def new_line(): exe_v0('echo >> %s'%out)
  C.printc(do['pmu'])
  exe('uname -a > ' + out, 'logging setup')
  exe('cat /etc/os-release | grep -v URL >> ' + out)
  new_line()
  exe("lsmod | tee setup-lsmod.log | egrep 'Module|kvm' >> " + out)
  new_line()
  exe('echo "PMU: %s" >> %s'%(do['pmu'], out))
  exe("lscpu | tee setup-lscpu.log | egrep 'family|Model|Step' >> " + out)
  new_line()
  exe('%s --version >> '%args.perf + out)
  setup_perf('log', out)
  exe('echo "python version: %s" >> %s'%(python_version(), out))
  new_line()
  
  if do['numactl']: exe('numactl -H >> ' + out)
  
  if do['dmidecode']: exe('sudo dmidecode > setup-memory.log')

def perf_format(es, result=''):
  for e in es.split(','):
    if ':' in e:
      ok = True
      e = e.split(':')
      if e[0].startswith('r'):
        if len(e[0])==5:   e='cpu/event=0x%s,umask=0x%s,name=%s/'%(e[0][3:5], e[0][1:3], e[1])
        elif len(e[0])==7: e='cpu/event=0x%s,umask=0x%s,cmask=0x%s,name=%s/'%(e[0][5:7], e[0][3:5], e[0][1:3], e[1])
        else: ok = False
      else: ok = False
      if not ok: C.error("profile:perf-stat: invalid syntax in '%s'"%':'.join(e))
    result += (e if result=='' else ','+e)
  return result

def profile(log=False, out='run'):
  def en(n): return args.profile_mask & 2**n
  def a_events():
    def power(rapl=['pkg', 'cores', 'ram'], px='/,power/energy-'): return px[(px.find(',')+1):] + px.join(rapl) + ('/' if '/' in px else '')
    return power() if args.power and not icelake() else ''
  def perf_stat(flags='', events='', grep='| egrep "seconds [st]|CPUs|GHz|insn|topdown"'):
    def append(x, y): return x if y == '' else ','+x
    perf_args = flags
    if icelake(): events += ',topdown-'.join([c('{slots'),'retiring','bad-spec','fe-bound','be-bound}'])
    if args.events:
      events += append(perf_format(args.events), events)
      grep = '' #keep output unfiltered with user-defined events
    if events != '': perf_args += ' -e %s,%s'%(do['perf-stat-def'], events)
    return '%s stat %s -- %s | tee %s.perf_stat%s.log %s'%(perf, perf_args, r, out, C.chop(flags,' '), grep)
  
  out = uniq_name()
  perf=args.perf
  r = do['run']
  if en(0) or log: log_setup()
  
  if en(1): exe(perf_stat(), 'per-app counting')
  
  if en(2): exe(perf_stat('-a ', a_events(), '| egrep "seconds|insn|topdown|pkg"'), 'system-wide counting')
  
  if en(3) and do['sample']:
    base = out+'.perf'
    if do['perf-record']:
      do['perf-record'] += ' '
      base += C.chop(do['perf-record'], ' :')
    exe(perf + ' record -g -o %s.perf.data '%out+do['perf-record']+r, 'sampling %sw/ stacks'%do['perf-record'])
    exe(perf + " report --stdio --hierarchy --header -i %s.perf.data | grep -v ' 0\.0.%%' | tee "%out+
      base+"-modules.log | grep -A11 Overhead", '@report modules')
    base2 = base+'-code'
    exe(perf + " annotate --stdio -i %s.perf.data | c++filt | tee "%out + base2 + ".log" \
      "| egrep -v -E ' 0\.[0-9][0-9] :|^\s+:($|\s+(Disassembly of section .text:|//|#include))' " \
      "| tee " + base2 + "_nonzero.log > /dev/null " \
      "&& egrep -n -B1 ' ([1-9].| [1-9])\... :|\-\-\-' " + base2 + ".log | grep '^[1-9]' " \
      "| head -20", '@annotate code', '2>/dev/null')
    if do['xed']: exe(perf + " script -i %s.perf.data -F insn --xed | sort | uniq -c | sort -n " \
      "| tee %s-imix.log | tail"%(out, base), '@instructions-mix')
  
  toplev = '' if perf == 'perf' else 'PERF=%s '%perf
  toplev+= (args.pmu_tools + '/toplev.py --no-desc ')
  grep_bk= "egrep '<==|MUX|Info.Bott'"
  grep_nz= "egrep -iv '^((FE|BE|BAD|RET).*[ \-][10]\.. |Info.* 0\.0 |RUN|Add)|not (found|supported)' "
  def toplev_V(v, tag='', nodes=do['nodes'], tlargs=args.toplev_args):
    o = '%s.toplev%s.log'%(out, v.split()[0]+tag)
    return "%s %s --nodes '%s' -V %s %s -- %s"%(toplev, v, nodes,
              o.replace('.log', '-perf.csv'), tlargs, r), o
  
  cmd, log = toplev_V('-vl6')
  if en(4): exe(cmd + ' | tee %s | %s'%(log, grep_bk), 'topdown full')
  
  cmd, log = toplev_V('-vl%d'%do['toplev-levels'])
  if en(5): exe(cmd + ' | tee %s | %s'%(log, grep_nz), 'topdown %d-levels'%do['toplev-levels'])
  
  if en(6):
    cmd, log = toplev_V('--drilldown --show-sample', nodes='+IPC,+Time',
      tlargs='' if args.toplev_args == TOPLEV_DEF else args.toplev_args)
    exe(cmd + ' | tee %s | egrep -v "^(Run toplev|Adding|Using|Sampling|perf record)" '%log, 'topdown auto-drilldown')
    if do['sample']:
      cmd = C.exe_output("grep 'perf record' %s | tail -1"%log)
      exe(cmd, '@sampling on bottleneck')
      perf_data = cmd.split('-o ')[1].split(' ')[0]
      C.printc("Try 'perf report -i %s' to browse sources"%perf_data)
      for c in ('report', 'annotate'):
        exe("%s %s --stdio -i %s > %s "%(perf, c, perf_data, log.replace('toplev--drilldown', 'locate-'+c)), '@'+c)

  if en(7) and args.no_multiplex:
    cmd, log = toplev_V('-vl6 --no-multiplex ', '-nomux', do['nodes'] + ',' + do['extra-metrics'])
    exe(cmd + " | tee %s | %s"%(log, grep_nz)
      #'| grep ' + ('RUN ' if args.verbose > 1 else 'Using ') + out +# toplev misses stdout.flush() as of now :(
      , 'topdown full no multiplexing')

def do_logs(cmd, ext=[]):
  log_files = ['','log','csv'] + ext
  if cmd == 'tar': exe('tar -czvf results.tar.gz run.sh '+ ' *.'.join(log_files) + ' .*.cmd')
  if cmd == 'clean': exe('rm -rf ' + ' *.'.join(log_files + ['pyc']) + ' *perf.data* __pycache__ results.tar.gz ')

def build_kernel(dir='./kernels/'):
  def fixup(x): return x.replace('./', dir)
  app = args.app_name
  if do['gen-kernel']:
    exe(fixup('%s ./gen-kernel.py %s > ./%s.c'%(do['python'], args.gen_args, app)), 'building kernel: ' + app)
    if args.verbose > 3: exe(fixup('head -2 ./%s.c'%app))
  exe(fixup('%s -g -O2 -o ./%s ./%s.c'%(do['compiler'], app, app)), None if do['gen-kernel'] else 'compiling')
  do['run'] = fixup('%s ./%s %d'%(do['pin'], app, int(float(args.app_iterations))))

def parse_args():
  ap = argparse.ArgumentParser(usage='do.py command [command ..] [options]', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  ap.add_argument('command', nargs='+', help='setup-perf log profile tar, all (for these 4) '\
                  '\nsupported options: ' + C.commands_list())
  ap.add_argument('--perf', default='perf', help='use a custom perf tool')
  ap.add_argument('--pmu-tools', default='%s ./pmu-tools'%do['python'], help='use a custom pmu-tools directory')
  ap.add_argument('--toplev-args', default=do['toplev'], help='arguments to pass-through to toplev')
  ap.add_argument('--install-perf', action='store_const', const=True, default=False, help='install the Linux perf tool')
  ap.add_argument('--print-only', action='store_const', const=True, default=False, help='print the commands without running them')
  ap.add_argument('-m', '--metrics', default=do['metrics'], help='user metrics to pass to toplev\'s --nodes')
  ap.add_argument('-e', '--events', help='user events to pass to perf-stat\'s -e')
  ap.add_argument('--power', action='store_const', const=True, default=False, help='collect power metrics/events as well')
  ap.add_argument('-g', '--gen-args', help='args to gen-kernel.py')
  ap.add_argument('-a', '--app-name', default=None, help='name of user-application/kernel/command to profile')
  ap.add_argument('-ki', '--app-iterations', default='1e9', help='num-iterations of kernel')
  ap.add_argument('-pm', '--profile-mask', type=lambda x: int(x,16), default='FF', help='mask to control stages in the profile command')
  ap.add_argument('-N', '--no-multiplex', action='store_const', const=False, default=True,
    help='skip no-multiplexing reruns')
  ap.add_argument('-v', '--verbose', type=int, default=0, help='verbose level; 0:none, 1:commands, ' \
    '2:+verbose-on-metrics, 3:+event-groups, 4:ALL')
  ap.add_argument('--tune', nargs='+', help=argparse.SUPPRESS) # override global variables with python expression
  x = ap.parse_args()
  return x

def main():
  global args
  args = parse_args()
  if args.verbose > 3: print(args)
  #args sanity checks
  if (args.gen_args or 'build' in args.command) and not args.app_name: C.error('must specify --app-name with any of: --gen-args, build')
  if args.verbose > 2: args.toplev_args += ' -g'
  if args.verbose > 1: args.toplev_args += ' -v'
  if args.app_name: do['run'] = args.app_name
  if args.print_only and args.verbose == 0: args.verbose = 1
  do['nodes'] += ("," + args.metrics)
  do['cmds_file'] = open('.%s.cmd'%uniq_name(), 'w')
  if args.tune:
    for t in args.tune:
      if t.startswith(':'):
        l = t.split(':')
        t = "do['%s']=%s"%(l[1], l[2] if len(l)==3 else ':'.join(l[2:]))
      if args.verbose > 3: print(t)
      exec(t)
  
  for c in args.command:
    if   c == 'forgive-me':   pass
    elif c == 'setup-all':
      tools_install()
      setup_perf()
    elif c == 'setup-perf':   setup_perf()
    elif c == 'find-perf':    exe('sudo find / -name perf -type f -executable')
    elif c == 'tools-update': tools_update()
    elif c == 'disable-smt':  smt()
    elif c == 'enable-smt':   smt('on')
    elif c == 'disable-atom': atom()
    elif c == 'enable-atom':  atom('online')
    elif c == 'log':          log_setup()
    elif c == 'profile':      profile()
    elif c == 'tar':          do_logs(c)
    elif c == 'clean':        do_logs(c)
    elif c == 'all':
      setup_perf()
      profile(True)
      do_logs('tar')
    elif c == 'build':        build_kernel()
    else:
      C.error("Unknown command: '%s' !"%c)
      return -1
  return 0

if __name__ == "__main__":
  main()
  do['cmds_file'].close()

