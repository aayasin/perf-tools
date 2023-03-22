#!/usr/bin/env python
# Copyright (c) 2020-2023, Intel Corporation
# Author: Ahmad Yasin
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT # ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# Misc utilities for CPU performance profiling on Linux
#
# TODO list:
#   report PEBS-based stats for DSB-miss types (loop-seq, loop-jump_to_mid)
#   move profile code to a seperate module, arg for output dir
#   quiet mode
#   convert verbose to a bitmask
#   support disable nmi_watchdog in CentOS
from __future__ import print_function
__author__ = 'ayasin'
__version__ = 1.96

import argparse, os.path, sys
import common as C, pmu, stats
from datetime import datetime
from math import log10
from platform import python_version

Find_perf = 'sudo find / -name perf -executable -type f'
LDLAT_DEF = '7'
XED_PATH = '/usr/local/bin/xed'
do = {'run':        C.RUN_DEF,
  'asm-dump':       30,
  'batch':          0,
  'calibrate':      0,
  'cmds_file':      None,
  'comm':           None,
  'compiler':       'gcc -O2 -ffast-math', # ~/tools/llvm-6.0.0/bin/clang',
  'container':      0,
  'core':           1,
  'cpuid':          0 if C.any_in(['Red Hat', 'CentOS'], C.file2str('/etc/os-release', 1)) else 1,
  'debug':          0,
  'dmidecode':      0,
  'extra-metrics':  "+Mispredictions,+IpTB,+BpTkBranch,+IpCall,+IpLoad,+ILP,+UopPI",
  'flameg':         0,
  'forgive':        0,
  'gen-kernel':     1,
  'help':           1,
  'imix':           0x1f, # bit 0: hitcounts, 1: imix-no, 2: imix, 3: process-all, 4: non-cold takens
  'loops':          int(pmu.cpu('cpucount') / 2),
  'log_stdio':      1,
  'lbr-branch-stats': 1,
  'lbr-verbose':    0,
  'lbr-indirects':  None,
  'lbr-stats':      '- 0 10 0 ANY_DSB_MISS',
  'lbr-stats-tk':   '- 0 20 1',
  'ldlat':          int(LDLAT_DEF),
  'levels':         2,
  'metrics':        '+Load_Miss_Real_Latency,+L2MPKI,+ILP,+IpTB,+IpMispredict' +
                    (',+Memory_Bound*/3' if pmu.goldencove() else ''), # +UopPI once ICL mux fixed, +ORO with TMA 4.5
  'model':          'MTL',
  'msr':            0,
  'msrs':           pmu.cpu_msrs(),
  'nodes':          "+CoreIPC,+Instructions,+CORE_CLKS,+Time,-CPU_Utilization",
  'numactl':        1,
  'objdump':        'binutils-gdb/binutils/objdump' if os.path.isfile('./binutils-gdb/binutils/objdump') else 'objdump',
  'package-mgr':    C.os_installer(),
  'packages':       ('cpuid', 'dmidecode', 'msr', 'numactl'),
  'perf-filter':    1,
  'perf-lbr':       '-j any,save_type -e %s -c 700001' % pmu.lbr_event(),
  'perf-ldlat':     '-e %s -c 1001' % pmu.ldlat_event(LDLAT_DEF),
  'perf-pebs':      '-b -e %s/event=0xc6,umask=0x1,frontend=0x1,name=FRONTEND_RETIRED.ANY_DSB_MISS/uppp -c 1000003' % pmu.pmu(),
  'perf-pt':        "-e '{intel_pt//u,%su}' -c 700001 -m,64M" % pmu.lbr_event(), # noretcomp
  'perf-record':    '', # '-e BR_INST_RETIRED.NEAR_CALL:pp ',
  'perf-scr':       0,
  'perf-stat':      '', # '--topdown' if pmu.perfmetrics() else '',
  'perf-stat-add':  1, # additional events using general counters
  'perf-stat-def':  'cpu-clock,context-switches,cpu-migrations,page-faults,instructions,cycles,ref-cycles', # ,cycles:G
  'perf-stat-ipc':  'stat -e instructions,cycles',
  'pin':            'taskset 0x4',
  'pmu':            pmu.name(),
  'python':         sys.executable,
  'repeat':         3,
  'reprocess':      2,
  'sample':         2,
  'size':           0,
  'super':          0,
  'tee':            1,
  'tma-fx':         '+IPC,+Instructions,+Time,+SLOTS,+CLKS',
  'tma-bot-fe':     ',+Mispredictions,+Big_Code,+Instruction_Fetch_BW,+Branching_Overhead,+DSB_Misses',
  'tma-bot-rest':   ',+Memory_Bandwidth,+Memory_Latency,+Memory_Data_TLBs,+Core_Bound_Likely',
  'xed':            1 if pmu.cpu('x86') else 0,
}
args = argparse.Namespace()

def exe(x, msg=None, redir_out='2>&1', run=True, log=True, timeit=False, fail=True, background=False, export=None):
  X = x.split()
  if msg and do['batch']: msg += " for '%s'" % args.app
  if redir_out: redir_out=' %s' % redir_out
  if not do['tee']: x = x.split('|')[0]
  x = x.replace('| ./', '| %s/' % C.dirname())
  if x.startswith('./'): x.replace('./', '%s/' % C.dirname(), 1)
  if 'tee >(' in x or export: x = '%s bash -c "%s"' % (export if export else '', x.replace('"', '\\"'))
  x = x.replace('  ', ' ').strip()
  if timeit and not export: x = 'time -f "\\t%%E time-real:%s" %s 2>&1' % ('-'.join(X[:2]), x)
  debug = args.verbose > 0
  if len(vars(args)):
    run = not args.print_only
    if C.any_in(['perf stat', ' record', 'toplev.py'], x):
      if args.mode == 'process':
        x, run, debug = '# ' + x, False, args.verbose > 2
        if not 'perf record ' in x: msg = None
    elif args.mode == 'profile':
        x, run, debug = '# ' + x, False, args.verbose > 2
    elif '--xed' in x and not os.path.isfile(XED_PATH): C.error('!\n'.join(('xed was not installed',
      "required by '%s' in perf-script of '%s'" % (msg, x), 'try: ./do.py setup-all --tune :xed:1 ')))
    if background: x = x + ' &'
    if C.any_in(['perf script', 'toplev.py'], x) and C.any_in(['Unknown', 'generic'], do['pmu']):
      C.warn('CPU model is unrecognized; consider Linux kernel update (https://intelpedia.intel.com/IntelNext#Intel_Next_OS)', suppress_after=1)
    if not 'loop_stats' in x or args.verbose > 0:
      do['cmds_file'].write(x + '\n')
      do['cmds_file'].flush()
  return C.exe_cmd(x, msg, redir_out, debug, run, log, fail, background)
def exe1(x, m=None, log=True):
  if args.stdout and '| tee' in x: x, log = x.split('| tee')[0], False
  return exe(x, m, redir_out=None, log=log)
def exe_to_null(x): return exe1(x + ' > /dev/null')
def exe_v0(x='true', msg=None): return C.exe_cmd(x, msg) # don't append to cmds_file
def prn_line(f): exe_v0('echo >> %s' % f)

def print_cmd(x, show=not do['batch']):
  if show: C.printc(x)
  if len(vars(args))>0: do['cmds_file'].write('# ' + x + '\n')

def exe_1line(x, f=None, heavy=True):
  return "-1" if args.mode == 'profile' and heavy or args.print_only else C.exe_one_line(x, f, args.verbose > 1)
def exe2list(x, f=None): return ['-1'] if args.mode == 'profile' or args.print_only else C.exe2list(x, args.verbose > 1)

def warn_file(x):
  if not args.mode == 'profile' and not args.print_only and not os.path.isfile(x): C.warn('file does not exist: %s' % x)

def isfile(f): return f and os.path.isfile(f)
def rp(x): return os.path.join(C.dirname(), x)
def version(): return str(round(__version__, 3 if args.tune else 2))
def lbr_version():
  import lbr
  return str(round(lbr.__version__, 2))
def app_name(): return args.app != C.RUN_DEF
def toplev_describe(m, msg=None, mod='^'):
  if not do['help']: return
  exe('%s --describe %s%s' % (get_perf_toplev()[1], m, mod), msg, redir_out=None)

def uniq_name():
  return C.command_basename(args.app, iterations=(args.app_iterations if args.gen_args else None))[:200]

def tools_install(installer='sudo %s -y install ' % do['package-mgr'], packages=[]):
  pkg_name = {'msr': 'msr-tools'}
  if args.install_perf:
    if args.install_perf == 'install':
      if do['package-mgr'] == 'dnf': exe('sudo yum install perf', 'installing perf')
      else: packages += ['linux-tools-generic && ' + Find_perf]
    elif args.install_perf == 'build':
      b='./build-perf.sh'
      if 'apt-get' in C.file2str(b): exe('sed -i s/apt\-get/%s/ %s'%(do['package-mgr'],b))
      exe('%s | tee %s.log'%(b, b.replace('.sh','')), 'building perf anew')
    elif args.install_perf == 'patch':
      exe_v0(msg='setting default perf')
      a_perf = C.exe_output(Find_perf + ' | grep -v /usr/bin/perf | head -1', '')
      exe('ln -f -s %s /usr/bin/perf'%a_perf)
    else: C.error('Unsupported --perf-install option: '+args.install_perf)
  for x in do['packages']:
    if do[x]: packages += [pkg_name[x] if x in pkg_name else x]
  #if len(packages) and not do['package-mgr'].startswith('apt'): exe(installer.replace('install', 'makecache --refresh'), 'updating %s DB' % do['package-mgr'])
  for x in packages:
    exe(installer + x, 'installing ' + x.split(' ')[0])
  if do['xed']:
    if do['xed'] < 2 and os.path.isfile(XED_PATH): exe_v0(msg='xed is already installed')
    else: exe('./build-xed.sh', 'installing xed')
    pip = 'pip3' if python_version().startswith('3') else 'pip'
    for x in ('numpy', 'xlsxwriter'): exe('%s install %s' % (pip, x), '@installing %s' % x)
    if 'Red Hat' in C.file2str('/etc/os-release', 1): exe('sudo yum install python3-xlsxwriter.noarch', '@patching xlsx')
  if do['msr']: exe('sudo modprobe msr', 'enabling MSRs')
  if do['flameg']: exe('git clone https://github.com/brendangregg/FlameGraph', 'cloning FlameGraph')

def tools_update(kernels=[], level=3):
  ks = [''] + C.exe2list("git status | grep 'modified.*kernels' | cut -d/ -f2") + kernels
  exe('git checkout HEAD run.sh' + ' kernels/'.join(ks))
  if level > 0: exe('git pull')
  if level > 1: exe('git submodule update --remote')
  if level > 2:
    exe(args.pmu_tools + "/event_download.py ")
    if do['super']:
      if level > 3: exe('mv ~/.cache/pmu-events /tmp')
      exe(args.pmu_tools + "/event_download.py -a") # requires sudo; download all CPUs

def set_sysfile(p, v): exe_to_null('echo %s | sudo tee %s'%(v, p))
def prn_sysfile(p, out=None): exe_v0('printf "%s : %s \n" %s' %
  (p, C.file2str(p), (' >> '+out if out else '')))
def setup_perf(actions=('set', 'log'), out=None):
  def set_it(p, v): set_sysfile(p, str(v))
  TIME_MAX = '/proc/sys/kernel/perf_cpu_time_max_percent'
  perf_params = [
    ('/proc/sys/kernel/perf_event_paranoid', -1, ),
    ('/proc/sys/kernel/perf_event_mlock_kb', 60000, ),
    ('/proc/sys/kernel/perf_event_max_sample_rate', int(1e9), 'root'),
    ('/sys/devices/%s/perf_event_mux_interval_ms' % pmu.pmu(), 100, ),
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
  perf_params += [(TIME_MAX, 0, 'root')] # has to be last
  for x in perf_params: 
    if (len(x) == 2) or superv:
      param, value = x[0], x[1]
      if 'set' in actions: set_it(param, value)
      if 'log' in actions: prn_sysfile(param, out)

def smt(x='off'):
  set_sysfile('/sys/devices/system/cpu/smt/control', x)
  if do['super']: exe(args.pmu_tools + '/cputop "thread == 1" %sline | sudo sh'%x)
def atom(x='offline'):
  exe(args.pmu_tools + "/cputop 'type == \"atom\"' %s"%x)
  exe("for x in {16..23}; do echo %d | sudo tee /sys/devices/system/cpu/cpu$x/online; done" %
    (0 if x == 'offline' else 1))
def fix_frequency(x='on', base_freq=C.file2str('/sys/devices/system/cpu/cpu0/cpufreq/base_frequency')):
  if x == 'on':
    for f in C.glob('/sys/devices/system/cpu/cpu*/cpufreq/scaling_m*_freq'):
      set_sysfile(f, base_freq)
  else:
    for m in ('max', 'min'):
      freq=C.file2str('/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_%s_freq'%m)
      for f in C.glob('/sys/devices/system/cpu/cpu*/cpufreq/scaling_%s_freq'%m):
        set_sysfile(f, freq)

def log_setup(out='setup-system.log', c='setup-cpuid.log', d='setup-dmesg.log'):
  def new_line(): return prn_line(out)
  def read_msr(m): return C.exe_one_line('sudo %s/msr.py %s' % (args.pmu_tools, m))
  C.printc(do['pmu']) #OS
  if args.mode == 'process': return
  exe('uname -a > ' + out, 'logging setup')
  exe("cat /etc/os-release | egrep -v 'URL|ID_LIKE|CODENAME' >> " + out)
  for f in ('/sys/kernel/mm/transparent_hugepage/enabled', ):
    prn_sysfile(f, out)
  exe("sudo sysctl -a | tee setup-sysctl.log | egrep 'randomize_va_space|hugepages =' >> %s" % out)
  exe("env > setup-env.log")
  new_line()          #CPU
  exe("lscpu | tee setup-lscpu.log | egrep 'family|Model|Step|(Socket|Core|Thread)\(' >> " + out)
  if do['msr']:
    for m in do['msrs']:
      v = read_msr(m)
      exe('echo "MSR %s: %s" >> %s' % (m, ('0'*(16 - len(v)) if C.is_num(v, 16) else '\t\t') + v, out))
  if do['cpuid']: exe("cpuid -1 > %s && cpuid -1r | tee -a %s | grep ' 0x00000001' >> %s"%(c, c, out))
  exe("dmesg -T | tee %s | %s >> %s && %s | tail -1 >> %s" % (d, C.grep('Performance E|micro'), out, C.grep('BIOS ', d), out))
  exe("perf record true 2> /dev/null && perf report -I --header-only > setup-cpu-toplogy.log".replace('perf', get_perf_toplev()[0]))
  new_line()          #PMU
  exe('echo "PMU: %s" >> %s'%(do['pmu'], out))
  exe('%s --version >> ' % args.perf + out)
  setup_perf('log', out)
  new_line()          #Tools
  exe('echo "python version: %s" >> %s' % (python_version(), out))
  for x in (do['compiler'], 'as'): exe('%s --version | head -1 >> ' % x + out)
  exe1('ldd --version | head -1 >> %s' % out, log=False)
  new_line()          #Memory
  if do['numactl']: exe('numactl -H >> ' + out)
  new_line()          #Devices, etc
  exe("lsmod | tee setup-lsmod.log | egrep 'Module|kvm' >> " + out)
  exe("ulimit -a > setup-ulimit.log")
  if do['dmidecode']: exe('sudo dmidecode > setup-memory.log')

def get_perf_toplev():
  perf, env, ptools = args.perf, '', {}
  if perf != 'perf':
    C.check_executable(perf)
    env = 'PERF=%s ' % perf
  for x in ('toplev.py', 'ocperf'):
    C.check_executable('/'.join((args.pmu_tools.split()[-1], x)))
    ptools[x] = env + args.pmu_tools + '/' + x
  if args.verbose > 5: ptools['toplev.py'] = 'OCVERBOSE=1 %s' % ptools['toplev.py']
  if do['core']:
    ##if pmu.perfmetrics(): toplev += ' --pinned'
    if pmu.meteorlake(): ptools['toplev.py'] += ' --force-cpu=adl'
    if pmu.hybrid(): ptools['toplev.py'] += ' --cputype=core'
  return (perf, ptools['toplev.py'], ptools['ocperf'])

def profile(mask, toplev_args=['mvl6', None]):
  out = uniq_name()
  perf, toplev, ocperf = get_perf_toplev()
  perf_report = ' '.join((perf, 'report', '--objdump %s' % do['objdump'] if do['objdump'] != 'objdump' else ''))
  perf_report_mods = perf_report + ' --stdio -F sample,overhead,comm,dso'
  perf_report_syms = perf_report_mods + ',sym'
  sort2u = 'sort | uniq -c | sort -n'
  sort2up = sort2u + ' | ./ptage'
  def en(n): return mask & 2**n
  def a_events():
    def power(rapl=['pkg', 'cores', 'ram'], px='/,power/energy-'): return px[(px.find(',')+1):] + px.join(rapl) + ('/' if '/' in px else '')
    return power() if args.power and not pmu.v5p() else ''
  def perf_ic(data, comm): return ' '.join(['-i', data, '-c %s' % comm if comm else ''])
  def perf_stat(flags, msg, events='', perfmetrics=do['core'],
                grep = "| egrep 'seconds [st]|CPUs|GHz|insn|topdown|Work|System|all branches' | uniq"):
    def append(x, y): return x if y == '' else ',' + x
    evts, perf_args = events, [flags, '--log-fd=1', do['perf-stat'] ]
    if args.metrics: perf_args += ['--metric-no-group', '-M', args.metrics] # 1st is workaround bug 4804e0111662 in perf-stat -r2 -M
    perf_args = ' '.join(perf_args)
    if perfmetrics and pmu.perfmetrics():
      prefix = ',topdown-'
      evts += prefix.join([append('{slots', evts), 'retiring', 'bad-spec', 'fe-bound', 'be-bound'])
      if pmu.goldencove():
        evts += prefix.join(['', 'heavy-ops', 'br-mispredict', 'fetch-lat', 'mem-bound}'])
        perf_args += ' --td-level=2'
      else: evts += '}'
      if pmu.hybrid(): evts = evts.replace(prefix, '/,cpu_core/topdown-').replace('}', '/}').replace('{slots/', '{slots')
      if do['perf-stat-add']: evts += append(pmu.basic_events(), evts)
    if args.events: evts += append(pmu.perf_format(args.events), evts)
    if args.events or args.metrics: grep = '' #keep output unfiltered with user-defined events
    if evts != '': perf_args += ' -e "%s,%s"' % (do['perf-stat-def'], evts)
    log = '%s.perf_stat%s.log' % (out, flags.strip())
    stat = ' stat %s -- %s | tee %s %s' % (perf_args, r, log, grep)
    exe1(perf + stat, msg)
    if args.stdout or do['tee']==0: return None
    if args.mode == 'process': return log
    if isfile(log) and os.path.getsize(log) == 0: exe1(ocperf + stat, msg + '@; retry w/ ocperf')
    if int(exe_1line('wc -l ' + log, 0, False)) < 5:
      if perfmetrics: return perf_stat(flags, msg + '@; no PM', events=events, perfmetrics=0, grep=grep)
      else: C.error('perf-stat failed for %s (despite multiple attempts)' % log)
    return log

  def get_comm(data):
    if not do['perf-filter']: return None
    if do['comm']: return do['comm']
    # might be doable to optimize out this 'perf script' with 'perf buildid-list' e.g.
    comm = exe_1line(perf + " script -i %s -F comm | %s | tail -1" % (data, sort2u), 1)
    if comm == 'perf' or comm.startswith('perf-'):
      # e.g. a perf tool overhead bug in Intel event names handling
      exe(' '.join([perf_report_syms, '-i', perf_data, '| grep -A11 Samples']))
      C.error("Most samples in 'perf' tool. Try run longer")
    return comm
  def perf_script(x, msg, data, export='', fail=True):
    if do['perf-scr']:
      samples = 1e4 * do['perf-scr']
      if perf_script.first: C.info('processing first %d samples only' % samples)
      export += ' LBR_STOP=%d' % samples
      x = x.replace('GREP_INST', 'head -%d | GREP_INST' % (300*samples))
    if do['perf-filter'] and not perf_script.comm:
      perf_script.comm = get_comm(data)
      if perf_script.first: C.info("filtering on command '%s' in next post-processing" % perf_script.comm)
    instline = '^\s+[0-9a-f]+\s'
    if 'taken branches' in msg: instline += '.*#'
    x = x.replace('GREP_INST', "grep -E '%s'" % instline)
    if perf_script.first and not en(8): C.warn('LBR profile-step is disabled')
    perf_script.first = False
    return exe(' '.join((perf, 'script', perf_ic(data, perf_script.comm), x)), msg, redir_out=None,
               timeit=(args.verbose > 2), export=export, fail=fail)
  perf_script.first = True
  perf_script.comm = do['comm']
  perf_stat_log = None
  def record_name(flags): return '%s%s' % (out, C.chop(flags, (' :/,={}\'', 'cpu_core', 'cpu')))
  def get_stat(s, default): return stats.get_stat_log(s, perf_stat_log) if isfile(perf_stat_log) else default
  def record_calibrate(x):
    factor = do['calibrate']
    if not (factor or args.sys_wide): factor = int(log10(get_stat('CPUs-utilized', 1)))
    if factor:
      do[x] = do[x].replace('0000', '0' * (4 + factor))
      C.info('\tcalibrated: %s' % do[x])
    return record_name(do[x])
  r = do['run'] if args.gen_args or args.sys_wide else args.app
  if en(0): log_setup()
  if args.profile_mask & ~0x1: C.info('App: ' + r)
  if en(1): perf_stat_log = perf_stat('-r%d' % do['repeat'], 'per-app counting %d runs' % do['repeat'])
  if en(2): perf_stat('-a', 'system-wide counting', a_events(), grep='| egrep "seconds|insn|topdown|pkg"')
  
  if en(3) and do['sample']:
    base = out+'.perf'
    if do['perf-record'] and len(do['perf-record']):
      do['perf-record'] += ' '
      base += C.chop(do['perf-record'], ' :/,=')
    data = '%s.perf.data'%record_name(do['perf-record'])
    exe(perf + ' record -c %d -g -o %s ' % (pmu.period(), data)+do['perf-record']+r, 'sampling %sw/ stacks'%do['perf-record'])
    if do['log_stdio'] and args.mode != 'process' and not do['forgive']:
      record_out = C.file2lines(C.log_stdio)
      for l in reversed(record_out):
        if 'sampling ' in l: break
        if 'WARNING: Kernel address maps' in l: C.error("perf tool is missing permissions. Try './do.py setup-perf'")
    exe(perf_report + " --header-only -i %s | grep duration" % data)
    print_cmd("Try '%s -i %s' to browse time-consuming sources" % (perf_report, data))
    #TODO:speed: parallelize next 3 exe() invocations & resume once all are done
    exe(perf_report_syms + " -n --no-call-graph -i %s | tee %s-funcs.log | grep -A7 Overhead "
      "| egrep -v '^# \.|^\s+$|^$' | head | sed 's/[ \\t]*$//'" % (data, base), '@report functions')
    exe(perf_report + " --stdio --hierarchy --header -i %s | grep -v ' 0\.0.%%' | tee "%data+
      base+"-modules.log | grep -A22 Overhead", '@report modules')
    exe(perf + " annotate --stdio -n -l -i %s | c++filt | tee %s-code.log " \
      "| egrep -v -E '^(\-|\s+([A-Za-z:]|[0-9] :))' > %s-code_nz.log" %
      (data, base, base), '@annotate code', redir_out='2>/dev/null')
    exe("grep -w -5 '%s :' %s-code.log" % (exe_1line("egrep '\s+[0-9]+ :' %s-code.log | sort -n | tail -1" %
                                                      base, 0), base), '@hottest block(s), all commands')
    if do['xed']: perf_script("-F insn --xed | %s | tee %s-hot-insts.log | tail" % (sort2up, base),
                              '@time-consuming instructions', data)
  
  toplev += ' --no-desc'
  grep_bk= "egrep '<==|MUX|Info.Bott' | sort"
  grep_NZ= "egrep -iv '^(all|)((FE|BE|BAD|RET).*[ \-][10]\.. |Info.* 0\.0[01]? |RUN|Add|warning:)|not (found|referenced|supported)|##placeholder##' "
  grep_nz= grep_NZ
  if args.verbose < 2: grep_nz = grep_nz.replace('##placeholder##', ' < [\[\+]|<$')
  def toplev_V(v, tag='', nodes=do['nodes'],
               tlargs = toplev_args[1] if toplev_args[1] else args.toplev_args):
    o = '%s.toplev%s.log'%(out, v.split()[0]+tag)
    c = "%s %s --nodes '%s' -V %s %s -- %s" % (toplev, v, nodes, o.replace('.log', '-perf.csv'), tlargs, r)
    if ' --global' in c: C.warn('Global counting is subject to system noise (cpucount=%d)' % pmu.cpu('cpucount'))
    return c, o
  def topdown_describe(log):
    path = stats.read_toplev(log, 'Critical-Node')
    if path:
      path = path.split('.')
      toplev_describe(path[0], '@description of nodes in TMA tree path to critical node')
      for n in path[1:]: toplev_describe(n)

  # +Info metrics that would not use more counters
  if en(4):
    cmd, log = toplev_V('-vl6', nodes=do['tma-fx'] + (do['tma-bot-fe'] + do['tma-bot-rest']))
    exe(cmd + ' | tee %s | %s' % (log, grep_bk), 'topdown full tree + All Bottlenecks')
    topdown_describe(log)

  if en(5):
    cmd, log = toplev_V('-vl%d' % do['levels'], tlargs='%s -r%d' % (args.toplev_args, do['repeat']))
    exe(cmd + ' | tee %s | %s' % (log, grep_nz), 'topdown primary, %d-levels %d runs' % (do['levels'], do['repeat']))
  
  if en(6):
    cmd, log = toplev_V('--drilldown --show-sample -l1', nodes='+IPC,+Heavy_Operations,+Time',
      tlargs='' if args.toplev_args == C.TOPLEV_DEF else args.toplev_args)
    exe(cmd + ' | tee %s | egrep -v "^(Run toplev|Add|Using|Sampling)|perf.* record" ' % log, 'topdown auto-drilldown')
    topdown_describe(log)
    if do['sample'] > 3:
      cmd = C.exe_output("grep 'perf record' %s | tail -1"%log)
      exe(cmd, '@sampling on bottleneck')
      perf_data = cmd.split('-o ')[1].split(' ')[0]
      print_cmd("Try '%s -i %s' to browse sources for critical bottlenecks"%(perf_report, perf_data))
      for c in ('report', 'annotate'):
        exe("%s %s --stdio -i %s > %s "%(perf, c, perf_data, log.replace('toplev--drilldown', 'locate-'+c)), '@'+c)

  if en(12):
    cmd, log = toplev_V('-mvl2', nodes=do['tma-fx'] + (do['tma-bot-fe'] + do['tma-bot-rest']).replace('+', '-'))
    exe(cmd + ' | sort | tee %s | %s' % (log, grep_nz), 'Info metrics')

  if en(13):
    cmd, log = toplev_V('-vvl2', nodes=do['tma-fx'] + do['tma-bot-fe'] + ',+Fetch_Latency*/3,+Branch_Resteers*/4,+IpTB,+CoreIPC')
    exe(cmd + ' | tee %s | %s' % (log, grep_nz), 'topdown 2 levels + FE Bottlenecks')
    print_cmd("cat %s | %s"%(log, grep_NZ), False)

  if en(14) and pmu.meteorlake():
    flags, events = '-W -c 20011', pmu.get_events(do['model'])
    data = '%s-tpebs-perf.data' % record_name('-%s%d' % (do['model'], events.count(':p')))
    cmd = "%s record %s -e %s -o %s -- %s" % (perf if 'raw' in do['model'] else ocperf, flags, events, data, r)
    exe(cmd.replace('20011', '3001') if 'raw' in do['model'] else cmd, "TMA sampling (%s)" % do['model'])
    exe("%s script -i %s -F event,retire_lat > %s.retire_lat.txt" % (perf, data, data))
    exe("sort %s.retire_lat.txt | uniq -c | sort -n | ./ptage | tail" % (data, ))

  def perf_record(tag, msg=None, record='record', track_ipc=do['perf-stat-ipc']):
    perf_data = '%s.perf.data' % record_calibrate('perf-%s' % tag)
    flags = do['perf-%s' % tag]
    assert C.any_in(('-b', '-j any', 'ldlat', 'intel_pt'), flags) or do['forgive'], 'No unfiltered LBRs! for %s: %s' % (tag, flags)
    cmd = 'bash -c "%s %s %s"' % (perf, track_ipc, r) if len(track_ipc) else '-- %s' % r
    exe(perf + ' %s %s -o %s %s' % (record, flags, perf_data, cmd), 'sampling-%s%s' % (tag.upper(), ' ' + msg if msg else ''))
    warn_file(perf_data)
    if not tag in ('ldlat', 'pt'): print_cmd("Try '%s -i %s --branch-history --samples 9' to browse streams" % (perf_report, perf_data))
    if tag == 'lbr' and int(exe_1line('%s script -i %s -D | grep -F RECORD_SAMPLE 2>/dev/null | head | wc -l' % (perf, perf_data))) == 0:
      C.error("No samples collected in %s ; Check if perf is in use e.g. '\ps -ef | grep perf'" % perf_data)
    return perf_data
  
  if en(8) and do['sample'] > 1:
    assert pmu.lbr_event()[:-1] in do['perf-lbr'] or do['forgive'], 'Incorrect event for LBR in: ' + do['perf-lbr']
    data = perf_record('lbr')
    info, comm = '%s.info.log' % data, get_comm(data)
    clean = "sed 's/#.*//;s/^\s*//;s/\s*$//;s/\\t\\t*/\\t/g'"
    def static_stats():
      bins = exe2list(perf + " script -i %s | cut -d\( -f2 | cut -d\) -f1 | egrep -v '^\[|anonymous' | %s | tail -5" %
                        (data, sort2u))[1:][::2]
      if args.mode == 'profile': return
      assert len(bins)
      exe_v0('printf "# %s:\n#\n" > %s' % ('Static Statistics', info))
      exe('size %s >> %s' % (' '.join(bins), info), "@stats")
      exe_v0('echo >> %s' % info)
    def log_count(x, l): return "printf 'Count of unique %s%s: ' >> %s && wc -l < %s >> %s" % (
      'non-cold ' if do['imix'] & 0x10 else '', x, info, l, info)
    def log_br_count(x, s): return log_count("%s branches" % x, "%s.%s.log" % (data, s))
    def tail(f=''): return "tail %s | grep -v total" % f
    if not os.path.isfile(info) or do['reprocess'] > 1:
      if do['size']: static_stats()
      exe_v0('printf "# processing %s%s\n"%s %s' % (data, " filtered on '%s'" % comm if comm else '', '>>' if do['size'] else '>', info))
      if do['lbr-branch-stats']: exe(perf + " report %s | grep -A13 'Branch Statistics:' | tee -a %s | egrep -v ':\s+0\.0%%|CROSS'" %
          (perf_ic(data, comm), info), None if do['size'] else "@stats")
      if isfile(perf_stat_log):
        exe("egrep '  branches| cycles|instructions|BR_INST_RETIRED' %s >> %s" % (perf_stat_log, info))
      sort2uf = "%s |%s ./ptage" % (sort2u, " egrep -v '\s+[1-9]\s+' |" if do['imix'] & 0x10 else '')
      perf_script("-F ip | %s > %s.samples.log && %s" % (sort2uf, data,
        log_br_count('sampled taken', 'samples').replace('Count', '\\nCount')), '@processing samples', data, fail=0)
      if do['xed']:
        if (do['imix'] & 0x8) == 0:
          perf_script("-F +brstackinsn --xed | GREP_INST| grep MISPRED | %s | %s > %s.mispreds.log" %
                      (clean, sort2uf, data), '@processing mispredicts', data)
        else:
          perf_script("-F +brstackinsn --xed | GREP_INST"
            "| tee >(grep MISPRED | %s | tee >(egrep -v 'call|jmp|ret' | %s > %s.misp_tk_conds.log) | %s > %s.mispreds.log)"
            "| %s | tee >(%s > %s.takens.log) | tee >(grep '%%' | %s > %s.indirects.log) | grep call | %s > %s.calls.log" %
            (clean, sort2uf, data, sort2uf, data, clean, sort2uf, data, sort2uf, data, sort2uf, data),
            '@processing taken branches', data)
          for x in ('taken', 'call', 'indirect'): exe(log_br_count(x, "%ss" % x))
          exe(log_br_count('mispredicted conditional taken', 'misp_tk_conds'))
        exe(log_br_count('mispredicted taken', 'mispreds'))
    if do['xed']:
      ips = '%s.ips.log'%data
      hits = '%s.hitcounts.log'%data
      loops = '%s.loops.log' % data
      lbr_hdr = '# LBR-based Statistics:'
      exe_v0('printf "\n%s\n#\n">> %s' % (lbr_hdr, info))
      if not os.path.isfile(hits) or do['reprocess']:
        lbr_env = "LBR_LOOPS_LOG=%s" % loops
        cycles = get_stat(pmu.event('cycles'), 0)
        if cycles: lbr_env += ' PTOOLS_CYCLES=%d' % cycles
        if do['lbr-verbose']: lbr_env += " LBR_VERBOSE=%d" % do['lbr-verbose']
        if do['lbr-indirects']: lbr_env += " LBR_INDIRECTS=%s" % do['lbr-indirects']
        misp, cmd, msg = '', "-F +brstackinsn --xed", '@info'
        if do['imix']:
          print_cmd(' '.join(('4debug', perf, 'script', cmd, '| less')), False)
          cmd += " | tee >(%s %s %s >> %s) %s | GREP_INST | %s " % (
            lbr_env, rp('lbr_stats'), do['lbr-stats-tk'], info, misp, clean)
          if do['imix'] & 0x1:
            cmd += "| tee >(sort|uniq -c|sort -k2 | tee %s | cut -f-2 | sort -nu | ./ptage > %s) " % (hits, ips)
            msg += ', hitcounts'
          if do['imix'] & 0x2:
            cmd += "| cut -f2- | tee >(cut -d' ' -f1 | %s > %s.perf-imix-no.log) " % (sort2up, out)
            msg += ' & i-mix'
          if do['imix'] & 0x4:
            cmd += '| %s | tee %s.perf-imix.log | %s' % (sort2up, out, tail())
            msg += 'es'
        if (do['imix'] & 0x4) == 0:
          cmd += ' > /dev/null'
        perf_script(cmd, msg, data)
        if do['imix'] & 0x4: exe("%s && %s" % (tail('%s.perf-imix-no.log' % out), log_count('instructions', hits)),
            "@instruction-mix no operands")
        if args.verbose > 0: exe("tail -4 " + ips, "@top-3 hitcounts of basic-blocks to examine in " + hits)
        exe("%s && tail %s | grep -v unique" % (C.grep('code footprint', info), info), "@top loops & more stats in " + info)
      else: exe("sed -n '/%s/q;p' %s > .1.log && mv .1.log %s" % (lbr_hdr, info, info), '@reuse of %s , loops and i-mix log files' % hits)
      if do['loops'] and os.path.isfile(loops):
        prn_line(info)
        cmd, top = '', min(do['loops'], int(exe_1line('wc -l %s' % loops, 0)))
        do['loops'] = top
        while top > 1:
          cmd += ' | tee >(%s %s >> %s) ' % (rp('loop_stats'), exe_1line('tail -%d %s | head -1' % (top, loops), 2)[:-1], info)
          top -= 1
        cmd += ' | ./loop_stats %s >> %s && echo' % (exe_1line('tail -1 %s' % loops, 2)[:-1], info)
        print_cmd(perf + " script -i %s -F +brstackinsn --xed -c %s | %s %s >> %s" % (data, comm, rp('loop_stats'),
          exe_1line('tail -1 %s' % loops, 2)[:-1], info))
        perf_script("-F +brstackinsn --xed %s && %s" % (cmd, C.grep('FL-cycles...[1-9][0-9]?', info, color=1)),
          "@detailed stats for hot loops", data, export='PTOOLS_HITS=%s' % (hits,))
      else: warn_file(loops)
  
  if en(9) and do['sample'] > 2:
    data = perf_record('pebs', C.flag_value(do['perf-pebs'], '-e'))
    exe(perf_report_mods + " %s | tee %s.modules.log | grep -A12 Overhead" % (perf_ic(data, get_comm(data)), data), "@ top-10 modules")
    if do['xed']: perf_script("--xed -F ip,insn | %s | tee %s.ips.log | tail -11" % (sort2up, data), "@ top-10 IPs, Insts", data)
    else: perf_script("-F ip | %s | tee %s.ips.log | tail -11" % (sort2up, data), "@ top-10 IPs", data)
    is_dsb = 0
    if pmu.dsb_msb() and 'DSB_MISS' in do['perf-pebs']:
      if pmu.cpu('smt-on') and do['forgive'] < 2: C.warn('Disable SMT for DSB robust analysis')
      else:
        is_dsb = 1
        perf_script("-F ip | ./addrbits %d 6 | %s | tee %s.dsb-sets.log | tail -11" %
                    (pmu.dsb_msb(), sort2up, data), "@ DSB-miss sets", data)
    top = 0
    if not is_dsb: pass
    elif top == 1:
      top_ip = exe_1line("tail -2 %s.ips.log | head -1" % data, 2)
      # asserts in skip_sample() only if piped!!
      perf_script("-F +brstackinsn --xed | tee >(%s %s | tee -a %s.ips.log) | ./lbr_stats %s | tee -a %s.ips.log" % (
        rp('lbr_stats'), top_ip, data, do['lbr-stats'], data), "@ stats on PEBS event", data)
    else:
      perf_script("-F +brstackinsn --xed | ./lbr_stats %s | tee -a %s.ips.log" % (do['lbr-stats'], data),
                  "@ stats on PEBS event", data)
    if top > 1:
      while top > 0:
        top_ip = exe_1line("egrep '^[0-9]' %s.ips.log | tail -%d | head -1" % (data, top+1), 2)
        perf_script("-F +brstackinsn --xed | ./lbr_stats %s | tee -a %s.ips.log" % (top_ip, data),
                    "@ stats on PEBS ip=%s" % top_ip, data)
        top -= 1
  
  if en(10):
    data = perf_record('ldlat', record='record' if pmu.ldlat_aux() else 'mem record')
    exe("%s mem report --stdio -i %s -F+symbol_iaddr -v " # workaround: missing -F+ip in perf-mem-report
        "-w 5,5,44,5,13,44,18,43,8,5,12,4,7 2>/dev/null | sed 's/RAM or RAM/RAM/;s/LFB or LFB/LFB or FB/' "
        "| tee %s.ldlat.log | grep -A12 -B4 Overhead | tail -17" % (perf, data, data), "@ top-10 samples", redir_out=None)
    def perf_script_ldlat(fields, tag): return perf_script("-F %s | grep -v mem-loads-aux | %s "
      "| tee %s.%s.log | tail -11" % (fields, sort2up, data, tag.lower()), "@ top-10 %s" % tag, data)
    perf_script_ldlat('event,ip,insn --xed', 'IPs')
    perf_script_ldlat('ip,addr', 'IPs-DLAs')

  if en(7):
    cmd, log = toplev_V('-%s --no-multiplex' % toplev_args[0], '-nomux', ','.join((do['nodes'], do['extra-metrics'])))
    exe(cmd + " | tee %s | %s" % (log, grep_nz), 'topdown-%s no multiplexing' % toplev_args[0])
  
  if en(16):
    data = perf_record('pt')
    tag, info = 'pt', '%s.info.log' % data
    exe(perf + " script --no-itrace -F event,comm -i %s | %s | tee %s.modules.log | ./ptage | tail" % (data, sort2u, data))
    perf_script("--itrace=Le -F +brstackinsn --xed | tee >(egrep 'ppp|#' > %s.pt-takens.log) | %s %s > %s" %
      (data, rp('lbr_stats'), do['lbr-stats-tk'], info), "@pt info", data)

  if en(18):
    assert do['msr']
    perf_data = '%s.perf.data' % record_name('-e msr')
    exe('sudo %s record -e msr:* -o %s -- %s' % (perf, perf_data, r), 'tracing MSRs')
    x = '-i %s | cut -d: -f3-4 | cut -d, -f1 | sort | uniq -c' % perf_data
    exe(' '.join(('sudo', perf, 'script', x)), msg=None, redir_out=None)

  if en(17) and do['flameg']:
    flags = '-ag -F 49' # -c %d' % pmu.period()
    perf_data = '%s.perf.data' % record_name(flags)
    exe('%s record %s -o %s -- %s' % (perf, flags, perf_data, r), 'FlameGraph')
    x = '-i %s %s > %s.svg ' % (perf_data,
      ' | ./FlameGraph/'.join(['', 'stackcollapse-perf.pl', 'flamegraph.pl']), perf_data)
    exe(' '.join((perf, 'script', x)), msg=None, redir_out=None, timeit=(args.verbose > 1))
    print('firefox %s.svg &' % perf_data)


def do_logs(cmd, ext=[], tag=''):
  log_files = ['', 'csv', 'log', 'txt', 'stat', 'xlsx', 'svg'] + ext
  if cmd == 'tar' and len(tag): res = '-'.join((tag, 'results.tar.gz'))
  s = (uniq_name() if app_name() else '') + '*'
  if cmd == 'tar': exe('tar -czvf %s run.sh '%res + (' %s.'%s).join(log_files) + ' .%s.cmd'%s)
  if cmd == 'clean': exe('rm -rf ' + ' *.'.join(log_files + ['pyc']) + ' *perf.data* __pycache__ results.tar.gz ')

def build_kernel(dir='./kernels/'):
  def fixup(x): return x.replace('./', dir)
  app = args.app
  if do['gen-kernel']:
    exe(fixup('%s ./gen-kernel.py %s > ./%s.c'%(do['python'], args.gen_args, app)), 'building kernel: ' + app, redir_out=None)
    if args.verbose > 1: exe(fixup('grep instructions ./%s.c'%app))
  exe(fixup('%s -g -o ./%s ./%s.c'%(do['compiler'], app, app)), None if do['gen-kernel'] else 'compiling')
  do['run'] = fixup('%s ./%s %d' % (do['pin'], app, int(float(args.app_iterations))))
  args.toplev_args += ' --single-thread'
  if args.verbose > 2: exe(fixup("%s -dw ./%s | grep -A%d pause | egrep '[ 0-9a-f]+:'" % (do['objdump'], app, do['asm-dump'])), '@kernel ASM')

def parse_args():
  modes = ('profile', 'process', 'both') # keep 'both', the default, last on this list
  ap = C.argument_parser(usg='do.py command [command ..] [options]',
    defs={'perf': 'perf', 'pmu-tools': '%s %s/pmu-tools' % (do['python'], C.dirname()),
          'toplev-args': C.TOPLEV_DEF, 'nodes': do['metrics']})
  ap.add_argument('command', nargs='+', help='setup-perf log profile tar, all (for these 4) '
                  '\nsupported options: ' + C.commands_list())
  ap.add_argument('--mode', nargs='?', choices=modes, default=modes[-1], help='analysis mode options: profile-only, (post)process-only or both')
  ap.add_argument('--install-perf', nargs='?', default=None, const='install', help='perf tool installation options: [install]|patch|build')
  ap.add_argument('--print-only', action='store_const', const=True, default=False, help='print the commands without running them')
  ap.add_argument('--stdout', action='store_const', const=True, default=False, help='keep profiling unfiltered results in stdout')
  ap.add_argument('--power', action='store_const', const=True, default=False, help='collect power metrics/events as well')
  ap.add_argument('-s', '--sys-wide', type=int, default=0, help='profile system-wide for x seconds. disabled by default')
  ap.add_argument('-g', '--gen-args', help='args to gen-kernel.py')
  ap.add_argument('-ki', '--app-iterations', default='1e9', help='num-iterations of kernel')
  x = ap.parse_args()
  return x

def main():
  global args
  args = parse_args()
  #args sanity checks
  if (args.gen_args or 'build' in args.command) and not app_name():
    C.error('must specify --app-name with any of: --gen-args, build')
  assert args.sys_wide >= 0, 'negative duration provided!'
  if args.verbose > 4: args.toplev_args += ' -g'
  if args.verbose > 2: args.toplev_args += ' --perf'
  if args.print_only and args.verbose == 0: args.verbose = 1
  do['nodes'] += ("," + args.nodes)
  if args.tune:
    for tlists in args.tune:
      for t in tlists:
        if t.startswith(':'):
          l = t.split(':')
          t = "do['%s']=%s"%(l[1], l[2] if len(l)==3 else ':'.join(l[2:]))
        if args.verbose > 3: print(t)
        exec(t)
  if do['debug']: C.dump_stack_on_error = 1
  do['perf-ldlat'] = do['perf-ldlat'].replace(LDLAT_DEF, str(do['ldlat']))
  if do['perf-stat-add']:
    x = ',branches,branch-misses'
    if do['repeat'] > 1: x += ',cycles:k'
    do['perf-stat-def'] += x
  if do['super']:
    do['perf-stat-def'] += ',syscalls:sys_enter_sched_yield'
  if args.mode == 'process':
    C.info('post-processing only (not profiling)')
    args.profile_mask &= ~0x1
    if args.profile_mask & 0x300: args.profile_mask |= 0x2
  record_steps = ('record', 'lbr', 'pebs', 'ldlat', 'pt')
  if args.sys_wide:
    if args.mode != 'process': C.info('system-wide profiling')
    do['run'] = 'sleep %d'%args.sys_wide
    for x in ('stat', 'stat-ipc') + record_steps: do['perf-'+x] += ' -a'
    args.toplev_args += ' -a'
    args.profile_mask &= ~0x4 # disable system-wide profile-step
  if do['container']:
    if args.mode != 'process': C.info('container profiling')
    for x in record_steps: do['perf-'+x] += ' --buildid-all --all-cgroup'
  do_cmd = '%s # version %s' % (C.argv2str(), version())
  if do['log_stdio']: C.log_stdio = '%s-out.txt' % ('run-default' if args.app == C.RUN_DEF else uniq_name())
  C.printc('\n\n%s\n%s' % (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), do_cmd), log_only=True)
  cmds_file = '.%s.cmd' % uniq_name()
  if os.path.isfile(cmds_file):
    C.exe_cmd('mv %s %s-%d.cmd' % (cmds_file, cmds_file.replace('.cmd', ''), os.getpid()), fail=0)
  do['cmds_file'] = open(cmds_file, 'w')
  do['cmds_file'].write('# %s\n' % do_cmd)
  if args.verbose > 5: C.printc(str(args))
  if args.verbose > 6: C.printc('\t' + C.dict2str(do))
  if args.verbose > 9: C.dump_stack_on_error = 1

  for c in args.command:
    param = c.split(':')[1:] if ':' in c else None
    if   c == 'forgive-me':   pass
    elif c == 'setup-all':    tools_install()
    elif c == 'prof-no-mux':  profile(args.profile_mask if args.profile_mask != C.PROF_MASK_DEF else 0x80,
                                      toplev_args=['vl6', ' --metric-group +Summary --single-thread'])
    elif c == 'build-perf':   exe('%s ./do.py setup-all --install-perf build -v%d --tune %s' % (do['python'],
      args.verbose, ' '.join([':%s:0' % x for x in (do['packages']+('xed', 'tee'))])))
    elif c == 'setup-perf':   setup_perf()
    elif c == 'find-perf':    exe(Find_perf)
    elif c == 'tools-update': tools_update()
    elif c.startswith('tools-update:'): tools_update(level=int(param[0]))
    # TODO: generalize disable/enable features that follow
    elif c == 'disable-smt':  smt()
    elif c == 'enable-smt':   smt('on')
    elif c == 'disable-atom': atom()
    elif c == 'enable-atom':  atom('online')
    elif c == 'disable-aslr': exe('echo 0 | sudo tee /proc/sys/kernel/randomize_va_space')
    elif c == 'disable-hugepages': exe('echo never | sudo tee /sys/kernel/mm/transparent_hugepage/enabled')
    elif c == 'enable-hugepages':  exe('echo always | sudo tee /sys/kernel/mm/transparent_hugepage/enabled')
    elif c == 'disable-prefetches': exe('sudo wrmsr -a 0x1a4 0xf && sudo rdmsr 0x1a4')
    elif c == 'enable-prefetches':  exe('sudo wrmsr -a 0x1a4 0 && sudo rdmsr 0x1a4')
    elif c == 'enable-fix-freq':    fix_frequency()
    elif c == 'disable-fix-freq':   fix_frequency('undo')
    elif c == 'help':         do['help'] = 1; toplev_describe(args.metrics, mod='')
    elif c == 'install-python': exe('./do.py setup-all -v%d --tune %s' % (args.verbose,
                                    ' '.join([':%s:0' % x for x in (do['packages'] + ('tee', ))])))
    elif c == 'log':          log_setup()
    elif c == 'profile':      profile(args.profile_mask)
    elif c.startswith('get'): get(param)
    elif c == 'tar':          do_logs(c, tag='.'.join((uniq_name(), pmu.cpu_TLA())) if app_name() else C.error('provide a value for -a'))
    elif c == 'clean':        do_logs(c)
    elif c == 'all':
      setup_perf()
      profile(args.profile_mask | 0x1)
      do_logs('tar')
    elif c == 'build':        build_kernel()
    elif c == 'reboot':       exe('history > history-%d.txt && sudo shutdown -r now' % os.getpid(), redir_out=None)
    elif c == 'version':      print(os.path.basename(__file__), 'version =', version(), '; lbr =', lbr_version())
    elif c.startswith('backup'):
      r = '../perf-tools-%s-lbr%s-e%d.tar.gz' % (version(), lbr_version(), len(param))
      to = 'ayasin@10.184.76.216:/nfs/site/home/ayasin/ln/mytools'
      if os.path.isfile(r): C.warn('file exists: %s' % r)
      fs = ' '.join(exe2list('git ls-files | grep -v pmu-tools') + ['.git'] + param if param else [])
      scp = 'scp %s %s' % (r, to)
      exe('tar -czvf %s %s ; echo %s' % (r, fs, scp), redir_out=None)
      #subprocess.Popen(['scp', r, to])
    else:
      C.error("Unknown command: '%s' !" % c)
      return -1
  return 0

def get(param):
  assert param and len(param) == 3, '3 parameters expected: e.g. get:<what>:<logfile>:<num>'
  sub, log, num = param
  num = int(num)
  if log == '-': log = exe_1line('ls -1tr *.%s.log | tail -1' % ('info' if sub == 'x2g-indirects' else sub))
  if sub == 'indirects': print(','.join([ '0x%s' % x.lstrip('0') for x in exe2list("tail -%d %s | grep -v total | sed 's/bnd jmp/bnd-jmp/'" % (num, log))[2:][::5] ]))
  elif sub == 'x2g-indirects':  exe("grep -E '^0x[0-9a-f]+:' %s | sort -n -k2 |grep -v total|uniq|tail -%d|cut -d: -f1|tr '\\n' ,|sed 's/.$/\\n/'" % (log, num))

if __name__ == "__main__":
  main()
  do['cmds_file'].close()
