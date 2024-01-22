#!/usr/bin/env python
# Copyright (c) 2020-2024, Intel Corporation
# Author: Ahmad Yasin
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
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
# pump version for changes with collection/report impact: by .01 on fix/tunable, by .1 on new command/profile-step/report
__version__ = 2.93

import argparse, os.path, sys
import common as C, pmu, stats, tma
from datetime import datetime
from getpass import getuser
from math import log10
from platform import python_version

def isfile(f): return f and os.path.isfile(f)
globs = {
  'cmds_file':          None,
  'find-perf':          'sudo find / -name perf -executable -type f | grep ^/',
  'force-cpu':          C.env2str('FORCECPU'),
  'ldlat-def':          '7',
  'perf-mux-interval':  53,
  'setup-log':          'setup-system.log',
  'time':               '/usr/bin/time',
  'tunable2pkg':        {'loop-ideal-ipc': 'libtinfo5', 'msr': 'msr-tools', 'xed': 'python3-pip'},
  'uname-a':            C.exe_one_line('uname -a')
}
if globs['uname-a'].startswith('Darwin'):
  C.error("Are you on MacOS? it is not supported; 'uname -a =' %s" % globs['uname-a'])

do = {'run':        C.RUN_DEF,
  'asm-dump':       30,
  'batch':          0,
  'calibrate':      0,
  'comm':           None,
  'compiler':       'gcc -O2 -ffast-math', # ~/tools/llvm-6.0.0/bin/clang',
  'container':      0,
  'core':           1,
  'cpuid':          0 if not isfile('/etc/os-release') or C.any_in(['Red Hat', 'CentOS'], C.file2str('/etc/os-release', 1)) else 1,
  'debug':          0,
  'dmidecode':      0,
  'extra-metrics':  "+Mispredictions,+BpTkBranch,+IpCall,+IpLoad",
  'flameg':         0,
  'forgive':        1,
  'gen-kernel':     1,
  'help':           1,
  'interval':       10,
  'imix':           0x3f, # bit 0: hitcounts, 1: imix-no, 2: imix, 3: process-all, 4: non-cold takens, 5: misp report
  'loop-ideal-ipc': 0,
  'loop-srcline':   0,
  'loops':          min(pmu.cpu('corecount'), 30),
  'log-stdout':     1,
  'lbr-branch-stats': 1,
  'lbr-indirects':  None,
  'lbr-jcc-erratum': 0,
  'lbr-stats':      '- 0 10 0 ANY_DSB_MISS',
  'lbr-stats-tk':   '- 0 20 1',
  'lbr-verbose':    0,
  'ldlat':          int(globs['ldlat-def']),
  'levels':         2,
  'metrics':        tma.get('key-info'),
  'model':          'MTL',
  'msr':            0,
  'msrs':           pmu.cpu_msrs(),
  'nodes':          "+CoreIPC,+Instructions,+CORE_CLKS,+Time,-CPUs_Utilized,-CPU_Utilization",
  'numactl':        1,
  'objdump':        'binutils-gdb/binutils/objdump' if isfile('./binutils-gdb/binutils/objdump') else 'objdump',
  'package-mgr':    C.os_installer(),
  'packages':       ['cpuid', 'dmidecode', 'numactl'] + list(globs['tunable2pkg'].keys()),
  'perf-ann-top':   3,
  'perf-filter':    1,
  'perf-lbr':       '-j any,save_type -e %s -c %d' % (pmu.lbr_event(), pmu.lbr_period()),
  'perf-ldlat':     '-e %s -c 1001' % pmu.ldlat_event(globs['ldlat-def']),
  'perf-pebs':      '-b -e %s -c 1000003' % pmu.event('dsb-miss'),
  'perf-pebs-top':  0,
  'perf-pt':        "-e '{intel_pt//u,%su}' -c %d -m,64M" % (pmu.lbr_event(), pmu.lbr_period()), # noretcomp
  'perf-record':    ' -g ', # '-e BR_INST_RETIRED.NEAR_CALL:pp ',
  'perf-report-append': '',
  'perf-scr':       0,
  'perf-stat':      '', # '--topdown' if pmu.perfmetrics() else '',
  'perf-stat-add':  2, # additional events using general counters
  'perf-stat-def':  'context-switches,cpu-migrations,page-faults', # JIRA LFE-9106
  'perf-stat-ipc':  'stat -e instructions,cycles',
  'pin':            'taskset 0x4',
  'plot':           0,
  'python':         sys.executable,
  'python-pkgs':    ['numpy', 'pandas', 'xlsxwriter'],
  'reprocess':      2,
  'sample':         2,
  'size':           0,
  'super':          0,
  'tee':            1,
  'time':           0,
  'tma-group':      None,
  'xed':            1 if pmu.cpu('x86', 0) else 0,
}
args = argparse.Namespace()

def exe(x, msg=None, redir_out='2>&1', run=True, log=True, timeit=False, fail=1, background=False, export=None):
  def get_time_cmd():
    X, i = x.split(), 0
    while C.any_in(('=', 'python'), X[i]): i += 1
    j=i+1
    while C.any_in(('--no-desc',), X[j]): j += 1
    kk = C.flag_value(x, '-e') or '' if ' record' in x else C.flag_value(x, '-F') if ' script' in x else X[j+1]
    cmd_name = C.chop('-'.join((X[i].split('/')[-1], X[j], kk)))
    time_str = '%s %s' % (globs['time'], '-f "\\t%%E time-real:%s"' % cmd_name if do['time'] > 1 else '')
    X.insert(1 if '=' in X[0] else 0, time_str)
    return ' '.join(X)
  if msg and do['batch']: msg += " for '%s'" % args.app
  if redir_out: redir_out=' %s' % redir_out
  if not do['tee']: x = x.split('|')[0]
  x = x.replace('| ./', '| %s/' % C.dirname())
  if x.startswith('./'): x.replace('./', '%s/' % C.dirname(), 1)
  profiling = C.any_in([' stat', ' record', 'toplev.py', 'genretlat'], x)
  if do['time'] and profiling: timeit = True
  if timeit and not export: x = get_time_cmd()
  x = bash(x, export).replace('  ', ' ').strip()
  debug = args.verbose > 0
  if getuser() == 'root': x = x.replace('sudo ', '')
  if len(vars(args)):
    run = not args.print_only
    if profiling:
      if args.mode == 'process':
        x, run, debug = '# ' + x, False, args.verbose > 2
        if not 'perf record ' in x: msg = None
    elif args.mode == 'profile':
        x, run, debug = '# ' + x, False, args.verbose > 2
    elif '--xed' in x and not isfile(C.Globals['xed']): C.error('!\n'.join(('xed was not installed',
      "required by '%s' in perf-script of '%s'" % (msg, x), 'try: ./do.py setup-all --tune :xed:1 ')))
    if background: x = x + ' &'
    if C.any_in(['perf script', 'toplev.py'], x) and C.any_in(['Unknown', 'generic'], pmu.name()):
      C.warn('CPU model is unrecognized; consider Linux kernel update (https://intelpedia.intel.com/IntelNext#Intel_Next_OS)', suppress_after=1)
    if globs['cmds_file'] and (not 'loop_stats' in x or args.verbose > 3) and (not x.startswith('#') or args.verbose > 2 or do['batch']):
      globs['cmds_file'].write(x + '\n')
      globs['cmds_file'].flush()
  return C.exe_cmd(x, msg, redir_out, debug, run, log, fail, background)
def exe1(x, m=None, fail=1, log=True):
  if args.stdout and '| tee' in x: x, log = x.split('| tee')[0], False
  return exe(x, m, redir_out=None, fail=fail, log=log)
def exe_to_null(x): return exe1(x + ' > /dev/null')
def exe_v0(x='true', msg=None): return C.exe_cmd(x, msg) # don't append to cmds_file
def prn_line(f): exe_v0('echo >> %s' % f)
def print_cmd(x, show=True):
  if show and not do['batch'] and args.verbose >= 0: C.printc(x)
  if len(vars(args))>0 and globs['cmds_file']: globs['cmds_file'].write('# ' + x + '\n')

def bash(x, px=None): return '%s bash -c "%s" 2>&1' % (px or '', x.replace('"', '\\"')) if 'tee >(' in x or x.startswith(globs['time']) or px else x
def exe_1line(x, f=None, heavy=True):
  return "-1" if args.mode == 'profile' and heavy or args.print_only else C.exe_one_line(bash(x), f, args.verbose > 1)
def exe2list(x, sep=' '): return ['-1'] if args.mode == 'profile' or args.print_only else C.exe2list(x, sep, args.verbose > 1)

def error(x): C.warn(x) if do['forgive'] else C.error(x)
def warn_file(x):
  if not args.mode == 'profile' and not args.print_only and not isfile(x): C.warn('file does not exist: %s' % x)

def version(): return str(round(__version__, 3 if args.tune else 2))
def module_version(mod_name):
  if mod_name == 'lbr':
    import lbr
    mod = lbr
  elif mod_name == 'stats':
    import stats
    mod = stats
  elif mod_name == 'study':
    import study
    mod = study
  else: C.error('Unsupported module: ' + mod_name)
  return '%s=%.2f' % (mod_name, mod.__version__)
def profiling(): return args.mode != 'process'
def user_app(): return args.output or args.app != C.RUN_DEF
def uniq_name(): return args.output or C.command_basename(args.app, args.app_iterations if args.gen_args else None)[:200]
def toplev_describe(m, msg=None, mod='^'):
  if do['help'] < 1: return
  exe('%s --describe %s%s' % (get_perf_toplev()[1], m, mod), msg, redir_out=None)
def read_toplev(l, m): return None if do['help'] < 0 else stats.read_toplev(l, m)
def perf_record_true(): return '%s record true > /dev/null' % get_perf_toplev()[0]

def tools_install(installer='sudo %s -y install ' % do['package-mgr'], packages=[]):
  if args.install_perf:
    if args.install_perf == 'install':
      if do['package-mgr'] == 'dnf': exe('sudo yum install perf', 'installing perf')
      else: packages += ['linux-tools-generic && ' + globs['find-perf']]
    elif args.install_perf == 'build':
      b='./build-perf.sh'
      if 'apt-get' in C.file2str(b): exe('sed -i s/apt\-get/%s/ %s'%(do['package-mgr'],b))
      exe('%s | tee %s.log'%(b, b.replace('.sh','')), 'building perf anew')
    elif args.install_perf == 'patch':
      exe_v0(msg='setting default perf')
      a_perf = C.exe_output(globs['find-perf'] + ' | grep -v /usr/bin/perf | head -1', '')
      exe('ln -f -s %s /usr/bin/perf'%a_perf)
    else: C.error('Unsupported --perf-install option: '+args.install_perf)
  for x in do['packages']:
    if do[x]: packages += [globs['tunable2pkg'][x] if x in globs['tunable2pkg'] else x]
  #if len(packages) and not do['package-mgr'].startswith('apt'): exe(installer.replace('install', 'makecache --refresh'), 'updating %s DB' % do['package-mgr'])
  for x in packages:
    exe(installer + x, 'installing ' + x.split(' ')[0])
  if do['xed']:
    if do['xed'] < 2 and isfile(C.Globals['xed']): exe_v0(msg='xed is already installed')
    else: exe('./build-xed.sh', 'installing xed')
    pip = 'pip3' if python_version().startswith('3') else 'pip'
    for x in do['python-pkgs']: exe('%s install %s' % (pip, x), '@installing %s' % x)
    if 'Red Hat' in C.file2str('/etc/os-release', 1): exe('sudo yum install python3-xlsxwriter.noarch', '@patching xlsx')
  if do['msr']: exe('sudo modprobe msr', 'enabling MSRs')
  if do['flameg']: exe('git clone https://github.com/brendangregg/FlameGraph', 'cloning FlameGraph')
  if do['loop-ideal-ipc']:
    if isfile(C.Globals['llvm-mca']): exe_v0(msg='llvm is already installed')
    else: exe('./build-llvm.sh', 'installing llvm')

def tools_update(kernels=[], mask=0x7):
  if mask & 0x1: 
    ks = [''] + C.exe2list("git status | grep 'modified.*kernels' | cut -d/ -f2") + kernels
    exe('git checkout HEAD run.sh' + ' kernels/'.join(ks))
  if mask & 0x2: exe('git pull')
  if mask & 0x4:
    exe(args.pmu_tools + "/event_download.py ")
    if do['super']:
      if mask & 0x8: exe('mv ~/.cache/pmu-events /tmp')
      exe(args.pmu_tools + "/event_download.py -a") # requires sudo; download all CPUs
  if mask & 0x10: exe('git submodule update --remote')

def set_sysfile(p, v): exe_to_null('echo %s | sudo tee %s'%(v, p))
def prn_sysfile(p, out=None): exe_v0('printf "%s : %s \n" %s' % (p, C.file2str(p), C.flag2str(' >> ', out)))
def find_perf():
  exe(globs['find-perf'] + " | tee find-perf.txt", fail=0)
  for x in C.file2lines('find-perf.txt'):
    C.printc('%s: %s' % (x, exe_1line('%s --version' % x)), col=C.color.BLACK)

def setup_perf(actions=('set', 'log'), out=None):
  def set_it(p, v): set_sysfile(p, str(v))
  TIME_MAX = '/proc/sys/kernel/perf_cpu_time_max_percent'
  perf_params = [ # Documentation/admin-guide/sysctl/kernel.rst
    ('/proc/sys/kernel/perf_event_paranoid', -1, ),
    ('/proc/sys/kernel/perf_event_mlock_kb', 60000, ),
    ('/proc/sys/kernel/perf_event_max_sample_rate', int(1e6), 'root'),
    ('/sys/devices/%s/perf_event_mux_interval_ms' % pmu.pmu(), globs['perf-mux-interval'], ),
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
  if 'set' in actions: exe(perf_record_true(), '@testing perf tool', redir_out=None, log=False) # fail if no perf tool

def smt(x='off'):
  if len(args.command) > 1: exe_v0(msg='setting SMT to: ' + x)
  set_sysfile('/sys/devices/system/cpu/smt/control', x)
  if do['super']: exe(args.pmu_tools + '/cputop "thread == 1" %sline | sudo sh'%x)
def atom(x='offline'):
  exe(args.pmu_tools + "/cputop 'type == \"atom\"' %s"%x)
  print(".. or try: for x in {16..23}; do echo %d | sudo tee /sys/devices/system/cpu/cpu$x/online; done" %
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

def msr_set(m, mask, set=True):
  v = pmu.msr_read(m)
  if C.is_num(v, 16):
    v = int(v, 16)
    return (v | mask) if set else (v & ~mask)
def msr_clear(m, mask): return msr_set(m, mask, set=False)

def log_setup(out=globs['setup-log'], c='setup-cpuid.log', d='setup-dmesg.log'):
  def label(x, tool='dmesg'): return C.grep(x, flags='-H --label %s' % tool)
  def log_patch(x, patch='| sed s/=/:\ /'): return exe("%s %s >> %s" % (x, patch, out))
  def new_line(): return prn_line(out)
  def version(tool): C.fappend('%s: %s' % (tool, exe_1line('%s --version | head -1' % tool)), out)
  forcecpu = globs['force-cpu']
  C.printc('%s%s' % (('%s/' % forcecpu.lower()) if forcecpu else '', pmu.name(real=True))) #OS
  if args.mode == 'process': return
  exe('uname -a | sed s/Linux/Linux:/ > ' + out, 'logging setup')
  log_patch("cat /etc/os-release | egrep -v 'URL|ID_LIKE|CODENAME'")
  for f in ('/sys/kernel/mm/transparent_hugepage/enabled',
            '/sys/devices/system/node/node0/memory_side_cache/index1/size'):
    if isfile(f): prn_sysfile(f, out)
  log_patch("sudo sysctl -a | tee setup-sysctl.log | egrep 'randomize_va_space|hugepages ='")
  C.fappend('IP-address: %s' % exe_1line('hostname -i'), out)
  exe("env > setup-env.log")
  new_line()          #CPU
  exe("lscpu | tee setup-lscpu.log | egrep 'family|Model|Step|(Socket|Core|Thread)\(' >> " + out)
  if do['msr']:
    if do['msr'] > 1: do['msrs'] += [pmu.MSR['IA32_MCU_OPT_CTRL']]
    for m in do['msrs']:
      v = pmu.msr_read(m)
      exe('echo "MSR 0x%03x: %s" >> %s' % (m, ('0'*(16 - len(v)) if C.is_num(v, 16) else '\t\t') + v, out))
  if do['cpuid']: exe("cpuid -1 > %s && cpuid -1r | tee -a %s | %s >> %s" % (c, c, label(' 0x00000001', 'cpuid'), out))
  exe("sudo dmesg -T | tee %s | %s >> %s && cat %s | %s | tail -1 >> %s" % (d,
    label('Command line|Performance E|micro'), out, d, label('BIOS '), out))
  exe("%s && %s report -I --header-only > setup-cpu-topology.log" % (perf_record_true(), get_perf_toplev()[0]))
  new_line()          #PMU
  C.fappend('PMU: %s\n%sTMA version:\t%s' % (pmu.name(real=True), ("Force CPU: %s\n" % forcecpu.lower()) if forcecpu else '',
                                             pmu.cpu('TMA version')), out)
  version(args.perf); setup_perf('log', out)
  new_line()          #Tools
  C.fappend('python version: ' + python_version(), out)
  for x in (do['compiler'].split()[0], 'as', 'ldd'): version(x)
  if do['loop-ideal-ipc']: log_patch('%s --version | %s >> %s' % (C.Globals['llvm-mca'], label('version', 'llvm-mca'), out))
  new_line()          #Memory
  exe('find /sys/devices/system/node > setup-node.log')
  if do['numactl']: exe('numactl -H >> ' + out)
  new_line()          #Devices, etc
  exe("lsmod | tee setup-lsmod.log | egrep 'Module|kvm' >> " + out)
  exe("ulimit -a > setup-ulimit.log")
  if do['dmidecode']: exe("sudo dmidecode | tee setup-memory.log | egrep -A15 '^Memory Device' | "
    "egrep '(Size|Type|Speed|Bank Locator):' | sort | uniq -c | sort -nr | %s >> %s" % (label('.', 'dmidecode'), out))

def perf_version(): return exe_1line(args.perf + ' --version', heavy=False).replace('perf version ', '')
def perf_version_float(): v = perf_version(); return float('.'.join(v.split('.')[0:2])) if v.isdigit() else 10
def get_perf_toplev():
  perf, env, ptools = args.perf, '', {}
  if perf != 'perf':
    C.check_executable(perf)
    env = 'PERF=%s ' % perf
  for x in ('toplev.py', 'ocperf', 'genretlat'):
    C.check_executable('/'.join((args.pmu_tools.split()[-1], x)))
    ptools[x] = env + args.pmu_tools + '/' + x
  if args.verbose > 5: ptools['toplev.py'] = 'OCVERBOSE=1 %s' % ptools['toplev.py']
  forcecpu = globs['force-cpu']
  if forcecpu:
    ptools['toplev.py'] += ' --force-cpu=%s' % pmu.force_cpu_toplev(forcecpu)
    ptools['ocperf'] = 'EVENTMAP=%s %s' % (pmu.force_cpu(forcecpu), ptools['ocperf'])
  elif do['core']:
    ##if pmu.perfmetrics(): toplev += ' --pinned'
    if pmu.hybrid(): ptools['toplev.py'] += ' --cputype=core'
  return (perf, ptools['toplev.py'], ptools['ocperf'], ptools['genretlat'])

def profile(mask, toplev_args=['mvl6', None]):
  out, profile_help = uniq_name(), {}
  perf, toplev, ocperf, genretlat = get_perf_toplev()
  base = '%s%s.perf' % (out, C.chop(do['perf-record'], ' :/,='))
  logs = {'stat': None, 'code': base + '-code.log', 'tma': None}
  def profile_exe(cmd, msg, step, mode='redirect', tune='', fail=0):
    if do['help'] < 0:
      if ' -r3' in cmd: tune = '[--repeat 3%s]' % (' --tune :levels:2' if ' -vl2 ' in cmd else '')
      elif ' -I10' in cmd: tune = '[--tune :interval:10]'
      elif ' record' in cmd and C.any_in((' -b', ' -j'), cmd): tune = '--tune :sample:3' if 'PEBS' in msg else '[--tune :sample:2]'
      elif len(tune): tune = '[--tune :%s:1]' % tune if 'stacks' in msg else 'setup-all --tune :%s:1' % tune
      profile_help[step] = '%x | %-50s | %s' % (2 ** step, msg, tune)
      return
    if mode == 'log-setup': return log_setup()
    if args.sys_wide and not (' -a ' in cmd): C.error("Incorrect system wide in profile-step='%s' cmd='%s'" % (msg, cmd))
    if mode == 'perf-stat': return exe1(cmd, msg, fail=fail)
    else: return exe(cmd, msg)
  def profile_mask_help(filename = 'profile-mask-help.md'):
    hdr = ('%7s' % 'mask', '%-50s' % 'profile-step', 'additional [optional] arguments')
    title = ("## Help for profile-steps in the profile command",
             "This is the bitmask argument --profile-mask <hex-value> (or -pm) of do.py",
             "Bits of multiple steps can be set in same run", "")
    with open(filename, 'w') as f1:
      f1.write('\n'.join(['\n\t'.join(title), ' | '.join(hdr), ' | '.join(('-' * len(hdr[i]) for i in range(len(hdr)))), '']))
      for k in sorted(profile_help.keys()): f1.write(profile_help[k] + '\n')
      f1.write('\n')
    C.info('wrote: %s' % filename)
  def mask_eq(mask): return args.profile_mask & mask == mask
  def perf_view(cmd='report', src=True):
    append = '%s%s' % (do['perf-report-append'], ' --objdump %s' % do['objdump'] if do['objdump'] != 'objdump' else '')
    return ' '.join((perf, cmd, append if src else ''))
  perf_report = perf_view(src=False)
  perf_report_mods = perf_report + ' --stdio -F sample,overhead,comm,dso'
  perf_report_syms = perf_report_mods + ',sym'
  sort2u = 'sort | uniq -c | sort -n'
  sort2up = sort2u + ' | ./ptage'
  def en(n): return mask & 2**n
  def a_events():
    def power(rapl=['pkg', 'cores', 'ram'], px='/,power/energy-'): return px[(px.find(',')):] + px.join(rapl) + ('/' if '/' in px else '')
    return 'msr/tsc/' + (power() if args.power and not pmu.v5p() else '')
  def perf_ic(data, comm): return ' '.join(['-i', data, C.flag2str('-c ', comm)])
  def perf_F(ilen=False):
    ilen = ilen or do['lbr-jcc-erratum'] or do['lbr-indirects']
    if ilen and perf_version_float() < 5.18: error('perf is too old: %s (no ilen support)' % perf_version())
    return "-F +brstackinsn%s%s --xed%s" % ('len' if ilen else '',
                                                        ',+srcline' if do['loop-srcline'] else '',
                                                        ' 2>>' + err if do['loop-srcline'] else '')
  def perf_stat(flags, msg, step, events='', perfmetrics=do['core'], csv=False,
                basic_events=do['perf-stat-add'] > 1, last_events=',' + do['perf-stat-def'], warn=True,
                grep = "| egrep 'seconds [st]|CPUs|GHz|insn|topdown|Work|System|all branches' | uniq"):
    def append(x, y): return x if y == '' else ',' + x
    evts, perf_args = events, [flags, '-x,' if csv else '--log-fd=1', do['perf-stat'] ]
    if args.metrics: perf_args += ['--metric-no-group', '-M', args.metrics] # 1st is workaround bug 4804e0111662 in perf-stat -r2 -M
    perf_args = ' '.join(perf_args)
    if perfmetrics and do['perf-stat-add'] > -1:
      es, fs = tma.fixed_metrics()
      evts += append(es, evts)
      if fs: perf_args += fs
    if basic_events and do['core']: evts += append(pmu.basic_events(), evts)
    if args.events: evts += append(pmu.perf_format(args.events), evts)
    if args.events or args.metrics or grep is None: grep = "| grep -v 'perf stat'" #keep output unfiltered with user-defined events
    if evts != '': perf_args += ' -e "cpu-clock,%s%s"' % (evts, last_events)
    log = '%s.perf_stat%s.%s' % (out, C.chop(flags.strip()), 'csv' if csv else 'log')
    stat = ' stat %s ' % perf_args + ('-o %s -- %s' % (log, r) if csv else '-- %s | tee %s %s' % (r, log, grep))
    ret = profile_exe(perf + stat, msg, step, mode='perf-stat', fail=0 if warn else -1)
    if args.stdout or do['tee']==0 or do['help']<0: return C.error('perf-stat failed') if ret else None
    if args.mode == 'process': return log
    if not isfile(log) or os.path.getsize(log) == 0:
      ret = profile_exe(ocperf + stat, msg + '@; retry w/ ocperf', step, mode='perf-stat')
    if not isfile(log) or int(exe_1line('wc -l ' + log, 0, False)) < 5:
      if perfmetrics: return perf_stat(flags, msg + '@; no PM', step, events=events, perfmetrics=0, csv=csv, grep=grep)
      else: C.error('perf-stat failed for %s (despite multiple attempts)' % log)
    if ret: C.error('perf_stat() failed')
    return log
  def samples_count(d): return 1e5 if args.mode == 'profile' else int(exe_1line(
    '%s script -i %s -D 2>/dev/null | %sgrep -F RECORD_SAMPLE | wc -l' % (perf, d,
    ('tee >(tail -50 > %s.debug.log) | ' % d) if do['debug'] else '') ))
  def get_comm(data):
    if not do['perf-filter']: return None
    if do['comm']: return do['comm']
    # might be doable to optimize out this 'perf script' with 'perf buildid-list' e.g.
    comm = exe_1line(perf + " script -i %s -F comm | %s | tee %s.comms.log | tail -1" % (data, sort2u, data), 1)
    if comm == 'perf' or comm.startswith('perf-'):
      # e.g. a perf tool overhead bug in Intel event names handling
      exe(' '.join([perf_report_syms, '-i', data, '| grep -A11 Samples']))
      C.error("Most samples in 'perf' tool. Try run longer")
    return "'%s'" % comm if ' ' in comm else comm
  def perf_script(x, msg, data, export='', fail=1, K=1e3):
    if do['perf-scr']:
      samples = K * do['perf-scr']
      if perf_script.first: C.info('processing first %d samples only' % samples)
      export += ' LBR_STOP=%d' % samples
      x = x.replace('GREP_INST', 'head -%d | GREP_INST' % (3*K*samples))
    if do['perf-filter'] and not perf_script.comm:
      perf_script.comm = get_comm(data)
      if perf_script.first and args.mode != 'profile': C.info("filtering on command '%s' in next post-processing" % perf_script.comm)
    instline = '^\s+[0-9a-f]+\s'
    if 'taken branches' in msg: instline += '.*#'
    x = x.replace('GREP_INST', "grep -E '%s'" % instline)
    if perf_script.first and not en(8) and not do['batch']: C.warn('LBR profile-step is disabled')
    perf_script.first = False
    return exe(' '.join((perf, 'script', perf_ic(data, perf_script.comm), x)), msg, redir_out=None,
               timeit=(args.verbose > 2), export=export, fail=fail)
  perf_script.first = True
  perf_script.comm = do['comm']
  def record_name(flags): return '%s%s' % (out, C.chop(flags, (C.CHOP_STUFF, 'cpu_core', 'cpu')))
  def get_stat(s, default=None): return stats.get_stat_log(s, logs['stat']) if isfile(logs['stat']) else default
  def record_calibrate(x):
    factor = do['calibrate']
    if not (factor or args.sys_wide): factor = int(log10(get_stat('CPUs_utilized', 1)))
    if factor:
      if not '000' in C.flag_value(do[x], '-c'): error("cannot calibrate '%s' with '%s'" % (x, do[x]))
      else:
        do[x] = do[x].replace('000', '0' * (3 + factor), 1)
        C.info('\tcalibrated: %s' % do[x])
    return record_name(do[x])
  r = do['run'] if args.gen_args or args.sys_wide else args.app
  if en(0): profile_exe('', 'logging setup details', 0, mode='log-setup')
  if args.profile_mask & ~0x1 and args.verbose >= 0: C.info('App: ' + r)
  if en(1): logs['stat'] = perf_stat('-r%d' % args.repeat, 'per-app counting %d runs' % args.repeat, 1)
  if en(2): perf_stat('-a', 'system-wide counting', 2, grep='| egrep "seconds|insn|topdown|pkg"',
                      events=a_events() if do['perf-stat-add'] > -1 else '')
  if en(3) and do['sample']:
    data = '%s.perf.data' % record_name(do['perf-record'])
    profile_exe(perf + ' record -c %d -o %s %s -- %s' % (pmu.default_period(), data, do['perf-record'], r),
                'sampling %s' % do['perf-record'].replace(' -g ', 'w/ stacks'), 3, tune='sample')
    if do['log-stdout'] and profiling() and do['forgive'] < 2:
      record_out = C.file2lines(C.log_stdio)
      for l in reversed(record_out):
        if 'sampling ' in l: break
        if 'WARNING: Kernel address maps' in l: C.error("perf tool is missing permissions. Try './do.py setup-perf'")
    exe(perf_report + " --header-only -i %s | grep duration" % data)
    print_cmd("Try '%s -i %s' to browse time-consuming sources" % (perf_view(), data))
    #TODO:speed: parallelize next 3 exe() invocations & resume once all are done
    def show(n=7): return "| grep -wA%d Overhead | cut -c-150 | egrep -v '^[#\s]*$| 0\.0.%%' | sed 's/[ \\t]*$//' " % n
    exe(perf_report_syms + " -n --no-call-graph -i %s | tee %s-funcs.log %s| nl -v-1" % (data, base, show()), '@report functions')
    exe(perf_report + " --stdio --hierarchy --header -i %s | tee %s-modules.log %s" % (data, base, show(22)), '@report modules')
    exe("%s --stdio -n -l -i %s | c++filt | tee %s "
        "| tee >(egrep '^\s+[0-9]+ :' | sort -n | ./ptage > %s-code-ips.log) "
        "| egrep -v -E '^(\-|\s+([A-Za-z:]|[0-9] :))' > %s-code_nz.log" % (perf_view('annotate'), data,
        logs['code'], base, base), '@annotate code', redir_out='2>/dev/null', timeit=(args.verbose > 2))
    exe("egrep -w -5 '(%s) :' %s" % ('|'.join(exe2list("egrep '\s+[0-9]+ :' %s | cut -d: -f1 | sort -n | uniq | tail -%d | egrep -vw '^\s+0'" %
      (logs['code'], do['perf-ann-top']))), logs['code']), '@hottest %d+ blocks, all commands' % do['perf-ann-top'])
    if do['xed']: perf_script("-F insn --xed | grep . | %s | tee %s-hot-insts.log | tail" % (sort2up, base),
                              '@time-consuming instructions', data)
  
  toplev += ' --no-desc'
  if do['plot']: toplev += ' --graph -I%d --no-multiplex' % do['interval']
  grep_bk= "egrep '<==|MUX|Info(\.Bot|.*Time)|warning.*zero' | sort " #| " + C.grep('^|^warning.*counts:', color=1)
  tl_skip= "not (found|referenced|supported)|Unknown sample event|^unreferenced "
  grep_NZ= "egrep -iv '^(all|core |)((FE|BE|BAD|RET).*[ \-][10]\.. |Info.* 0\.0[01]? |RUN|Add)|%s|##placeholder##' " % tl_skip
  grep_nz= grep_NZ
  if args.verbose < 2: grep_nz = grep_nz.replace('##placeholder##', ' < [\[\+]|<$')
  def toplev_V(v, tag='', nodes=do['nodes'],
               tlargs = toplev_args[1] if toplev_args[1] else args.toplev_args):
    o = '%s.toplev%s%s.log' % (out, v.split()[0]+tag, '-nomux' if 'no-multiplex' in tlargs else '')
    if pmu.redwoodcove_on():
      retlat = '%s/%s-retlat.json' % (C.dirname(), out)
      tlargs += ' --ret-latency %s' % retlat
      if profiling() and not isfile(retlat):
        exe('%s -q -o %s -- %s' % (genretlat, retlat, r), 'calibrating retire latencies')
    c = "%s %s --nodes '%s' -V %s %s -- %s" % (toplev, v, nodes, C.toplev_log2csv(o), tlargs, r)
    if ' --global' in c:
      # https://github.com/andikleen/pmu-tools/issues/453
      C.warn('Global counting is subject to system noise (cpucount=%d)' % pmu.cpu('cpucount'))
    return c, o
  def tl_args(x): return ' '.join([args.toplev_args, x])
  def topdown_describe(log):
    path = read_toplev(log, 'Critical-Node')
    if path:
      path = path.split('.')
      toplev_describe(path[0], '@description of nodes in TMA tree path to critical node')
      for n in path[1:]: toplev_describe(n)

  # +Info metrics that would not use more counters
  if en(4):
    cmd, logs['tma'] = toplev_V('-vl6', nodes=tma.get('bottlenecks'),
      tlargs=tl_args('--tune \'DEDUP_NODE = "%s"\'' % tma.get('dedup-nodes')))
    profile_exe(cmd + ' | tee %s | %s' % (logs['tma'], grep_bk if args.verbose <= 1 else grep_nz), 'topdown full tree + All Bottlenecks', 4)
    if profiling():
      C.fappend('Info.PerfTools SMT_on - %d' % int(pmu.cpu('smt-on')), logs['tma'])
      insts = read_toplev(logs['tma'], 'Instructions')
      if insts is not None and insts < 1e6:
        C.exe_cmd('grep -w Instructions %s' % logs['tma'], debug=1)
        error("No/too little Instructions = %d " % insts)
    zeros = read_toplev(logs['tma'], 'zero-counts')
    def fail_zeros(): return len([m for m in zeros.split() if m not in tma.get('zero-ok')]) if zeros else 0
    if zeros and fail_zeros():
      # https://github.com/andikleen/pmu-tools/issues/455
      error("Too many metrics with zero counts; %d unexpected (%s). Run longer or use: --toplev-args ' --no-multiplex'" % (fail_zeros(), zeros))
    topdown_describe(logs['tma'])

  if en(5):
    cmd, log = toplev_V('-vl%d' % do['levels'], tlargs=tl_args('-r%d' % args.repeat))
    profile_exe(cmd + ' | tee %s | %s' % (log, grep_nz), 'topdown primary, %d-levels %d runs' % (do['levels'], args.repeat), 5)
  
  if en(6):
    cmd, log = toplev_V('--drilldown --show-sample -l1', nodes='+IPC,+Heavy_Operations,+Time',
      tlargs='' if args.toplev_args == C.TOPLEV_DEF else args.toplev_args)
    profile_exe(cmd + ' | tee %s | egrep -v "^(Run toplev|Add|Using|Sampling)|perf.* record" ' % log, 'topdown auto-drilldown', 6)
    topdown_describe(log)
    if do['sample'] > 3:
      cmd = C.exe_output("grep 'perf record' %s | tail -1"%log)
      exe(cmd, '@sampling on bottleneck')
      perf_data = cmd.split('-o ')[1].split(' ')[0]
      print_cmd("Try '%s -i %s' to browse sources for critical bottlenecks"%(perf_report, perf_data))
      for c in ('report', 'annotate'):
        exe("%s --stdio -i %s > %s " % (perf_view(c), perf_data, log.replace('toplev--drilldown', 'locate-'+c)), '@'+c)

  if en(12):
    cmd, logs['info'] = toplev_V('-mvl2 --no-sort %s' % ('' if args.sys_wide else ' --no-uncore'),
                        nodes='+IPC,-CPUs_Utilized,'+tma.get('bottlenecks-only').replace('+', '-'))
    profile_exe(cmd + ' | tee %s | %s' % (logs['info'], grep_nz), 'Info metrics', 12)

  if en(13):
    cmd, log = toplev_V('-vvl2', nodes=tma.get('fe-bottlenecks') + ',+Fetch_Latency*/3,+Branch_Resteers*/4,+IpTB,+CoreIPC')
    profile_exe(cmd + ' | tee %s | %s' % (log, grep_nz), 'topdown FE Bottlenecks', 13)
    print_cmd("cat %s | %s"%(log, grep_NZ), False)

  if en(15):
    group = do['tma-group']
    if not logs['tma']: C.warn('topdown-group requires topdown-full profile-step')
    elif not group:
      group = read_toplev(logs['tma'], 'Critical-Group')
      if group: C.info('detected group: %s' % group)
    if not group: group, x = 'Mem', C.warn("Could not auto-detect group; Minimize system-noise, e.g. try './do.py disable-smt'")
    MG='--metric-group +Summary'
    assert MG in args.toplev_args, "'%s' is missing in toplev-args! " % MG
    cmd, log = toplev_V('-vl2', tag='-'+group, nodes=tma.get('fixed'), tlargs=args.toplev_args.replace(MG, ',+'.join((MG, group))))
    profile_exe(cmd + ' | tee %s | %s' % (log, grep_nz), 'topdown %s group' % group, 15)
    print_cmd("cat %s | %s" % (log, grep_NZ), False)

  if en(16):
    if profiling():
      if pmu.cpu('smt-on'): C.error('bottlenecks-view: disable-smt')
      if not pmu.perfmetrics(): C.error('bottlenecks-view: no support prior to Icelake')
    logs['bott'] = perf_stat('-r1', 'bottlenecks-view', 16, tma.get('perf-groups'),
      perfmetrics=None, basic_events=False, last_events='', grep="| egrep 'seconds [st]|inst_retired_any '", warn=False)
    if do['help'] >= 0: stats.perf_log2stat(logs['bott'], 0)

  if en(14) and (pmu.meteorlake() or do['help']<0):
    flags, raw, events = '-W -c 20011', 'raw' in do['model'], pmu.get_events(do['model'])
    nevents = events.count('/p' if raw else ':p')
    data = '%s_tpebs-perf.data' % record_name('_%s-%d' % (do['model'], nevents))
    cmd = "%s record %s -e %s -o %s -- %s" % (perf if raw else ocperf, flags, events, data, r)
    profile_exe(cmd, "TMA sampling (%s with %d events)" % (do['model'], nevents), 14)
    n = samples_count(data)
    if n < 1e4: C.warn("Too little samples collected (%s in %s); rerun with: --tune :model:'MTLraw:2'" % (n, data))
    exe("%s script -i %s -F event,retire_lat > %s.retire_lat.txt" % (perf, data, data))
    exe("sort %s.retire_lat.txt | uniq -c | sort -n | ./ptage | tail" % (data, ))

  def perf_record(tag, step, msg=None, record='record', track_ipc=do['perf-stat-ipc']):
    perf_data, flags = '%s.perf.data' % record_calibrate('perf-%s' % tag), do['perf-%s' % tag]
    assert C.any_in(('-b', '-j any', 'ldlat', 'intel_pt'), flags) or (do['forgive'] > 1), 'No unfiltered LBRs! for %s: %s' % (tag, flags)
    cmd = "bash -c '%s %s %s'" % (perf, track_ipc, r) if len(track_ipc) else '-- %s' % r
    profile_exe(perf + ' %s %s -o %s %s' % (record, flags, perf_data, cmd), 'sampling-%s%s' % (tag.upper(), C.flag2str(' on ', msg)), step)
    warn_file(perf_data)
    if not tag in ('ldlat', 'pt'): print_cmd("Try '%s -i %s --branch-history --samples 9' to browse streams" % (perf_view(), perf_data))
    n = samples_count(perf_data)
    def warn(x='little'): C.warn("Too %s samples collected (%s in %s); rerun with '--tune :calibrate:%d'" % (x, n,
      perf_data, do['calibrate'] + (-1 if x == 'little' else 1)))
    if n == 0: C.error("No samples collected in %s ; Check if perf is in use e.g. '\ps -ef | grep perf'" % perf_data)
    elif n < 1e4: warn()
    elif n > 1e5: warn("many")
    return perf_data, n
  
  if en(8) and do['sample'] > 1:
    assert C.any_in((pmu.lbr_event()[:-1], 'instructions:ppp') ,do['perf-lbr']) or do['forgive'] > 2, 'Incorrect event for LBR in: %s, use LBR_EVENT=<event>' % do['perf-lbr']
    data, nsamples = perf_record('lbr', 8)
    info, comm = '%s.info.log' % data, get_comm(data)
    clean = "sed 's/#.*//;s/^\s*//;s/\s*$//;s/\\t\\t*/\\t/g'"
    def print_info(x):
      if args.mode != 'profile': exe_v0('printf "%s" >%s %s' % (x, '' if print_info.first else '>', info))
      print_info.first = False
    print_info.first = True
    def static_stats():
      if args.mode == 'profile': return
      bins = exe2list(perf + " script -i %s | cut -d\( -f2 | cut -d\) -f1 | egrep -v '^\[|anonymous' | %s | tail -5" %
                        (data, sort2u))[1:][::2]
      assert len(bins)
      print_info('# %s:\n#\n' % 'Static Statistics')
      exe('size %s >> %s' % (' '.join(bins), info), "@stats")
      bin=bins[-1]
      if isfile(bin):
        print_info('\ncompiler info for %s (check if binary was built with -g if nothing is printed):\n' % bin)
        exe("strings %s | %s >> %s" % (bin, C.grep('^(GCC:|clang [bv])'), info))
      prn_line(info)
    def log_count(x, l): return "printf 'Count of unique %s%s: ' >> %s && wc -l < %s >> %s" % (
      'non-cold ' if do['imix'] & 0x10 else '', x, info, l, info)
    def log_br_count(x, s): return log_count("%s branches" % x, "%s.%s.log" % (data, s))
    def tail(f=''): return "tail %s | grep -v total" % f
    def check_err(err):
      if not os.path.getsize(err) == 1:
        C.error("perf script failed to extract srcline info! Check errors at '%s'. "
                "Try to use a newer or a different compiler" % err)
    def report_info(info, err, hists=['IPC', 'IpTB']):
      if do['loop-srcline']: check_err(err)
      hist_cmd = ''
      for h in hists: hist_cmd += " && %s | sed '/%s histogram summary/q'" % (C.grep('%s histogram:' % h, info, '-A33'), h)
      exe("%s && tail %s | grep -v '[cC]ount of' %s" % (C.grep('code footprint', info), info, hist_cmd),
          "@top loops & more in " + info)
    # TODO: move this code to a seperate 'analyze' module!
    def calc_misp_ratio():
      misp_file, header, takens_freq, mispreds = data + '.mispreds.log', 'Branch Misprediction Report (taken-only)', {}, {}
      exe_v0(msg='@'+header.lower())
      assert isfile(misp_file) and isfile(data+'.takens.log')
      for l in C.file2lines(data+'.takens.log')[:-1]:
        b = C.str2list(l)
        takens_freq[ b[2] ] = int(b[1])
      for l in C.file2lines(misp_file)[:-1]:
        b = C.str2list(l)
        m = int(b[1])
        mispreds[ (' '.join(b[2:]), C.ratio(m, takens_freq[b[2]])) ] = m * takens_freq[b[2]]
      # significance := hitcounts x mispredicts (based on taken-branch IP)
      C.fappend('\n%s:\n' % header + '\t'.join(('significance', '%7s' % 'ratio', 'instruction addr & ASM')), misp_file)
      for b in C.hist2slist(mispreds): C.fappend('\t'.join(('%12s' % b[1], '%7s' % b[0][1], b[0][0])), misp_file) if b[1] > 1 else None
    lbr_hdr = '# LBR-based Statistics:'
    if not isfile(info) or do['reprocess'] > 1:
      if do['size']: static_stats()
      print_info('# processing %s%s\n' % (data, C.flag2str(" filtered on ", comm)))
      if do['lbr-branch-stats']: exe(perf + " report %s | grep -A13 'Branch Statistics:' | tee -a %s | egrep -v ':\s+0\.0%%|CROSS'" %
          (perf_ic(data, comm), info), None if do['size'] else "@stats")
      if isfile(logs['stat']): exe("egrep '  branches| cycles|instructions|BR_INST_RETIRED' %s >> %s" % (logs['stat'], info))
      sort2uf = "%s |%s ./ptage" % (sort2u, " egrep -v '\s+[1-9]\s+' |" if do['imix'] & 0x10 else '')
      perf_script("-F ip | %s > %s.samples.log && %s" % (sort2uf, data, log_br_count('sampled taken',
        'samples').replace('Count', '\\nCount')), '@processing %d samples' % nsamples, data, fail=0)
      if do['xed']:
        if (do['imix'] & 0x8) == 0:
          perf_script("-F +brstackinsn --xed | GREP_INST| grep MISPRED | %s | %s > %s.mispreds.log" %
                      (clean, sort2uf, data), '@processing mispredicts', data)
        else:
          perf_script("-F +brstackinsn --xed | GREP_INST"
            "| tee >(grep MISPRED | %s | tee >(egrep -v 'call|jmp|ret' | %s > %s.misp_tk_conds.log) | %s > %s.mispreds.log) "
            "| %s | tee >(%s > %s.takens.log) | tee >(grep '%%' | %s > %s.indirects.log) | grep call | %s > %s.calls.log" %
            (clean, sort2uf, data, sort2uf, data, clean, sort2uf, data, sort2uf, data, sort2uf, data),
            '@processing taken branches', data)
          for x in ('taken', 'call', 'indirect'): exe(log_br_count(x, "%ss" % x))
          exe(log_br_count('mispredicted conditional taken', 'misp_tk_conds'))
          if do['imix'] & 0x20 and args.mode != 'profile': calc_misp_ratio()
        exe(log_br_count('mispredicted taken', 'mispreds'))
    else: exe("sed -n '/%s/q;p' %s > .1.log && mv .1.log %s" % (lbr_hdr, info, info), '@reuse of stats log files')
    if do['xed']:
      ips = '%s.ips.log'%data
      hits = '%s.hitcounts.log'%data
      loops = '%s.loops.log' % data
      llvm_mca = '%s.llvm_mca.log' % data
      err = '%s.error.log' % data
      ev = C.flag_value(do['perf-lbr'], '-e')
      print_info('\n%s\n#\n' % lbr_hdr)
      if not isfile(hits) or do['reprocess']:
        lbr_env = "LBR_LOOPS_LOG=%s" % loops
        cycles = get_stat(pmu.event('cycles')) or get_stat('cycles', 0)
        if cycles: lbr_env += ' PTOOLS_CYCLES=%d' % cycles
        if args.verbose > 2: do['lbr-verbose'] |= 0x800
        if do['lbr-verbose']: lbr_env += " LBR_VERBOSE=0x%x" % (do['lbr-verbose'] | C.env2int('LBR_VERBOSE', base=16))
        if do['lbr-indirects']: lbr_env += " LBR_INDIRECTS=%s" % do['lbr-indirects']
        exe('echo > %s' % err)
        misp, cmd, msg = '', perf_F(), '@info'
        if do['imix']:
          print_cmd(' '.join(('4debug', perf, 'script', perf_ic(data, perf_script.comm), cmd, '| less')), False)
          cmd += " | tee >(%s %s %s %s >> %s) %s | GREP_INST | %s " % (
            lbr_env, C.realpath('lbr_stats'), do['lbr-stats-tk'], ev, info, misp, clean)
          if do['imix'] & 0x1:
            cmd += "| tee >(sort| sed 's/\s\+/\\t/g'|uniq -c|sort -k2 | tee %s | cut -f-2 | sort -nu | ./ptage > %s) " % (hits, ips)
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
        if args.mode != "profile": stats.inst_fusions(hits, info)
        if do['imix'] & 0x4: exe("%s && %s" % (tail('%s.perf-imix-no.log' % out), log_count('instructions', hits)),
            "@instruction-mix no operands")
        if args.verbose > 0: exe("grep 'LBR samples:' %s && tail -4 %s" % (info, ips), "@top-3 hitcounts of basic-blocks to examine in " + hits)
        report_info(info, err)
      if do['loops'] and isfile(loops):
        prn_line(info)
        if do['loop-ideal-ipc']: exe('echo > %s' % llvm_mca)
        cmd, top = '', min(do['loops'], int(exe_1line('wc -l %s' % loops, 0)))
        do['loops'] = top
        while top > 1:
          cmd += ' | tee >(%s %s %s >> %s) ' % (C.realpath('loop_stats'), exe_1line('tail -%d %s | head -1' % (top, loops), 2)[:-1], ev, info)
          top -= 1
        cmd += ' | ./loop_stats %s %s >> %s && echo' % (exe_1line('tail -1 %s' % loops, 2)[:-1], ev, info)
        print_cmd(perf + " script -i %s -F +brstackinsn --xed -c %s | %s %s %s >> %s" % (data, comm, C.realpath('loop_stats'),
          exe_1line('tail -1 %s' % loops, 2)[:-1], ev, info))
        perf_script("%s %s && %s" % (perf_F(), cmd,
                    C.grep('FL-cycles...[1-9][0-9]?', info, color=1)), "@detailed stats for hot loops", data,
                    export='PTOOLS_HITS=%s %s' % (hits, ('LLVM_LOG=%s' % llvm_mca) if do['loop-ideal-ipc'] else ''))
      else: warn_file(loops)

  if en(9) and do['sample'] > 2:
    data = perf_record('pebs', 9, pmu.event_name(do['perf-pebs']))[0]
    exe(perf_report_mods + " %s | tee %s.modules.log | grep -A12 Overhead" % (perf_ic(data, get_comm(data)), data), "@ top-10 modules")
    if do['xed']: perf_script("--xed -F ip,insn | %s | tee %s.ips.log | tail -11" % (sort2up, data), "@ top-10 IPs, Insts", data)
    else: perf_script("-F ip | %s | tee %s.ips.log | tail -11" % (sort2up, data), "@ top-10 IPs", data)
    is_dsb = 0
    if pmu.dsb_msb() and 'DSB_MISS' in do['perf-pebs']:
      if pmu.cpu('smt-on') and not do['batch'] and do['forgive'] < 2: C.warn('Disable SMT for DSB robust analysis')
      else:
        is_dsb = 1
        perf_script("-F ip | ./addrbits %d 6 | %s | tee %s.dsb-sets.log | tail -11" %
                    (pmu.dsb_msb(), sort2up, data), "@ DSB-miss sets", data)
    top = do['perf-pebs-top']
    top_ip = exe_1line("tail -2 %s.ips.log | head -1" % data, 2)
    if top < 0 and isfile(logs['code']):
      exe("grep -w -5 '%s:' %s" % (top_ip, logs['code']), '@code around IP: %s' % top_ip)
    elif not is_dsb: pass
    elif top == 1:
      # asserts in skip_sample() only if piped!!
      perf_script("%s | tee >(%s %s | tee -a %s.ips.log) | ./lbr_stats %s | tee -a %s.ips.log" % (
        perf_F(ilen=True), C.realpath('lbr_stats'), top_ip, data, do['lbr-stats'], data), "@ stats on PEBS event", data)
    else:
      perf_script("%s | ./lbr_stats %s | tee -a %s.ips.log" % (perf_F(ilen=True), do['lbr-stats'], data),
                  "@ stats on PEBS event", data)
    if top > 1:
      cmd = ''
      while top > 0:
        top_ip = exe_1line("egrep '^[0-9]' %s.ips.log | tail -%d | head -1" % (data, top+1), 2)
        cmd += ' | tee >(%s %s >> %s.ctxt.log) ' % (C.realpath('lbr_stats'), top_ip, data)
        top -= 1
      perf_script("%s %s > /dev/null" % (perf_F(ilen=True), cmd), "@ stats on PEBS", data)

  if en(10):
    data = perf_record('ldlat', 10, record='record' if pmu.goldencove() else 'mem record')[0]
    exe("%s mem report --stdio -i %s -F+symbol_iaddr -v " # workaround: missing -F+ip in perf-mem-report
        "-w 5,5,44,5,13,44,18,43,8,5,12,4,7 2>/dev/null | sed 's/RAM or RAM/RAM/;s/LFB or LFB/LFB or FB/' "
        "| tee %s.ldlat.log | grep -A12 -B4 Overhead | tail -17" % (perf, data, data), "@ top-10 samples", redir_out=None)
    def perf_script_ldlat(fields, tag): return perf_script("-F %s | grep -v mem-loads-aux | %s "
      "| tee %s.%s.log | tail -11" % (fields, sort2up, data, tag.lower()), "@ top-10 %s" % tag, data)
    perf_script_ldlat('event,ip,insn --xed', 'IPs')
    perf_script_ldlat('ip,addr', 'DLA-IP')

  if en(7):
    cmd, logs['tma'] = toplev_V('-%s --no-multiplex' % toplev_args[0], '-nomux', ','.join((do['nodes'], do['extra-metrics'])))
    profile_exe(cmd + " | tee %s | %s" % (logs['tma'], grep_nz), 'topdown-%s no multiplexing' % toplev_args[0], 7)

  if en(17):
    csv_file = perf_stat('-I%d' % do['interval'], 'over-time counting at %dms interval' % do['interval'], 17, csv=True)
    if args.events:
      for e in args.events.split(','): exe('egrep -i %s %s > %s' % (e, csv_file, csv_file.replace('.csv', '-%s.csv' % e)))

  if en(19):
    data = perf_record('pt', 19)[0]
    tag, info = 'pt', '%s.info.log' % data
    exe(perf + " script --no-itrace -F event,comm -i %s | %s | tee %s.modules.log | ./ptage | tail" % (data, sort2u, data))
    perf_script("--itrace=Le -F +brstackinsn --xed | tee >(egrep 'ppp|#' > %s.pt-takens.log) | %s %s > %s" %
      (data, C.realpath('lbr_stats'), do['lbr-stats-tk'], info), "@pt info", data)

  if en(18):
    assert do['msr']
    perf_data = '%s.perf.data' % record_name('-e msr')
    profile_exe('sudo %s record -e msr:* -o %s -- %s' % (perf, perf_data, r), 'tracing MSRs', 18, tune='msr')
    x = '-i %s | cut -d: -f3-4 | cut -d, -f1 | sort | uniq -c' % perf_data
    exe(' '.join(('sudo', perf, 'script', x)), msg=None, redir_out=None)

  if en(20) and do['flameg']:
    flags = '-ag -F 49' # -c %d' % pmu.period()
    perf_data = '%s.perf.data' % record_name(flags)
    profile_exe('%s record %s -o %s -- %s' % (perf, flags, perf_data, r), 'FlameGraph', 20, tune='flameg')
    x = '-i %s %s > %s.svg ' % (perf_data,
      ' | ./FlameGraph/'.join(['', 'stackcollapse-perf.pl', 'flamegraph.pl']), perf_data)
    exe(' '.join((perf, 'script', x)), msg=None, redir_out=None, timeit=(args.verbose > 2))
    print('firefox %s.svg &' % perf_data)

  if do['help'] < 0: profile_mask_help()
  elif args.repeat == 3 and (mask_eq(0x1012) or mask_eq(0x82)):
    stats.csv2stat(C.toplev_log2csv(logs['tma']))
    d, not_counted_name, not_supported_name, time = stats.read_perf_toplev(C.toplev_log2csv(logs['tma'])), \
                                                    'num-not_counted-stats', 'num-not_supported-stats', 'DurationTimeInMilliSeconds'
    not_counted, not_supported = d[not_counted_name], d[not_supported_name]
    if not mask_eq(0x80):
      assert d[time] > tma.get('num-mux-groups') * globs['perf-mux-interval'], "Too short run time! %f [ms]" % d[time]
      toplev_d = stats.read_perf_toplev(C.toplev_log2csv(logs['info']))
      not_counted += toplev_d[not_counted_name]
      not_supported += toplev_d[not_supported_name]
    if not_counted > 0 or not_supported > 0:
      msg = "invalid collection! log= %s" % logs['tma']
      if not_counted > 0: error("%s %s=%d" % (msg, not_counted_name, not_counted))
      if not_supported > 0: error("%s %s=%d" % (msg, not_supported_name, not_supported))
  #profile-end

def do_logs(cmd, ext=[], tag=''):
  log_files = ['', 'csv', 'json', 'log', 'stat', 'svg', 'xlsx'] + ext
  if cmd == 'tar':
    r = '.'.join((tag, pmu.cpu('CPU'), 'results.tar.gz')) if len(tag) else C.error('do_logs(tar): expecting tag')
    if isfile(r): exe('rm -f ' + r, 'deleting %s !' % r)
  s = (uniq_name() if user_app() else '')
  if cmd == 'tar':
    files = C.glob('.'+s+'*.cmd') + (C.glob('setup*') if isfile(globs['setup-log']) else [])
    for f in C.glob(s+'*'):
      if not (f.endswith('perf.data') or f.endswith('perf.data.old')): files += [f]
    if isfile('run.sh'): files += ['run.sh']
    exe('tar -czvf %s ' % r + ' '.join(files), 'tar into %s' % r, log=False)
  if cmd == 'clean': exe('rm -rf ' + ' *.'.join(log_files) + ' *-out.txt *perf.data* $(find -name __pycache__) results.tar.gz')

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
  def help_s_arg(x): return x + ' profiling for x seconds. disabled by default'
  modes = ('profile', 'process', 'both') # keep 'both', the default, last on this list
  epilog = """environment variables:
    FORCECPU - force a specific CPU all over e.g. SPR, spr.
  """
  ap = C.argument_parser(usg='do.py command [command ..] [options]',
    defs={'perf': 'perf', 'pmu-tools': '%s %s/pmu-tools' % (do['python'], C.dirname()),
          'toplev-args': C.TOPLEV_DEF, 'nodes': do['metrics']}, epilog=epilog)
  ap.add_argument('command', nargs='+', help='setup-perf log profile tar, all (for these 4) '
                  '\nsupported options: ' + C.commands_list())
  ap.add_argument('--mode', nargs='?', choices=modes, default=modes[-1], help='analysis mode options: profile-only, (post)process-only or both')
  ap.add_argument('--install-perf', nargs='?', default=None, const='install', help='perf tool installation options: [install]|patch|build')
  ap.add_argument('--print-only', action='store_const', const=True, default=False, help='print the commands without running them')
  ap.add_argument('--stdout', action='store_const', const=True, default=False, help='keep profiling unfiltered results in stdout')
  ap.add_argument('--power', action='store_const', const=True, default=False, help='collect power metrics/events as well')
  ap.add_argument('-d', '--delay', type=int, default=0, help=help_s_arg('delay'))
  ap.add_argument('-s', '--sys-wide', type=int, default=0, help=help_s_arg('system-wide'))
  ap.add_argument('-o', '--output', help='basename to use for output files')
  ap.add_argument('-g', '--gen-args', help='args to gen-kernel.py')
  ap.add_argument('-ki', '--app-iterations', default='1e9', help='num-iterations of kernel')
  x = ap.parse_args()
  return x

def main():
  global args
  args = parse_args()
  #args sanity checks
  if args.gen_args or 'build' in args.command:
    if not user_app(): C.error('must specify --app-name with any of: --gen-args, build')
    if not 'build' in args.command: C.error('must use build command with --gen-args')
  if args.output and ' ' in args.output: C.error('--output must not have spaces')
  assert args.sys_wide >= 0, 'negative duration provided!'
  if args.verbose > 4: args.toplev_args += ' -g'
  if args.verbose > 2: args.toplev_args += ' --perf'
  if args.print_only and args.verbose <= 0: args.verbose = 1
  do['nodes'] += ("," + args.nodes)
  if args.events and '{' in args.events: do['perf-stat-add'] = -1
  if args.tune:
    for tlists in args.tune:
      for t in tlists:
        if t.startswith(':'):
          l = t.split(':')
          t = "do['%s']=%s"%(l[1], l[2] if len(l)==3 else ':'.join(l[2:]))
        if args.verbose > 3: print(t)
        exec(t)
  pmu.pmutools = args.pmu_tools
  if do['debug']: C.dump_stack_on_error, stats.debug = 1, do['debug']
  if any(perf_version() == x.split()[0] for x in C.file2lines(C.dirname()+'/settings/perf-bad.txt')):
    C.error('Unsupported perf tool: ' + perf_version())
  do['perf-ldlat'] = do['perf-ldlat'].replace(globs['ldlat-def'], str(do['ldlat']))
  if do['perf-stat-add'] > 0:
    x = ',branches,branch-misses'
    if args.repeat > 1: x += ',cycles:k'
    do['perf-stat-def'] += x
  if do['plot']:
    do['packages'] += ['feh']
    do['python-pkgs'] += ['matplotlib', 'brewer2mpl']
  if do['super']:
    do['perf-stat-def'] += ',syscalls:sys_enter_sched_yield'
  do_cmd = '%s # version %s' % (C.argv2str(), version())
  if do['log-stdout']: C.log_stdio = '%s-out.txt' % (uniq_name() if user_app() else 'run-default')
  C.printc('\n\n%s\n%s' % (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), do_cmd), log_only=True)
  if args.mode == 'process':
    C.info('post-processing only (not profiling)')
    args.profile_mask &= ~0x1
    if args.profile_mask & 0x300: args.profile_mask |= 0x2
  elif args.mode == 'both' and args.verbose >= 0 and args.profile_mask & 0x100 and not (args.profile_mask & 0x2):
    C.warn("Better enable 'per-app counting' profile-step with LBR; try '-pm %x'" % (args.profile_mask | 0x2))
  record_steps = ('record', 'lbr', 'pebs', 'ldlat', 'pt')
  if pmu.hybrid() and args.profile_mask & 0x10000:
    C.warn('bottlenecks view not supported on Hybrid. disabling..')
    args.profile_mask &= ~0x10000
  if args.sys_wide:
    if profiling(): C.info('system-wide profiling')
    do['run'] = 'sleep %d'%args.sys_wide
    for x in ('stat', 'stat-ipc') + record_steps: do['perf-'+x] += ' -a'
    args.toplev_args += ' -a'
    if not do['comm']: do['perf-filter'] = 1
    args.profile_mask &= ~0x4 # disable system-wide profile-step
  if args.delay:
    if profiling(): C.info('delay profiling by %d seconds' % args.delay)
    delay = ' -D %d' % (args.delay * 1000)
    for x in ('stat', 'stat-ipc'): do['perf-'+x] += delay
    for x in record_steps: do['perf-'+x] += delay
    args.toplev_args += delay
  if do['container']:
    if profiling(): C.info('container profiling')
    for x in record_steps: do['perf-'+x] += ' --buildid-all --all-cgroup'
  if args.verbose > 2: C.info('timing perf tool post-processing')
  if args.app and '|' in args.app: C.error("Invalid use of pipe in app: '%s'. try putting it in a .sh file" % args.app)
  if not do['batch'] or args.mode == 'profile':
    cmds_file = '.%s.cmd' % uniq_name()
    if isfile(cmds_file):
      C.exe_cmd('mv %s %s-%d.cmd' % (cmds_file, cmds_file.replace('.cmd', ''), os.getpid()), fail=0)
    globs['cmds_file'] = open(cmds_file, 'w')
    globs['cmds_file'].write('# %s\n' % do_cmd)
  if args.verbose > 5: C.printc(str(args))
  if args.verbose > 6: C.printc('\t' + C.dict2str(do))
  if args.verbose > 9: C.dump_stack_on_error = 1
  # suspend commands
  com2cond = { 'aslr': True, 'atom': True, 'fix-freq': True, 'hugepages': True, 'prefetches': True, 'smt': pmu.cpu('smt-on') }
  while True:
    c = next((c for c in args.command if c.startswith('suspend')), None)
    if not c: break
    com = c.split('suspend-')[1].split()[0]
    if com in com2cond:
      if com2cond[com]: args.command = ['disable-%s' % com] + args.command + ['enable-%s' % com]
      args.command.remove('suspend-%s' % com)
    else:
      C.error("Unknown command: '%s' !" % c)
      return -1
  for c in args.command:
    param = c.split(':')[1:] if ':' in c else None
    if   c == 'forgive-me':   pass
    elif c == 'setup-all':    tools_install()
    elif c == 'prof-no-mux':  profile(args.profile_mask if args.profile_mask != C.PROF_MASK_DEF else 0x80,
                                      toplev_args=['vl6', ' --metric-group +Summary --single-thread'])
    elif c == 'build-perf':   exe('%s ./do.py setup-all --install-perf build -v%d --tune %s' % (do['python'],
      args.verbose, ' '.join([':%s:0' % x for x in (do['packages']+['xed', 'tee', 'loop-ideal-ipc'])])))
    elif c == 'setup-perf':   setup_perf()
    elif c == 'find-perf':    find_perf()
    elif c == 'git-log-oneline': exe("git log --pretty=format:'%h%x09%an%x09%ad%x09%s' | egrep -v "
      "'Merge branch \'master\'|forbid perf tool|\sa bug fix'")
    elif c == 'tools-update': tools_update()
    elif c.startswith('tools-update:'): tools_update(mask=int(param[0], 16))
    elif c == 'eventlist-update': tools_update(mask=0x4)
    elif c.startswith('disable') or c.startswith('enable'):
      en = c.startswith('enable')
      com2func = {'aslr':        (set_sysfile, ('/proc/sys/kernel/randomize_va_space', 1 if en else 0)),
                  'atom':        (atom, 'online' if en else None),
                  'fix-freq':    (fix_frequency, None if en else 'undo'),
                  'hugepages':   (exe, 'echo %s | sudo tee /sys/kernel/mm/transparent_hugepage/enabled' % ('always' if en else 'never')),
                  'prefetches':  (exe, 'sudo wrmsr -a 0x1a4 0x%x && sudo rdmsr 0x1a4' % (msr_clear(0x1a4, 0xf) if en else msr_set(0x1a4, 0xf))),
                  'smt':         (smt, 'on' if en else None)}
      key = c.replace('enable-' if en else 'disable-', '')
      if not key in com2func:
        C.error("Unknown command: '%s' !" % c)
        return -1
      func, arg = com2func[key][0], com2func[key][1]
      func() if arg is None else func(*arg) if type(arg) == tuple else func(arg)
    elif c == 'help':         do['help'] = 1; toplev_describe(args.metrics, mod='')
    elif c == 'install-python': exe('./do.py setup-all -v%d --tune %s' % (args.verbose,
                                    ' '.join([':%s:0' % x for x in (do['packages'] + ('tee', ))])))
    elif c == 'log':          log_setup()
    elif c == 'profile':      profile(args.profile_mask)
    elif c.startswith('get'): get(param)
    elif c == 'tar':          do_logs(c, tag=uniq_name() if user_app() else C.error('provide a value for -a or -o'))
    elif c == 'clean':        do_logs(c)
    elif c == 'all':
      setup_perf()
      profile(args.profile_mask | 0x1)
      do_logs('tar')
    elif c == 'build':        build_kernel()
    elif c == 'reboot':       exe('history > history-%d.txt && sudo shutdown -r now' % os.getpid(), redir_out=None)
    elif c == 'sync-date':    exe('sudo date -s "$(wget -qSO- --max-redirect=0 google.com 2>&1 | grep Date: | cut -d\' \' -f5-8)Z"', redir_out=None)
    elif c == 'version':      print(os.path.basename(__file__), 'version =', version(), '; '.join([''] +
      [module_version(x) for x in ('lbr', 'stats')] + [exe_1line(args.perf + ' --version').replace(' version ', '='),
                                                       'TMA=%s' % pmu.cpu('TMA version')]))
    elif c.startswith('backup'):
      r = '../perf-tools-%s-%s-e%d.tar.gz' % (version(),
          '-'.join([module_version(x) for x in ('lbr', 'stats', 'study')]), len(param))
      to = 'ayasin@10.184.76.216:/nfs/site/home/ayasin/ln/mytools'
      if isfile(r): C.warn('file exists: %s' % r)
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
  if globs['cmds_file']: globs['cmds_file'].close()
