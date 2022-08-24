#!/usr/bin/env python
# Misc utilities for CPU performance analysis on Linux
# Author: Ahmad Yasin
# edited: Aug 2022
# TODO list:
#   report PEBS-based stats for DSB-miss types (loop-seq, loop-jump_to_mid)
#   move profile code to a seperate module, arg for output dir
#   toplev 3-levels default Icelake onwards
#   quiet mode
#   convert verbose to a bitmask
#   add test command to gate commits to this file
#   support disable nmi_watchdog in CentOS
from __future__ import print_function
__author__ = 'ayasin'
__version__= 1.50

import argparse, math, os.path, sys
import common as C
import pmu
from datetime import datetime
from platform import python_version

RUN_DEF = './run.sh'
TOPLEV_DEF='--frequency --metric-group +Summary' #FIXME: argparse should tell whether user specified an options
Find_perf = 'sudo find / -name perf -executable -type f'
do = {'run':        RUN_DEF,
  'asm-dump':       30,
  'cmds_file':      None,
  'compiler':       'gcc -O2', # ~/tools/llvm-6.0.0/bin/clang',
  'container':      0,
  'core':           1,
  'cpuid':          1,
  'dmidecode':      0,
  'extra-metrics':  "+Mispredictions,+IpTB,+BpTkBranch,+IpCall,+IpLoad,+ILP,+UPI",
  'forgive':        0,
  'gen-kernel':     1,
  'loops':          pmu.cpu('corecount'),
  'lbr-indirects':  None,
  'lbr-stats':      '- 0 10 0 ANY_DSB_MISS',
  'lbr-stats-tk':   '- 0 20 1',
  'metrics':        "+Load_Miss_Real_Latency,+L2MPKI,+ILP,+IpTB,+IpMispredict", # +UPI once ICL mux fixed, +ORO with TMA 4.5
  'msr':            0,
  'msrs':           pmu.cpu_msrs(),
  'nodes':          "+CoreIPC,+Instructions,+CORE_CLKS,+Time,-CPU_Utilization",
  'numactl':        1,
  'objdump':        'binutils-gdb/binutils/objdump' if os.path.isfile('./binutils-gdb/binutils/objdump') else 'objdump',
  'package-mgr':    C.os_installer(),
  'packages':       ('cpuid', 'dmidecode', 'msr', 'numactl'),
  'perf-lbr':       '-j any,save_type -e %s -c 700001' % pmu.lbr_event(),
  'perf-pebs':      '-b -e %s/event=0xc6,umask=0x1,frontend=0x1,name=FRONTEND_RETIRED.ANY_DSB_MISS/uppp -c 1000003' % pmu.pmu(),
  'perf-record':    '', # '-e BR_INST_RETIRED.NEAR_CALL:pp ',
  'perf-scr':       0,
  'perf-stat':      '', # '--topdown' if pmu.perfmetrics() else '',
  'perf-stat-def':  'cpu-clock,context-switches,cpu-migrations,page-faults,instructions,cycles,ref-cycles,branches,branch-misses', # ,cycles:G
  'perf-stat-ipc':  '-- perf stat -e instructions,cycles',
  'pin':            'taskset 0x4',
  'pmu':            pmu.name(),
  'python':         sys.executable,
  'repeat':         3,
  'reprocess':      2,
  'sample':         2,
  'super':          0,
  'tee':            1,
  'tma-fx':         '+IPC,+Instructions,+Time,+SLOTS,+CLKS',
  'tma-bot-fe':     ',+Mispredictions,+Big_Code,+Instruction_Fetch_BW,+Branching_Overhead,+DSB_Misses',
  'tma-bot-rest':   ',+Memory_Bandwidth,+Memory_Latency,+Memory_Data_TLBs,+Core_Bound_Likely',
  'toplev':         TOPLEV_DEF,
  'levels':         2,
  'xed':            1,
}
args = argparse.Namespace()

def exe(x, msg=None, redir_out='2>&1', verbose=False, run=True, log=True, timeit=False, background=False, export=None):
  X = x.split()
  if redir_out: redir_out=' %s' % redir_out
  if not do['tee'] and redir_out: x = x.split('|')[0]
  x = x.replace('| ./', '| %s/' % C.dirname())
  if x.startswith('./'): x.replace('./', '%s/' % C.dirname(), 1)
  if 'tee >(' in x: x = '%s bash -c "%s"' % (export if export else '', x.replace('"', '\\"'))
  x = x.replace('  ', ' ').strip()
  if timeit: x = 'time -f "\\t%%E time-real:%s" %s 2>&1' % ('-'.join(X[:2]), x)
  if len(vars(args)):
    run = not args.print_only
    if 'perf stat' in x or 'perf record' in x or 'toplev.py' in x:
      if args.mode == 'process':
        x, run = '# ' + x, False
        if not 'perf record ' in x: msg = None
    elif args.mode == 'profile':
        x, run = '# ' + x, False
    if background: x = x + ' &'
    do['cmds_file'].write(x + '\n')
    do['cmds_file'].flush()
    verbose = args.verbose > 0
  return C.exe_cmd(x, msg, redir_out, verbose, run, log, background)
def exe1(x, m=None, log=True):
  if args.stdout and '| tee' in x: x, log = x.split('| tee')[0], False
  return exe(x, m, redir_out=None, log=log)
def exe_to_null(x): return exe1(x + ' > /dev/null')
def exe_v0(x='true', msg=None): return C.exe_cmd(x, msg) # don't append to cmds_file
def prn_line(f): exe_v0('echo >> %s' % f)

def print_cmd(x, show=True):
  if show: C.printc(x)
  if len(vars(args))>0: do['cmds_file'].write('# ' + x + '\n')

def exe_1line(x, f=None): return "-1" if args.mode == 'profile' or args.print_only else C.exe_one_line(x, f)

def warn_file(x):
  if not args.mode == 'profile' and not args.print_only and not os.path.isfile(x): C.warn('file does not exist: %s' % x)

def rp(x): return os.path.join(C.dirname(), x)

def uniq_name():
  return C.command_basename(args.app_name, iterations=(args.app_iterations if args.gen_args else None))

def tools_install(installer='sudo %s install '%do['package-mgr'], packages=[]):
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
  for x in packages:
    exe(installer + x, 'installing ' + x.split(' ')[0])
  if do['xed']:
    if do['xed'] < 2 and os.path.isfile('/usr/local/bin/xed'): exe_v0(msg='xed is already installed')
    else: exe('./build-xed.sh', 'installing xed')
    exe('%s install numpy' % ('pip3' if python_version().startswith('3') else 'pip'), 'installing numpy')
  if do['msr']: exe('sudo modprobe msr', 'enabling MSRs')

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
  def read_msr(m): return C.exe_one_line('sudo %s/msr.py %s'%(args.pmu_tools, m))
  C.printc(do['pmu']) #OS
  if args.mode == 'process': return
  exe('uname -a > ' + out, 'logging setup')
  exe("cat /etc/os-release | egrep -v 'URL|ID_LIKE|CODENAME' >> " + out)
  for f in ('/sys/kernel/mm/transparent_hugepage/enabled', '/proc/sys/vm/nr_hugepages', '/proc/sys/vm/nr_overcommit_hugepages'):
    prn_sysfile(f, out)
  exe("env > setup-env.log")
  new_line()          #CPU
  exe("lscpu | tee setup-lscpu.log | egrep 'family|Model|Step|(Socket|Core|Thread)\(' >> " + out)
  if do['msr']:
    for m in do['msrs']: exe('echo "MSR %5s:\t%16s" >> '%(m, read_msr(m)) + out)
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
  new_line()          #Memory
  if do['numactl']: exe('numactl -H >> ' + out)
  new_line()          #Devices, etc
  exe("lsmod | tee setup-lsmod.log | egrep 'Module|kvm' >> " + out)
  exe("ulimit -a > setup-ulimit.log")
  if do['dmidecode']: exe('sudo dmidecode > setup-memory.log')

def get_perf_toplev():
  perf, toplev = args.perf, ''
  if perf != 'perf':
    C.check_executable(perf)
    toplev = 'PERF=%s ' % perf
  C.check_executable(args.pmu_tools.split()[-1] + '/toplev.py')
  toplev += (args.pmu_tools + '/toplev.py')
  if do['core']:
    ##if pmu.perfmetrics(): toplev += ' --pinned'
    if pmu.hybrid():      toplev += ' --cputype=core'
    if pmu.sapphire():    toplev += ' --force-cpu=adl'
  return (perf, toplev)

def profile(log=False, out='run'):
  out = uniq_name()
  perf, toplev = get_perf_toplev()
  def en(n): return args.profile_mask & 2**n
  def a_events():
    def power(rapl=['pkg', 'cores', 'ram'], px='/,power/energy-'): return px[(px.find(',')+1):] + px.join(rapl) + ('/' if '/' in px else '')
    return power() if args.power and not pmu.v5p() else ''
  def perf_stat(flags, events='',
    grep = "| egrep 'seconds [st]|CPUs|GHz|insn|topdown|Work|System|all branches' | uniq"):
    def append(x, y): return x if y == '' else ',' + x
    perf_args = [flags, '--log-fd=1', do['perf-stat'] ]
    if args.metrics: perf_args += ['--metric-no-group', '-M', args.metrics] # 1st is workaround bug 4804e0111662 in perf-stat -r2 -M
    perf_args = ' '.join(perf_args)
    if pmu.perfmetrics() and do['core']:
      prefix = ',topdown-'
      events += prefix.join([append('{slots', events),'retiring','bad-spec','fe-bound','be-bound'])
      if pmu.goldencove():
        events += prefix.join(['', 'heavy-ops','br-mispredict','fetch-lat','mem-bound}'])
        perf_args += ' --td-level=2'
      else: events += '}'
      if pmu.hybrid(): events = events.replace(prefix, '/,cpu_core/topdown-').replace('}', '/}').replace('{slots/', '{slots')
      events += append(pmu.basic_events(), events)
    if args.events: events += append(pmu.perf_format(args.events), events)
    if args.events or args.metrics: grep = '' #keep output unfiltered with user-defined events
    if events != '': perf_args += ' -e "%s,%s"'%(do['perf-stat-def'], events)
    log = '%s.perf_stat%s.log' % (out, flags.strip())
    return '%s stat %s -- %s | tee %s %s' % (perf, perf_args, r, log, grep), log
  def perf_script(x, msg=None, export=''):
    if do['perf-scr']:
      samples = 1e4 * do['perf-scr']
      if perf_script.first: C.info('processing first %d samples only' % samples)
      export += ' LBR_STOP=%d' % samples
      x = x.replace('GREP_INST', 'head -%d | GREP_INST' % (300*samples))
    instline = '^\s+[0-9a-f]+\s'
    if msg and 'counting takens' in msg: instline += '.*#'
    x = x.replace('GREP_INST', "grep -E '%s'" % instline)
    perf_script.first = False
    return exe(' '.join((perf, 'script', x)), msg, redir_out=None, timeit=(args.verbose > 1), export=export)
  perf_script.first = True
  perf_stat_log = None
  def record_name(flags):
    return '%s%s'%(out, C.chop(flags, (' :/,=', 'cpu_core', 'cpu')))
  def get_metric(m, default=-1):
    if perf_stat_log and os.path.isfile(perf_stat_log):
      for l in C.file2lines(perf_stat_log):
        if m in l: return float(l.strip().split()[4])
    return default
  def record_calibrate(x):
    factor = int(math.log(get_metric('CPUs', 1), 10))
    if factor:
      do[x] = do[x].replace('0000', '0' * (4 + factor))
      C.info('\tcalibrated: %s' % do[x])
    return record_name(do[x])
  perf_report = ' '.join((perf, 'report', '--objdump %s' % do['objdump'] if do['objdump'] != 'objdump' else ''))
  sort2u = 'sort | uniq -c | sort -n'
  sort2up = sort2u + ' | ./ptage'
  r = do['run']
  if en(0) or log: log_setup()
  
  if args.profile_mask & ~0x1: C.info('App: %s %s' % (r, args.app_iterations if args.gen_args else ''))
  if en(1):
    x = perf_stat(flags='-r%d' % do['repeat'])
    exe1(x[0], 'per-app counting %d runs' % do['repeat'])
    perf_stat_log = x[1]
  
  if en(2): exe1(perf_stat('-a', a_events(), grep='| egrep "seconds|insn|topdown|pkg"')[0], 'system-wide counting')
  
  if en(3) and do['sample']:
    base = out+'.perf'
    if do['perf-record'] and len(do['perf-record']):
      do['perf-record'] += ' '
      base += C.chop(do['perf-record'], ' :/,=')
    data = '%s.perf.data'%record_name(do['perf-record'])
    exe(perf + ' record -c 1000003 -g -o %s '%data+do['perf-record']+r, 'sampling %sw/ stacks'%do['perf-record'])
    exe(perf_report + " --header-only -i %s | grep duration" % data)
    print_cmd("Try '%s -i %s' to browse time-consuming sources" % (perf_report, data))
    #TODO:speed: parallelize next 3 exe() invocations & resume once all are done
    exe(perf_report + " --stdio -F sample,overhead,comm,dso,sym -n --no-call-graph -i %s " \
      " | tee %s-funcs.log | grep -A7 Overhead | egrep -v '^# \.|^\s+$|^$' | head | sed 's/[ \\t]*$//'" %
      (data, base), '@report functions')
    exe(perf_report + " --stdio --hierarchy --header -i %s | grep -v ' 0\.0.%%' | tee "%data+
      base+"-modules.log | grep -A22 Overhead", '@report modules')
    exe(perf + " annotate --stdio -n -l -i %s | c++filt | tee %s-code.log " \
      "| egrep -v -E '^(\-|\s+([A-Za-z:]|[0-9] :))' > %s-code_nz.log" %
      (data, base, base), '@annotate code', redir_out='2>/dev/null')
    exe("egrep -w -5 '%s :' %s-code.log" % (exe_1line("sort -n %s-code.log | tail -1" % base, 0), base), '@hottest block')
    if do['xed']: perf_script("-i %s -F insn --xed | %s " \
      "| tee %s-hot-insts.log | tail"%(data, sort2up, base), '@time-consuming instructions')
  
  toplev += ' --no-desc'
  grep_bk= "egrep '<==|MUX|Info.Bott' | sort"
  grep_NZ= "egrep -iv '^((FE|BE|BAD|RET).*[ \-][10]\.. |Info.* 0\.0[01]? |RUN|Add|warning:)|not (found|referenced|supported)|##placeholder##' "
  grep_nz= grep_NZ
  if args.verbose < 2: grep_nz = grep_nz.replace('##placeholder##', ' < [\[\+]|<$')
  def toplev_V(v, tag='', nodes=do['nodes'], tlargs=args.toplev_args):
    o = '%s.toplev%s.log'%(out, v.split()[0]+tag)
    return "%s %s --nodes '%s' -V %s %s -- %s"%(toplev, v, nodes,
              o.replace('.log', '-perf.csv'), tlargs, r), o
  
  # +Info metrics that would not use more counters
  cmd, log = toplev_V('-vl6', nodes=do['tma-fx'] + (do['tma-bot-fe']+do['tma-bot-rest']))
  if en(4): exe(cmd + ' | tee %s | %s' % (log, grep_bk), 'topdown full tree + All Bottlenecks')
  
  cmd, log = toplev_V('-vl%d' % do['levels'], tlargs='%s -r%d' % (args.toplev_args, do['repeat']))
  if en(5): exe(cmd + ' | tee %s | %s' % (log, grep_nz),
              'topdown primary, %d-levels %d runs' % (do['levels'], do['repeat']))
  
  if en(6):
    cmd, log = toplev_V('--drilldown --show-sample -l1', nodes='+IPC,+Heavy_Operations,+Time',
      tlargs='' if args.toplev_args == TOPLEV_DEF else args.toplev_args)
    exe(cmd + ' | tee %s | egrep -v "^(Run toplev|Add|Using|Sampling|perf record)" '%log, 'topdown auto-drilldown')
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
  
  data, comm = None, None
  def perf_record(tag, comm, msg=''):
    assert '-b' in do['perf-%s'%tag] or '-j any' in do['perf-%s'%tag] or do['forgive'], 'No unfiltered LBRs! tag=%s'%tag
    perf_data = '%s.perf.data' % record_calibrate('perf-%s' % tag)
    exe(perf + ' record %s -o %s %s -- %s' % (do['perf-%s'%tag], perf_data, do['perf-stat-ipc'], r), 'sampling-%s %s' % (tag.upper(), msg))
    warn_file(perf_data)
    print_cmd("Try '%s -i %s --branch-history --samples 9' to browse streams"%(perf_report, perf_data))
    if not comm:
      # might be doable to optimize out this 'perf script' with 'perf buildid-list' e.g.
      comm = exe_1line(perf + " script -i %s -F comm | %s | tail -1" % (perf_data, sort2u), 1)
    return perf_data, comm
  
  if en(8) and do['sample'] > 1:
    assert pmu.lbr_event()[:-1] in do['perf-lbr'] or do['forgive'], 'Incorrect event for LBR in: ' + do['perf-lbr']
    data, comm = perf_record('lbr', comm)
    info = '%s.info.log' % data
    clean = "sed 's/#.*//;s/^\s*//;s/\s*$//;s/\\t\\t*/\\t/g'"
    def log_count(x, l): return "printf 'Count of unique %s: ' >> %s && wc -l < %s >> %s" % (x, info, l, info)
    def log_br_count(x, s): return log_count("%s branches" % x, "%s.%s.log" % (data, s))
    def tail(f=''): return "tail %s | grep -v total" % f
    if not os.path.isfile(info) or do['reprocess'] > 1:
      exe(perf +" report -i %s | grep -A13 'Branch Statistics:' | tee %s | egrep -v ':\s+0\.0%%|CROSS'" % (data, info), "@stats")
      if perf_stat_log and os.path.isfile(perf_stat_log): exe("egrep '  branches|instructions' %s >> %s" % (perf_stat_log, info))
      sort2uf = "%s | egrep -v '\s+[1-9]\s+' | ./ptage" % sort2u
      perf_script("-i %s -F ip -c %s | %s | tee %s.samples.log | %s" %
        (data, comm, sort2uf, data, log_br_count('sampled taken', 'samples').replace('Count', '\\nCount')))
      if do['xed']:
        perf_script("-i %s -F +brstackinsn --xed -c %s | GREP_INST"
          "| tee >(grep MISPRED | %s | %s > %s.mispreds.log) | %s"
          "| tee >(%s > %s.takens.log) | tee >(grep '%%' | %s > %s.indirects.log) "
          "| grep call | %s > %s.calls.log" %
          (data, comm, clean, sort2uf, data, clean, sort2uf, data, sort2uf, data, sort2uf, data), '@processing taken branches')
        for x in ('taken', 'call', 'indirect'): exe(log_br_count(x, "%ss" % x))
        exe(log_br_count('mispredicted taken', 'mispreds'))
    if do['xed']:
      ips = '%s.ips.log'%data
      hits = '%s.hitcounts.log'%data
      loops = '%s.loops.log' % data
      lbr_hdr = '# LBR-based Statistics:'
      exe_v0('printf "\n%s\n#\n">> %s' % (lbr_hdr, info))
      if not os.path.isfile(hits) or do['reprocess']:
        lbr_env = "LBR_LOOPS_LOG=%s PTOOLS_CYCLES=%s" % (loops, exe_1line("egrep '(\s\s|e/)cycles' %s | tail -1" % C.log_stdout, 0).replace(',', ''))
        if do['lbr-indirects']: lbr_env += " LBR_INDIRECTS=%s" % do['lbr-indirects']
        perf_script("-i %s -F +brstackinsn --xed -c %s "
          "| tee >(%s %s %s >> %s) | GREP_INST | %s"
          "| tee >(sort|uniq -c|sort -k2 | tee %s | cut -f-2 | sort -nu | ./ptage > %s) | cut -f2- "
          "| tee >(cut -d' ' -f1 | %s > %s.perf-imix-no.log) | %s | tee %s.perf-imix.log | %s" %
          (data, comm, lbr_env, rp('lbr_stats'), do['lbr-stats-tk'], info, clean, hits, ips,
          sort2up, out, sort2up, out, tail()), "@instruction-mix for '%s'" % comm)
        exe("%s && %s" % (tail('%s.perf-imix-no.log' % out), log_count('instructions', hits)), "@i-mix no operands for '%s'" % comm)
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
        perf_script("-i %s -F +brstackinsn --xed -c %s %s && %s" % (data, comm, cmd, C.grep('FL-cycles...[1-9][0-9]?', info, color=1)),
          "@detailed stats for hot loops", export='PTOOLS_HITS=%s' % (hits,))
      else: warn_file(loops)
  
  if en(9) and do['sample'] > 2:
    data, comm = perf_record('pebs', comm, C.flag_value(do['perf-pebs'], '-e'))
    exe(perf + " report -i %s --stdio -F overhead,comm,dso | tee %s.modules.log | grep -A12 Overhead" %
      (data, data), "@ top-10 modules")
    perf_script("-i %s -F ip | %s | tee %s.ips.log | tail -11"%(data, sort2up, data), "@ top-10 IPs")
    is_dsb = 0
    if pmu.dsb_msb() and 'DSB_MISS' in do['perf-pebs']:
      if pmu.cpu('smt-on') and do['forgive'] < 2: C.warn('Disable SMT for DSB robust analysis')
      else:
        is_dsb = 1
        perf_script("-i %s -F ip | ./addrbits %d 6 | %s | tee %s.dsb-sets.log | tail -11" %
                    (data, pmu.dsb_msb(), sort2up, data), "@ DSB-miss sets")
    top = 0
    if not is_dsb: pass
    elif top == 1:
      top_ip = exe_1line("tail -2 %s.ips.log | head -1" % data, 2)
      perf_script("-i %s -F +brstackinsn --xed "
        "| tee >(%s %s | tee -a %s.ips.log) " # asserts in skip_sample() only if piped!!
        "| ./lbr_stats %s | tee -a %s.ips.log"%(data, rp('lbr_stats'), top_ip, data,
            do['lbr-stats'], data), "@ stats on PEBS event")
    else:
      perf_script("-i %s -F +brstackinsn --xed "
        "| ./lbr_stats %s | tee -a %s.ips.log"%(data, do['lbr-stats'], data), "@ stats on PEBS event")
    if top > 1:
      while top > 0:
        top_ip = exe_1line("egrep '^[0-9]' %s.ips.log | tail -%d | head -1" % (data, top+1), 2)
        perf_script("-i %s -F +brstackinsn --xed "
          "| ./lbr_stats %s | tee -a %s.ips.log"%(data, top_ip, data), "@ stats on PEBS ip=%s"%top_ip)
        top -= 1
  
  if en(7):
    cmd, log = toplev_V('-mvl6 --no-multiplex', '-nomux', ','.join((do['nodes'], do['extra-metrics'])))
    exe(cmd + " | tee %s | %s"%(log, grep_nz)
      #'| grep ' + ('RUN ' if args.verbose > 1 else 'Using ') + out +# toplev misses stdout.flush() as of now :(
      , 'topdown full no multiplexing')
  
  if en(16):
    assert do['msr']
    perf_data = '%s.perf.data' % record_name('-e msr')
    exe('sudo %s record -e msr:* -o %s -- %s' % (perf, perf_data, r), 'tracing MSRs')
    x = '-i %s | cut -d: -f3-4 | cut -d, -f1 | sort | uniq -c' % perf_data
    exe(' '.join(('sudo', perf, 'script', x)), msg=None, redir_out=None, timeit=(args.verbose > 1))

def do_logs(cmd, ext=[], tag=''):
  log_files = ['', 'csv', 'log', 'txt'] + ext
  if cmd == 'tar' and len(tag): res = '-'.join((tag, 'results.tar.gz'))
  s = (uniq_name() if args.app_name else '') + '*'
  if cmd == 'tar': exe('tar -czvf %s run.sh '%res + (' %s.'%s).join(log_files) + ' .%s.cmd'%s)
  if cmd == 'clean': exe('rm -rf ' + ' *.'.join(log_files + ['pyc']) + ' *perf.data* __pycache__ results.tar.gz ')

def build_kernel(dir='./kernels/'):
  def fixup(x): return x.replace('./', dir)
  app = args.app_name
  if do['gen-kernel']:
    exe(fixup('%s ./gen-kernel.py %s > ./%s.c'%(do['python'], args.gen_args, app)), 'building kernel: ' + app, redir_out=None)
    if args.verbose > 1: exe(fixup('grep instructions ./%s.c'%app))
  exe(fixup('%s -g -o ./%s ./%s.c'%(do['compiler'], app, app)), None if do['gen-kernel'] else 'compiling')
  do['run'] = fixup('%s ./%s %d'%(do['pin'], app, int(float(args.app_iterations))))
  if args.verbose > 2: exe(fixup("%s -dw ./%s | grep -A%d pause | egrep '[ 0-9a-f]+:'" % (do['objdump'], app, do['asm-dump'])), '@kernel ASM')

def parse_args():
  modes = ('profile', 'process', 'both') # keep 'both', the default, last on this list
  ap = argparse.ArgumentParser(usage='do.py command [command ..] [options]', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  ap.add_argument('command', nargs='+', help='setup-perf log profile tar, all (for these 4) '\
                  '\nsupported options: ' + C.commands_list())
  ap.add_argument('--mode', nargs='?', choices=modes, default=modes[-1], help='analysis mode options: profile-only, (post)process-only or both')
  ap.add_argument('--perf', default='perf', help='use a custom perf tool')
  ap.add_argument('--pmu-tools', default='%s ./pmu-tools'%do['python'], help='use a custom pmu-tools')
  ap.add_argument('--toplev-args', default=do['toplev'], help='arguments to pass-through to toplev')
  ap.add_argument('--install-perf', nargs='?', default=None, const='install', help='perf tool installation options: [install]|patch|build')
  ap.add_argument('--print-only', action='store_const', const=True, default=False, help='print the commands without running them')
  ap.add_argument('--stdout', action='store_const', const=True, default=False, help='keep profiling unfiltered results in stdout')
  ap.add_argument('-m', '--metrics', help='user metrics to pass to perf-stat\'s -M')
  ap.add_argument('-e', '--events', help='user events to pass to perf-stat\'s -e')
  ap.add_argument('--power', action='store_const', const=True, default=False, help='collect power metrics/events as well')
  ap.add_argument('-n', '--nodes', default=do['metrics'], help='user metrics to pass to toplev\'s --nodes')
  ap.add_argument('-a', '--app-name', default=None, help='name of user-application/kernel/command to profile')
  ap.add_argument('-s', '--sys-wide', type=int, default=0, help='profile system-wide for x seconds. disabled by default')
  ap.add_argument('-g', '--gen-args', help='args to gen-kernel.py')
  ap.add_argument('-ki', '--app-iterations', default='1e9', help='num-iterations of kernel')
  ap.add_argument('-pm', '--profile-mask', type=lambda x: int(x,16), default='317F', help='mask to control stages in the profile command')
  ap.add_argument('-v', '--verbose', type=int, default=0, help='verbose level; 0:none, 1:commands, ' \
    '2:+verbose-on metrics|build, 3:+toplev --perf|ASM on kernel build, 4:+args parsing, 5:+event-groups, .. 9:anything')
  ap.add_argument('--tune', nargs='+', help=argparse.SUPPRESS, action='append') # override global variables with python expression
  x = ap.parse_args()
  return x

def main():
  global args
  args = parse_args()
  #args sanity checks
  if (args.gen_args or 'build' in args.command) and not args.app_name:
    C.error('must specify --app-name with any of: --gen-args, build')
  assert args.sys_wide >= 0, 'negative duration provided!'
  if args.verbose > 4: args.toplev_args += ' -g'
  if args.verbose > 2: args.toplev_args += ' --perf'
  if args.app_name: do['run'] = args.app_name
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
  if args.mode == 'process':
    C.info('post-processing only (not profiling)')
    args.profile_mask &= ~0x1
    if args.profile_mask & 0x300: args.profile_mask |= 0x2
  if args.sys_wide:
    if args.mode != 'process': C.info('system-wide profiling')
    do['run'] = 'sleep %d'%args.sys_wide
    for x in ('stat', 'record', 'lbr', 'pebs', 'stat-ipc'): do['perf-'+x] += ' -a'
    args.toplev_args += ' -a'
    args.profile_mask &= ~0x4 # disable system-wide profile-step
  if do['container']:
    if args.mode != 'process': C.info('container profiling')
    for x in ('record', 'lbr', 'pebs'): do['perf-'+x] += ' --buildid-all --all-cgroup'
  do_cmd = '%s # version %.2f' % (C.argv2str(), __version__)
  C.log_stdout = '%s-out.txt' % ('run-default' if do['run'] == RUN_DEF else uniq_name())
  C.printc('\n\n%s\n%s' % (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), do_cmd), log_only=True)
  cmds_file = '.%s.cmd' % uniq_name()
  if os.path.isfile(cmds_file):
    exe_v0('mv %s %s-%d.cmd' % (cmds_file, cmds_file.replace('.cmd', ''), os.getpid()))
  do['cmds_file'] = open(cmds_file, 'w')
  do['cmds_file'].write('# %s\n' % do_cmd)
  if args.verbose > 5: C.printc(str(args))
  if args.verbose > 6: C.printc(str(do))
  
  for c in args.command:
    param = c.split(':')[1:] if ':' in c else None
    if   c == 'forgive-me':   pass
    elif c == 'setup-all':
      tools_install()
      setup_perf('set')
    elif c == 'build-perf':   exe('./do.py setup-all --install-perf build -v%d --tune %s'%(args.verbose,
                                  ' '.join([':%s:0'%x for x in (do['packages']+('xed', 'tee'))])))
    elif c == 'setup-perf':   setup_perf()
    elif c == 'find-perf':    exe(Find_perf)
    elif c == 'tools-update': tools_update()
    elif c.startswith('tools-update:'): tools_update(level=int(param[0]))
    # TODO: generalize disable/enable features that follow
    elif c == 'disable-smt':  smt()
    elif c == 'enable-smt':   smt('on')
    elif c == 'disable-atom': atom()
    elif c == 'enable-atom':  atom('online')
    elif c == 'disable-hugepages': exe('echo never | sudo tee /sys/kernel/mm/transparent_hugepage/enabled')
    elif c == 'enable-hugepages':  exe('echo always | sudo tee /sys/kernel/mm/transparent_hugepage/enabled')
    elif c == 'disable-prefetches': exe('sudo wrmsr -a 0x1a4 0xf && sudo rdmsr 0x1a4')
    elif c == 'enable-prefetches':  exe('sudo wrmsr -a 0x1a4 0 && sudo rdmsr 0x1a4')
    elif c == 'enable-fix-freq':    fix_frequency()
    elif c == 'disable-fix-freq':   fix_frequency('undo')
    elif c == 'help':         exe('%s --describe %s' % (get_perf_toplev()[1], args.metrics), redir_out=None)
    elif c == 'log':          log_setup()
    elif c == 'profile':      profile()
    elif c.startswith('get'): get(param)
    elif c == 'tar':          do_logs(c, tag='.'.join((uniq_name(), pmu.cpu_TLA())) if args.app_name else C.error('provide a value for -a'))
    elif c == 'clean':        do_logs(c)
    elif c == 'all':
      setup_perf()
      profile(True)
      do_logs('tar')
    elif c == 'build':        build_kernel()
    elif c == 'reboot':       exe('history > history-%d.txt && sudo shutdown -r now' % os.getpid(), redir_out=None)
    else:
      C.error("Unknown command: '%s' !"%c)
      return -1
  return 0

def get(param):
  assert param and len(param) == 3, '3 parameters expected: e.g. get:<what>:<logfile>:<num>'
  sub, log, num = param
  num = int(num)
  if log == '-': log = exe_1line('ls -1tr *.%s.log | tail -1' % ('info' if sub == 'x2g-indirects' else sub))
  if sub == 'indirects':        print(','.join([ '0x%s' % x.lstrip('0') for x in C.exe2list("tail -%d %s | grep -v total | sed 's/bnd jmp/bnd-jmp/'" % (num, log))[2:][::5] ]))
  elif sub == 'x2g-indirects':  exe("grep -E '^0x[0-9a-f]+:' %s | sort -n -k2 |grep -v total|uniq|tail -%d|cut -d: -f1|tr '\\n' ,|sed 's/.$/\\n/'" % (log, num))

if __name__ == "__main__":
  main()
  do['cmds_file'].close()

