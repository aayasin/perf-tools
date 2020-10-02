#!/usr/bin/env python2
# Misc utilities for CPU performance analysis on Linux
# Author: Ahmad Yasin
# edited: October 2020
# TODO list:
#   check sudo permissions
#   auto-produce options for command help
__author__ = 'ayasin'

import argparse, sys
from os import system
#from subprocess import check_output

def exe(x): return system(x)

def parse_args():
    def get_commands():
        #return check_output("grep elif %s | cut -d\\' -f2"%sys.argv[0], shell=True)
        exe("grep elif %s | grep -v grep | cut -d' ' -f8"%sys.argv[0])
    ap = argparse.ArgumentParser()
    ap.add_argument('command', help='support options: setup-perf log-setup profile, all (for these 3)'
        + '\n\t\t\t[disable|enable]-smt git-update')
    ap.add_argument('--perf', default='perf', help='use a custom perf tool')
    x = ap.parse_args()
    return x

def setup_perf():
  cmds=["echo 0     | sudo tee /proc/sys/kernel/nmi_watchdog",
        "echo 0     | sudo tee /proc/sys/kernel/soft_watchdog",
        "echo 0     | sudo tee /proc/sys/kernel/kptr_restrict",
        "echo -1    | sudo tee /proc/sys/kernel/perf_event_paranoid",
        "echo 100   | sudo tee /sys/devices/cpu/perf_event_mux_interval_ms",
        "echo 60000 | sudo tee /proc/sys/kernel/perf_event_mlock_kb"]
  for c in cmds: exe(c)

def smt(x='off'):
    exe('echo %s | sudo tee /sys/devices/system/cpu/smt/control'%x)

def profile(perf):
    exe(perf + ' stat -- ./run.sh > run-perf_stat.log 2>&1')
    exe(perf + ' record -g ./run.sh')
    exe(perf + " report --stdio --hierarchy 2>&1 | grep -v '0\.0.%' > run-perf-modules.txt ")
    exe("PERF=%s ./pmu-tools/toplev.py --no-desc --no-perf -vl6 -- ./run.sh > run-toplev-vl6.log 2>&1"%perf)

def log_setup():
    exe('lscpu > setup-lscpu.log')

def main():
    args = parse_args()
    c = args.command
    if   c == 'forgive-me': pass
    elif c == 'setup-perf':   setup_perf()
    elif c == 'git-update':
        exe('git submodule update --remote')
        exe("./pmu-tools/event_download.py") # No sudo
    elif c == 'disable-smt':  smt()
    elif c == 'enable-smt':   smt('on')
    elif c == 'log-setup':    log_setup()
    elif c == 'profile':      profile(args.perf)
    elif c == 'all':
        setup_perf()
        log_setup()
        profile(args.perf)
    else: sys.exit("Unknown command: '%s' !"%c)

if __name__ == "__main__":
    main()

