#!/usr/bin/env python
# Copyright (c) 2024, Intel Corporation
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

import common as C
import lbr.common_lbr as LC
import pmu
from lbr.x86 import rem_xed_sfx
import os
import re
import argparse
import sys

__author__ = 'akhalil'
# edited: Oct 2024
INTRO_MESSAGE = '\
*******llvm_mca.py********\n\
-Amiri Khalil        amiri.khalil@intel.com\n\
-Andi Kleen        andi.kleen@intel.com\n\
\n\
>Run llvm-mca within ./do.py profiling on hot loops or individually on input files.\n' \
  'When running with ./do.py, the script generates llvm_mca.log which includes all ' \
  'llvm-mca output.\n'


LLVM = C.Globals['llvm-mca']

# handle incompatibilities between xed and LLVM MCinst
repl = (("movsxd", "movslq"),
        ("movsxb", "movsbl"),
        ("movzxb", "movzbl"),
        ("movslql", "movslq"),
        ("movsxw", "movsx"),
        ("movzxw", "movzbl"),
        ("nopw  %ax, (%rax,%rax,1)", "nopw (%rax,%rax)"),
        ("nopl  %eax, (%rax)", "nopl (%rax)"),
        ("nopl  %eax, (%rax,%rax,1)", "nopl (%rax,%rax,1)"),
        ('divsdq', 'divsd'),
        ('movdl', 'movd'),
        ('movhpsq', 'movhps'),
        ('movlpsq', 'movlps'),
        ('movqq', 'movq'),
        ('movsbb', 'movsb'),
        ('movsdq', 'movsd'),
        ('stosqq', 'stosq'),
        ('ucomisdq', 'ucomisd'),
        ('movsqq', 'movsq')
)

# map AVX insts to MCInst by removing last letter
avxrepl = ('vmovqq', 'vmovdl')

rerepl = ((r"(jmpq?|callq?)\s+(\(|%)", r"\1\t*\2"),)

regs = (('w', ('%ax', '%bx', '%cx', '%dx', '%di', '%si', '%bp', '%sp')),
        ('b', ('%ah', '%al', '%bh', '%bl', '%ch', '%cl', '%dh', '%dl')),
        ('b', ('%sil', '%dil', '%bpl', '%spl')))


def run_llvm(hitcounts, llvm_log, args, loop, loop_ipc):
  if os.path.getsize(hitcounts) == 0: C.error("%s file is empty" % hitcounts)
  llvm_input_name = ".llvm_in_%s.txt" % loop_ipc
  C.exe_cmd(C.grep('0%x' % int(loop_ipc, 16), hitcounts, '-A%d' % (loop['size'] - 1)),
            redir_out=' | sed -e "s/^[ \t]*//" | cut -d " " -f 2- > %s' % llvm_input_name)
  lbrmca(llvm_input_name, args=args, llvm_log=llvm_log, loop_ipc=loop_ipc)


def get_ipc(hitcounts, llvm_log, args, loop, loop_ipc):
  output = C.exe_one_line(C.grep(loop_ipc, llvm_log, '-c'))
  if int(output) == 0:
    run_llvm(hitcounts, llvm_log, args, loop, loop_ipc)
  result = None
  # TODO: think how to change the fixed number of lines (16) for future usages
  result_str = C.exe_one_line('%s | %s' % (C.grep(loop_ipc, llvm_log, '-A16'), C.grep('IPC')))
  try:
    result = float(result_str.split()[1])
  except IndexError:
    C.error("bogus IPC line:\n%s\nat %s for loop %s" % (result_str, llvm_log, loop_ipc))
  return result


def regsuf(r):
  if r.startswith("%r"):
    if r.endswith("d"):
      return "l"
    if r.endswith("w"):
      return "w"
    if r.endswith("b"):
      return "b"
    return "q"
  if r.startswith("%e"):
    return "l"
  for suf, l in regs:
    if r in l:
      return suf
  return ""


def lbrmca(input_file_path, args='', llvm_log=None, loop_ipc=None):
  if not os.path.exists(LLVM): C.error('llvm-mca is not installed! Please run ./build-llvm.sh to install it.')
  reg = ""
  nasm = 0
  with open(input_file_path, 'r') as input_file:
    for l in input_file.readlines():
      if not LC.is_empty(l):
        s = ' '.join(rem_xed_sfx(l).split()[1:]) + '\n'
        for o, r in repl:
          s = s.replace(o, r)
        for o in avxrepl:
          s = s.replace(o, o[:-1])
        for o, r in rerepl:
          s = re.sub(o, r, s)
        n = s.split()
        if len(n) > 2 and n[0] == "movsx":
          s = s.replace("movsx", "movs" + regsuf(n[1]) + regsuf(n[2]))
        reg += s
        nasm += 1
  if nasm > 0:
    if "%mmx" in reg:
      C.error("LLVM-MCA does not support MMX")
    else:
      if args == '':
        args = '--iterations=1000 --dispatch=%s' % pmu.cpu_pipeline_width()
      reg = reg.replace("%", "%%")
      cmd = "printf '%s' | %s %s" % (reg, LLVM, args)
      if llvm_log and loop_ipc:
        C.printc('llvm-mca output of loop at %s:\n' % loop_ipc,
                   C.color.BOLD + C.color.UNDERLINE, log_only=True, outfile=llvm_log)
        cmd += " >> %s && printf '\n\n' >> %s" % (llvm_log, llvm_log)
        cmd_print = " >> %s\n" % cmd.replace('\n', '\\n')
        C.printc(cmd_print, C.color.GREY, log_only=True, outfile=llvm_log)
      C.exe_cmd(cmd)


def main(argv):
  args = get_args(argv)
  for file in args.input_files:
    lbrmca(file, args.args)


def get_args(args_in):
  parser = argparse.ArgumentParser(description=INTRO_MESSAGE,
                                   formatter_class=argparse.RawDescriptionHelpFormatter,
                                   usage=argparse.SUPPRESS)
  parser.add_argument('input_files', default=None, nargs='+',
                      help="run llvm-mca on these input files.")
  parser.add_argument('--args', default='',
                      help="run llvm-mca on input files with <args>")
  return parser.parse_args(args=args_in)


if __name__ == "__main__":
  main(sys.argv[1:])
