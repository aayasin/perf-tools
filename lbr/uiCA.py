#!/usr/bin/env python
# Copyright (c) 2024, Intel Corporation
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

import common as C
from lbr.x86 import JUMP, COND_BR
import os, re, pmu

__author__ = 'akhalil'
INTRO_MESSAGE = '\
*******uiCA.py********\n\
-Amiri Khalil        amiri.khalil@intel.com\n\
\n\
>Run uiCA within ./do.py profiling on hot loops.\n' \
  'When running with ./do.py, the script generates uiCA.log which includes all ' \
  'uiCA output.\n'

UICA = C.Globals['uica']
FIX_OUT = "| sed -E 's/8;;|https:\/\/[^ ]*\.html//g' | col -b "

def run_uica(hitcounts, uica_log, loop, loop_ipc):
  if not os.path.exists(UICA): C.error('uiCA is not installed! Please run ./build-uica.sh to install it.')
  if os.path.getsize(hitcounts) == 0: C.error("%s file is empty" % hitcounts)
  CPU = pmu.cpu('CPU')
  if CPU == 'ICX': CPU = 'ICL'
  if not CPU in C.exe_output('%s -h' % UICA):
    C.error('uiCA tool does not support current CPU')
  def patch(l):
    line = l
    if '0x' in l and (re.search(JUMP, l) or re.search(COND_BR, l)):
      line = l.replace(l.split()[-1], 'end')
    if 'movupsx' in line: line = line.replace('movupsx', 'movups')
    return line
  input_list = C.exe_output(C.grep('0%x' % int(loop_ipc, 16), hitcounts, '-A%d' % (loop['size'] - 1)) +
                       ' | awk \'{for (i=3; i<=NF; i++) printf "%s ", $i; print ""}\' | sed \'s/ ilen:.*$//\'').split(';')
  input = 'l: '
  for l in input_list[:-1]:
    line = patch(l)
    input += line + ';'
  input += input_list[-1].replace(input_list[-1].split()[-1], 'l')
  input += ';end:'
  in_file = ".uica_in_%s.asm" % loop_ipc
  o_file = in_file.replace('.asm', '.o')
  cmd = "echo '%s' > %s && as %s -o %s && %s %s -arch %s %s" % (input, in_file, in_file, o_file, UICA, o_file, CPU, FIX_OUT)
  if uica_log and loop_ipc:
    C.printc('uiCA output of loop at %s:\n' % loop_ipc,
             C.color.BOLD + C.color.UNDERLINE, log_only=True, outfile=uica_log)
    cmd += ">> %s && printf '\n\n' >> %s" % (uica_log, uica_log)
    cmd_print = ">> %s\n" % cmd.replace('\n', '\\n')
    C.printc(cmd_print, C.color.GREY, log_only=True, outfile=uica_log)
  C.exe_cmd(cmd)

# no support for non-contiguous loops and loops with inner loop
def get_ipc(hitcounts, uica_log, loop, loop_ipc):
  output = C.exe_one_line(C.grep(loop_ipc, uica_log, '-c'))
  if int(output) == 0:
    run_uica(hitcounts, uica_log, loop, loop_ipc)
  result = None
  # TODO: think how to change the fixed number of lines (5) for future usages
  result_str = C.exe_one_line('%s | %s' % (C.grep(loop_ipc, uica_log, '-A5'), C.grep('Throughput')))
  try:
    result = float(result_str.split()[-1])
  except IndexError:
    C.error("bogus Throughput line:\n%s\nat %s for loop %s" % (result_str, uica_log, loop_ipc))
  return round(float(loop['size']) / result, 2)
