#!/usr/bin/env python3
# Copyright (c) 2024, Intel Corporation
# Author: Amiri Khalil
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# A module for processing functions in LBR streams
#
__author__ = 'akhalil'

import common as C
import lbr.common_lbr as LC
from lbr.loops import loops, is_loop_exit
import lbr.x86_fusion as x86_f, lbr.x86 as x86

user_imix = C.env2list('LBR_FUNC_IMIX', ['zcnt'])
types = ['lea', 'cmov'] + x86.MEM_INSTS + user_imix

# TODO:
# update detect_function() to consider TCO case

def ipc_values(histo):
  d = LC.print_hist([histo, 'IPC', None, None, None, False], print_hist=False)
  return f', IPC-mode: {d["mode"]}, IPC-mean: {d["mean"]}, IPC-num-buckets: {d["num-buckets"]}'

class Function:
  def __init__(self, ip):
    self.ip = ip
    self.hotness = 0
    self.FF_cycles = 0
    self.srcline = None
    self.flows = set()  # set of Flow
    self.flows_num = 0
    self.ipc_histo = dict()
    self.ipc_total = 0
    self.ipc_sum = 0

  def __eq__(self, other):
    if isinstance(other, Function):
      return self.ip == other.ip
    return NotImplemented

  def __hash__(self):
    return hash(self.ip)

  def __lt__(self, other):
    return self.hotness > other.hotness

  def __str__(self, detailed=False, index=None):
    ipcs = sorted(self.ipc_histo.keys())
    summ = f"{{ip: {self.ip}, hotness: {self.hotness}, FF-cycles%: {C.ratio(self.FF_cycles, LC.stat['total_cycles'])}" \
      f"{f', srcline: {self.srcline}' if self.srcline else ''}" \
      f"{ipc_values(self.ipc_histo) if ipcs else ''}" \
      f", flows-num: {self.flows_num}"
    flows = sorted(self.flows)
    if detailed:
      result = C.printc(f'flows of function at {self.ip}:', log_only=True)
      for i, f in enumerate(reversed(flows)): result += '\n' + str(f)
      if ipcs:
        result += '\n\n'
        result += C.printc(f'IPC histogram of function at {self.ip}:\n', log_only=True)
        result += LC.print_ipc_hist(self.ipc_histo, ipcs)
      result += f'\n\nFunction#{index}: {summ}}}\n\n'
    else:
      result = summ + ", %sflows: {" % ('top-10 ' if len(self.flows) > 10 else '')
      for i, f in enumerate(flows):
        if i < 10: result += f"{', ' if i > 0 else ''}{f.flow}: {f.hotness}"
      result += '}}'
    return result

class Flow:
  def __init__(self, ip, flow=''):
    self.flow = flow
    self.hotness = 0
    self.func_ip = ip
    self.FF_cycles = 0
    self.size = 0
    self.imix_ID = None
    self.back = None
    self.taken = 0
    self.takens = set()
    self.inner = self.outer = 0
    self.inner_funcs = self.outer_funcs = None
    self.conds = 0
    self.op_jcc_mf = self.mov_op_mf = self.ld_op_mf = 0
    self.ipc_histo = dict()
    self.ipc_total = 0
    self.ipc_sum = 0
    self.code = ''

  def __eq__(self, other):
    if isinstance(other, Flow):
      return self.flow == other.flow
    return NotImplemented

  def __hash__(self):
    return hash(self.flow)

  def __lt__(self, other):
    return self.hotness > other.hotness

  def __str__(self):
    ipcs = self.ipc_histo.keys()
    result = '' if self.code == '' else f'\n{self.code}\n'
    result += f"flow {self.flow}: [hotness: {self.hotness}, func-ip: {self.func_ip}, FF-cycles%: {C.ratio(self.FF_cycles, LC.stat['total_cycles'])}, " \
      f"size: {self.size}, imix-ID: {self.imix_ID}, back: {self.back}, inner: {self.inner},{f' inner-functions: {self.inner_funcs},' if self.inner > 0 else ''}" \
      f" outer: {self.outer},{f' outer-functions: {self.outer_funcs},' if self.outer > 0 else ''} Conds: {self.conds}, " \
      f"op-jcc-mf: {self.op_jcc_mf}, mov-op-mf: {self.mov_op_mf}, ld-op-mf: {self.ld_op_mf}, taken: {self.taken}" \
      f"{f', takens: {self.takens}' if self.taken > 0 else ''}" \
      f"{ipc_values(self.ipc_histo) if ipcs else ''}"
    for i in types:
      result += f", {i}: {getattr(self, i)}"
    result += ']'
    return result

funcs = set()
partial_funcs = set()
total_cycles = 0

def get_func(func, funcs_set):
  for f in funcs_set:
    if f == func: return f
  return None
def get_flow(flow, func):
  for f in func.flows:
    if f == flow: return f
  return None

# considers CALL -> RET case only with inner functions support
# returns last processed function line and inner functions IPs (for recursive calling)
def process_function(lines, outer_funcs=[]):
  assert 'call' in lines[0], C.error(f'wrong function detected with no call {lines[0]}')
  if len(lines) == 1: return lines[0], []  # corner case 1 of call only
  lines.pop(0)
  info = LC.line2info(lines[0])
  srcline = info.srcline() if LC.is_srcline(lines[0]) else None
  if info.is_label():
    if len(lines) == 1: return lines[0], [] # corner case 2 of call -> label -> sample end
    lines.pop(0)
  ip = LC.hex_ip(LC.line_ip(lines[0]))
  new_func = Function(ip)
  new_func.srcline = srcline
  new_flow = Flow(ip)
  inner_funcs = []
  new_flow.outer = len(outer_funcs)
  new_flow.outer_funcs = outer_funcs
  insts_cnt = {}
  for i in types: insts_cnt[i] = 0
  cycles = 0
  loop_ip, loop_end = None, None

  # finalize stats, add new or update current func/flow if exists
  def add_func(back=None):
    new_flow.inner = len(inner_funcs)
    new_flow.inner_funcs = inner_funcs
    for i in types: setattr(new_flow, i, insts_cnt[i])
    new_flow.imix_ID = C.num2char(new_flow.load) + C.num2char(new_flow.store) + C.num2char(new_flow.conds) + C.num2char(new_flow.lea)
    new_flow.back = back
    if new_flow.flow.endswith('_'): new_flow.flow = new_flow.flow[:-1]
    if new_flow.flow == '': new_flow.flow = '<serial>'
    funcs_set = funcs if back else partial_funcs
    func = get_func(new_func, funcs_set) if new_func in funcs_set else new_func
    if new_flow in func.flows: flow = get_flow(new_flow, func)
    else:
      flow = new_flow
      func.flows_num += 1
    func.hotness += 1
    flow.hotness += 1
    func.FF_cycles += cycles
    flow.FF_cycles += cycles
    ipc = round(flow.size / cycles, 1) if cycles > 0 else None
    def add_ipc(obj):
      if not k in obj.ipc_histo: obj.ipc_histo[k] = 0
      obj.ipc_histo[k] += 1
      obj.ipc_total += 1
      obj.ipc_sum += ipc
    if ipc:
      k = str(ipc)
      add_ipc(func)
      add_ipc(flow)
    func.flows.add(flow)
    funcs_set.add(func)

  def update_flow(c, s):
    if not new_flow.flow.endswith('_') and new_flow.flow != '': new_flow.flow += '_'
    new_flow.flow += '%s%s_' % (c, s)

  global total_cycles
  inner_end = None
  for index, line in enumerate(lines):
    if inner_end and index <= inner_end: continue  # bypass lines of inner function
    info = LC.line2info(line)
    if info.is_label(): continue
    new_flow.size += 1
    new_flow.code += line.strip() + '\n'
    line_ip = info.ip()
    hex_ip = LC.hex_ip(line_ip)
    next = LC.next_line(lines, index)
    if info.is_taken():
      new_flow.taken += 1
      new_flow.takens.add(hex_ip)
      if not loop_ip or is_loop_exit(loop_ip, loop_end, line_ip, next):
        loop_ip = None
        c = LC.line_timing(line)[0]
        cycles += c
        total_cycles += c
      if info.is_indirect() and next:  # taken indirect branch
        update_flow('I', LC.hex_ip(LC.line_ip(next)))
    if 'ret' in line:  # function end
      add_func(hex_ip)
      return line, [ip] + inner_funcs if ip not in inner_funcs else inner_funcs  # return last processed line & inner functions
    if 'call' in line:  # inner function
      resume_line, inner_funcs_add = process_function(lines[index:], outer_funcs=outer_funcs + [ip])
      inner_end = lines.index(resume_line)
      inner_funcs.extend([item for item in inner_funcs_add if item not in inner_funcs])
      continue
    if index > 1:
      prev = LC.prev_line(lines, index)
      if prev:
        if x86_f.is_jcc_fusion(prev, line): new_flow.op_jcc_mf += 1
        elif index == len(lines) - 1 or not x86_f.is_jcc_fusion(line, next):
          if x86_f.is_mov_op_fusion(prev, line) or x86_f.is_vec_mov_op_fusion(prev, line):
            new_flow.mov_op_mf += 1
          elif x86_f.is_ld_op_fusion(prev, line) or x86_f.is_vec_ld_op_fusion(prev, line):
            new_flow.ld_op_mf += 1
    t = info.inst_type()
    if t and t in types: insts_cnt[t] += 1
    if line_ip in loops and not loop_ip:  # inner loop
      loop_ip, loop_end = line_ip, loops[line_ip]['back']
    if info.is_cond_br():  # cond branch line
      new_flow.conds += 1
      if loop_ip and line_ip == loop_end and not info.is_taken():  # inner loop end
        update_flow('L', LC.hex_ip(loop_ip))
        loop_ip = None
        continue
      if not loop_ip:
        t = '1' if info.is_taken() else '0'
        new_flow.flow += t
  # reached sample end before function ends
  add_func()
  return lines[-1], [ip] + inner_funcs if ip not in inner_funcs else inner_funcs  # return last processed line & inner functions

# supports functions observed in a single sample
def detect_functions(lines):
  while len(lines):
    line = lines[0]
    while not 'call' in line:
      lines.pop(0)
      if not len(lines): return
      line = lines[0]
    # call found, process function and restart for next functions
    resume_line = process_function(lines)[0]
    lines = lines[lines.index(resume_line):]
    lines.pop(0)
