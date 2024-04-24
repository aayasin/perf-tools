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
from lbr.loops import loops
from kernels import x86
__version__ = 1.01

user_imix = C.env2list('LBR_FUNC_IMIX', ['zcnt'])
types = ['lea', 'cmov'] + x86.MEM_INSTS + user_imix

# TODO:
# update detect_function() to consider TCO case

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

  def __str__(self, detailed=False):
    result = f"{{ip: 0x{self.ip}, hotness: {self.hotness}, FF-cycles%: {C.ratio(self.FF_cycles, LC.stat['total_cycles'])}, " \
      f"srcline: {self.srcline}, flows-num: {self.flows_num}"
    if not detailed: result += ", flows: {"
    else:
      ipcs = sorted(self.ipc_histo.keys())
      if ipcs:
        result += f", IPC-mode: {ipcs[-1]}, IPC-mean: {round(self.ipc_sum / self.ipc_total, 1)}, IPC-num-buckets: {len(ipcs)}"
      result += '}\n\n'
      result += C.printc(f'flows of function at 0x{self.ip}:', log_only=True)
    for i, f in enumerate(sorted(self.flows)):
      if detailed: result += '\n' + str(f)
      else:
        result += f"{', ' if i > 0 else ''}{f.flow}: {f.hotness}"
    if not detailed: result += '}}'
    else:
      if ipcs:
        result += '\n\n'
        result += C.printc(f'IPC histogram of function at 0x{self.ip}:', log_only=True)
        for ipc in ipcs:
          v = self.ipc_histo[ipc]
          result += "\n{:>5}: {:>6} {:>5}%".format(ipc, v, round(v / self.ipc_total * 100, 1))
      result += '\n'
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

  def __eq__(self, other):
    if isinstance(other, Flow):
      return self.flow == other.flow
    return NotImplemented

  def __hash__(self):
    return hash(self.flow)

  def __lt__(self, other):
    return self.hotness > other.hotness

  def __str__(self):
    result = f"flow {self.flow}: [hotness: {self.hotness}, func-ip: 0x{self.func_ip}, FF-cycles%: {C.ratio(self.FF_cycles, LC.stat['total_cycles'])}, " \
      f"size: {self.size}, imix-ID: {self.imix_ID}, back: {self.back}, inner: {self.inner},{f' inner-functions: {self.inner_funcs},' if self.inner > 0 else ''}" \
      f" outer: {self.outer},{f' outer-functions: {self.outer_funcs},' if self.outer > 0 else ''} Conds: {self.conds}, " \
      f"op-jcc-mf: {self.op_jcc_mf}, mov-op-mf: {self.mov_op_mf}, ld-op-mf: {self.ld_op_mf}, taken: {self.taken}" \
      f"{f', takens: {self.takens}' if self.taken > 0 else ''}"
    for i in types:
      result += f", {i}: {getattr(self, i)}"
    result += ']'
    return result

funcs = set()
#funcs_cands = set()
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
def process_function(lines, srcline, outer_funcs=[]):
  assert 'call' in lines[0], C.error(f'wrong function detected with no call {lines[0]}')
  if len(lines) == 1: return lines[0], []  # corner case of last line being a CALL
  lines.pop(0)
  if LC.is_label(lines[0]):
    srcline = LC.get_srcline(lines[0])
    lines.pop(0)
  ip = LC.line_ip_hex(lines[0])
  new_func = Function(ip)
  new_func.srcline = srcline
  new_flow = Flow(ip)
  inner_funcs = []
  new_flow.outer = len(outer_funcs)
  new_flow.outer_funcs = outer_funcs
  insts_cnt = {}
  for i in types: insts_cnt[i] = 0
  cycles = 0
  loop_code, loop_end = False, None

  # finalize stats, add new or update current func/flow if exists
  def add_func(back=None):
    new_flow.inner = len(inner_funcs)
    new_flow.inner_funcs = inner_funcs
    for i in types: setattr(new_flow, i, insts_cnt[i])
    new_flow.imix_ID = C.num2char(new_flow.load) + C.num2char(new_flow.store) + C.num2char(new_flow.conds) + C.num2char(new_flow.lea)
    new_flow.back = back
    if new_flow.flow.endswith('_'): new_flow.flow = new_flow.flow[:-1]
    if new_flow.flow == '': new_flow.flow = '<serial>'
    # funcs_set = funcs if back else funcs_cands
    # func = get_func(new_func, funcs_set) if new_func in funcs_set else new_func
    func = get_func(new_func, funcs) if new_func in funcs else new_func
    if new_flow in func.flows: flow = get_flow(new_flow, func)
    else:
      flow = new_flow
      func.flows_num += 1
    func.hotness += 1
    flow.hotness += 1
    func.FF_cycles += cycles
    flow.FF_cycles += cycles
    ipc = round(flow.size / cycles, 1) if cycles > 0 else None
    if ipc:
      k = str(ipc)
      if not k in func.ipc_histo: func.ipc_histo[k] = 0
      func.ipc_histo[k] += 1
      func.ipc_total += 1
      func.ipc_sum += ipc
    func.flows.add(flow)
    # funcs_set.add(func)
    funcs.add(func)

  global total_cycles
  inner_end = None
  for index, line in enumerate(lines):
    if inner_end and index <= inner_end: continue  # bypass lines of inner function
    # update srcline for next functions and ignore labels
    if LC.is_label(line):
      srcline = LC.get_srcline(line)
      continue
    new_flow.size += 1
    line_ip = LC.line_ip(line)
    hex_ip = LC.hex_ip(line_ip)
    if LC.is_taken(line):
      new_flow.taken += 1
      new_flow.takens.add(hex_ip)
      if not loop_code:
        c = LC.line_timing(line)[0]
        cycles += c
        total_cycles += c
    if 'ret' in line:  # function end
      add_func(hex_ip)
      return line, [ip] + inner_funcs  # return last processed line & inner functions
    if 'call' in line:  # inner function
      resume_line, inner_funcs = process_function(lines[index:], srcline, outer_funcs=outer_funcs + [ip])
      inner_end = lines.index(resume_line)
      continue
    if index > 1:
      if x86.is_jcc_fusion(lines[index - 1], line): new_flow.op_jcc_mf += 1
      elif index == len(lines) - 1 or not x86.is_jcc_fusion(line, lines[index + 1]):
        if x86.is_mov_op_fusion(lines[index - 1], line) or x86.is_vec_mov_op_fusion(lines[index - 1], line):
          new_flow.mov_op_mf += 1
        elif x86.is_ld_op_fusion(lines[index - 1], line) or x86.is_vec_ld_op_fusion(lines[index - 1], line):
          new_flow.ld_op_mf += 1
    t = LC.line_inst(line)
    if t and t in types: insts_cnt[t] += 1
    if line_ip in loops and not loop_code:
      new_flow.flow += '_' + hex_ip + '_'
      loop_code = True
      loop_end = loops[line_ip]['back']
    if LC.is_type(x86.COND_BR, line):  # cond branch line
      new_flow.conds += 1
      if loop_end and line_ip == loop_end and not LC.is_taken(line):
        loop_code = False
        continue
      if not loop_code:
        t = '1' if LC.is_taken(line) else '0'
        new_flow.flow += t
  # reached sample end before function ends
  add_func()
  return lines[-1], [ip] + inner_funcs  # return last processed line & inner functions

# supports functions observed in a single sample
def detect_functions(lines, srcline):
  while len(lines):
    line = lines[0]
    while not 'call' in line:
      if LC.is_label(line): srcline = LC.get_srcline(line)
      lines.pop(0)
      if not len(lines): return
      line = lines[0]
    # call found, process function and restart for next functions
    resume_line = process_function(lines, srcline)[0]
    lines = lines[lines.index(resume_line):]
    lines.pop(0)
