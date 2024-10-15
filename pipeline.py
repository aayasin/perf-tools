# Copyright (c) 2020-2024, Intel Corporation
# Author: Ahmad Yasin
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# Processes a custom perf_stat output file into a visual time-based snapshot of the core pipeline.
import pmu,common
from tabulate import tabulate
import itertools,sys,re

def pipeline_view(log, depths):
  out_pipe = open(log.replace('csv', 'pipeline.log'), 'w');
  pipe_list = common.file2lines(log)
  event_list = []
  depth_list = []
  lines = []
  for i in depths:
    event_list.append(depths[i][0])
    depth_list.append(int(depths[i][1]))
  issued_name = depths['issued'][0] 
  issued_index = [i for i, item in enumerate(event_list) if issued_name in item][0]
  lines = get_search_list(pipe_list, event_list[0])
  rows = int(len(lines)/depth_list[0]) 
  indices = [i+1 for i in range(max(depth_list))]
  chunks = get_empty_chunk_list(rows, event_list, depth_list)
  processed_chunks = get_empty_chunk_list(rows, event_list, depth_list)
  percent_chunks = get_empty_chunk_list(rows, event_list, depth_list)
  final_percent = [[[0 for i in range(k)] for j, k in zip(range(len(event_list)), depth_list)] for l in range(rows)]
  totals = [[0 for i in range(len(event_list))] for j in range(rows)]
  for event_name, event_depth in zip(event_list, depth_list):
    sum = 0
    lines = []
    index = event_list.index(str(event_name))
    cols = event_depth
    lines = get_search_list(pipe_list, event_name)
    chunks[index] = [[lines[i * cols + j] for j in range(cols)] for i in range(rows)]
    for i in range(rows):
      for j in range(event_depth-1):
        if not "not" in chunks[index][i][j] and not "not" in chunks[index][i][j+1]:
          processed_chunks[index][i][j]=abs(int(chunks[index][i][j])-int(chunks[index][i][j+1]))
        else:
           common.error("Some events were not counted, try running application longer; aborting")
        if j == (cols-2):
          processed_chunks[index][i][j+1] = int(chunks[index][i][j+1])
      for k in range(cols):
        sum += processed_chunks[index][i][k]
      for l in range(cols):
        percent_chunks[index][i][l] = int(100*processed_chunks[index][i][l]/sum)
      totals[i][index] = sum
      sum = 0
  final_percent = [[[percent_chunks[j][i][l] for l in range(k)] for j, k in zip(range(len(event_list)), depth_list)] for i in range(rows)]
  time = 0
  for i in range(rows):
    subtotals = totals[i]
    headers = [event_name.upper()+': '+str(round(subtotal/1000/1000,2))+'M | '+str(round(subtotal/subtotals[issued_index]*100,2))+'% of Issue' for event_name, subtotal in zip(event_list, subtotals)]
    headers.insert(0,'t'+str(time)+' (%)')
    time += 1
    out_pipe.write(tabulate(list(map(list, itertools.zip_longest(*final_percent[i]))), headers = headers, showindex = indices, tablefmt = "fancy_outline"))
    out_pipe.write("\n") 
  out_pipe.close() 

def get_empty_chunk_list(rows, event_list, depth_list):
  temp_list = [[[0 for i in range(l)] for j in range(rows)] for k, l in zip(range(len(event_list)), depth_list)] 
  return temp_list

def get_search_list(list_arg, search_arg):
  return_lines = []
  for i in list_arg:
    if len(i) > 3 and search_arg in i:
      return_lines.append(i.split(",")[1])
  return return_lines

