# Copyright (c) 2020-2024, Intel Corporation
# Author: Jon Strang
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# Processes a custom perf_stat output file into a visual time-based snapshot of the core pipeline.
import pmu,common
import itertools,sys,re
try: from tabulate import tabulate
except: common.warn("Failed to import tabulate, pipeline-view post-processing will fail. Please run './do.py setup-all'")

def pipeline_view(log, depths):
  # FIXME:01: add a "namer" module to assign filename for all logs
  out_pipe = open(log.replace('csv', 'pipeline.log'), 'w');
  pipe_list = common.file2lines(log)
  event_list = []
  depth_list = []
  lines = []
  #Get the events and the depths of each uarch structure [ dsb, mite, decoders, ms, issue, execute, retire ]
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
  #Iterate through the list of events and their associated depths
  for event_name, event_depth in zip(event_list, depth_list):
    sum = 0
    lines = []
    index = event_list.index(str(event_name))
    cols = event_depth
    lines = get_search_list(pipe_list, event_name)
    #Comb through the perf-stats csv and grep for the events and put it into chunks list
    chunks[index] = [[lines[i * cols + j] for j in range(cols)] for i in range(rows)]
    for i in range(rows):
      for j in range(event_depth-1):
        #Take the different between cmask-N which is the superset and cmask-N+1 which is the subset put that into the processed_chunks lists
        if not "not" in chunks[index][i][j] and not "not" in chunks[index][i][j+1]: 
          #This takes into accout the PMU queury rate, and the possibility that an event with cmask N can be possibly smaller than N+1 (superset < subset) due to shift in workload intensity, so we take the abs(absolute value).
          processed_chunks[index][i][j]=abs(int(chunks[index][i][j])-int(chunks[index][i][j+1]))*(j+1)
        else:
           #Error check that "not counted" doesn't exist 
           common.error("Some events were not counted, try running application longer; aborting")
        #Put the tail cmask as its own calculation outside of loop.
        if j == (cols-2): 
          processed_chunks[index][i][j+1] = int(chunks[index][i][j+1])*(j+1)
      #Generate a sum value as total sum of an event to be divisor.
      for k in range(cols):
        sum += processed_chunks[index][i][k]
      #Use the sum to convert discrete values into percents and place into percent_chunks list
      for l in range(cols):
        percent_chunks[index][i][l] = int(100*processed_chunks[index][i][l]/(sum+.1))
      totals[i][index] = sum
      sum = 0
  #Convert the percent_chunks from homogenous event data to heterogenous data where dsb, mite, decoders, ms, issue, execute, retire all occupy a single snapshot.
  final_percent = [[[percent_chunks[j][i][l] for l in range(k)] for j, k in zip(range(len(event_list)), depth_list)] for i in range(rows)]
  time = 0
  #Use the imported tabulate to post-process and write to output file. We anchor all events to UOPS ISSUED.
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

