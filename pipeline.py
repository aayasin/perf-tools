import pmu,common
from tabulate import tabulate
import itertools,sys,re

def pipeline_view(log,depths):
  out_pipe=open(log.replace('csv','pipeline.log'),'w');
  pipe_list=get_log(log)
  event_list=[]
  depth_list=[]
  lines=[]
  for i in depths:
    event_list.append(depths[i][0])
    depth_list.append(int(depths[i][1]))
  issued_name=depths['issued'][0] 
  issued_list=[i for i,item in enumerate(event_list) if re.search(issued_name,item)]
  issued_index=issued_list[0]
  lines=get_search_list(pipe_list,event_list[0])
  rows=int(len(lines)/depth_list[0]) 
  indices=[i+1 for i in range(max(depth_list))]
  chunks=[[[0 for i in range(l)] for j in range(rows)] for k,l in zip(range(len(event_list)),depth_list)]
  processed_chunks=[[[0 for i in range(l)] for j in range(rows)] for k,l in zip(range(len(event_list)),depth_list)]
  percent_chunks=[[[0 for i in range(l)] for j in range(rows)] for k,l in zip(range(len(event_list)),depth_list)]
  final_percent=[[[0 for i in range(k)] for j,k in zip(range(len(event_list)),depth_list)] for l in range(rows)]
  totals=[[0 for i in range(len(event_list))] for j in range(rows)]
  for event_name,event_depth in zip(event_list,depth_list):
    sum=0
    lines=[]
    index=event_list.index(str(event_name))
    cols=event_depth
    lines=get_search_list(pipe_list,event_name)
    for i in range(rows):
      for j in range(cols):
        chunks[index][i][j]=lines[(i*cols)+j]
    for i in range(rows):
      for j in range(event_depth-1):
        if not "not" in chunks[index][i][j] and not "not" in chunks[index][i][j+1]:
          processed_chunks[index][i][j]=abs(int(chunks[index][i][j])-int(chunks[index][i][j+1]))
        else:
          print("Some events were not counted, try running application longer; aborting")
          sys.exit()
        if j == (cols-2):
          processed_chunks[index][i][j+1]=int(chunks[index][i][j+1])
      for k in range(cols):
        sum+=processed_chunks[index][i][k]
      for l in range(cols):
        percent_chunks[index][i][l]=int(100*processed_chunks[index][i][l]/sum)
      totals[i][index]=sum
      sum=0
  for i in range(rows):
    for j,k in zip(range(len(event_list)),depth_list):
      for l in range(k):
        final_percent[i][j][l]=percent_chunks[j][i][l]
  time=0
  for i in range(rows):
    subtotals=totals[i]
    headers=[event_name.upper()+': '+str(round(subtotal/1000/1000,2))+'M | '+str(round(subtotal/subtotals[issued_index]*100,2))+'% of Issue' for event_name,subtotal in zip(event_list,subtotals)]
    headers.insert(0,'t'+str(time)+' (%)')
    time+=1
    out_pipe.write(tabulate(list(map(list,itertools.zip_longest(*final_percent[i]))),headers=headers,showindex=indices,tablefmt="fancy_outline"))
    out_pipe.write("\n")
  out_pipe.close()

def get_log(log):
  return common.file2lines(log)

def get_search_list(list_arg,search_arg):
  return_lines=[]
  for i in list_arg:
    if len(i) > 3 and search_arg in i:
      return_lines.append(i.split(",")[1])
  return return_lines

