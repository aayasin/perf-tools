#!/bin/bash
# replace the following with invocation to your application + arguments below.

RUN_NLOOP=${RUN_NLOOP:-5}
RUN_APP=${RUN_APP:-./pmu-tools/workloads/PYTHON1s}
App=`echo $RUN_APP | rev | cut -d/ -f1 | rev`

# taskset set CPU affinity for consistent measurements (for CPUs 0,1 in this example)
#taskset 0x3 \
#./n-loop $RUN_NLOOP \			# enlarge duration for repeatitiveness
./n-loop $RUN_NLOOP $RUN_APP 2>&1 | 	# a sample command with no arguments
 tee .run-$App-$1-$$.log |  		# redirect bulk output to some log file
 grep seconds				# grep for execution-time & some work metric
 
# sample output of the last command
# "Game 0 played in 37.6 seconds with 24 moves"

printf "\tDid you invoked your workload?!\n"	# remove me
