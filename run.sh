#!/bin/bash
# replace the following with invocation to your application + arguments below.

# taskset set CPU affinity for consistent measurements (for CPUs 0,1 in tnis example)
taskset 0x3 \
 ./pmu-tools/workloads/PYTHON1s 2>&1 | 	# a sample command with no arguments
 tee out.log |				# redirect bulk output to some log file
 grep seconds				# grep for execution-time & some work metric
 
# sample output of the last command
# "Game 0 played in 37.6 seconds with 24 moves"

printf "\tDid you invoked your workload?!\n"	# remove me
