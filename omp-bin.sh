#!/bin/sh
# Author: Ahmad Yasin
# June 2022

bin=$2
omp=$1
aff=$3
cmd="taskset $aff"
if [ $# -le 1 ]; then
  echo $0: must provide binary and num-threads
  exit 1
fi
if [ $# -eq 2 ]; then
  echo not pinning ..
  cmd=""
fi

export OMP_NUM_THREADS=$omp
$cmd $bin
