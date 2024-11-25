#!/bin/bash
#set -x
./workloads/permute.$1 abcdefghijk
exit 0
clang++ -g -std=c++17 -static workloads/src/permute.cpp -o workloads/permute.scl
clang++ -g -std=c++17 workloads/src/permute.cpp -o workloads/permute.dcl
g++ -g -std=c++17 workloads/src/permute.cpp -o workloads/permute.dgc
g++ -g -std=c++17 -static workloads/src/permute.cpp -o workloads/permute.sgc
