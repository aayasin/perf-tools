#!/bin/sh
# Author: Ahmad Yasin
# Aug. 2020
#
./gen-kernel.py jumpy -n 5 -i JMP -a 14  > jumpy5p14.c
gcc -S jumpy5p14.c
gcc -o jumpy5p14 jumpy5p14.c
#perf stat -a --topdown -e instructions,BACLEARS.ANY --no-metric-only -C0 -- taskset 0x1 ./jumpy5p14 999999999
