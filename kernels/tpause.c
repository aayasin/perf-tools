// Microbenchmark for TPAUSE for optimized waiting from user-land
//   as well as RDTSC instruction
// Original author:  Grant Zhou
// modified by Sinduri Gundu, Ahmad Yasin
// June 2023

#include <stdio.h>
#include <stdlib.h>
#include <immintrin.h>
#define C0_1 1
#define C0_2 0

int main(int argc, char *argv[])
{
    if (argc < 3) {
        printf("%s: missing <C0-sub-state> <num-tsc-cycles> args!\n", argv[0]);
        exit(-1);
    }
    unsigned int state = atoi(argv[1]);
    if (state != 1 && state != 2) {
        printf("%s: invalid C0-sub-state '%s'! options: 1|2\n", argv[0], argv[1]);
        exit(-1);
    }
    state = (state == 1) ? C0_1 : C0_2;
    const unsigned long long tsc_tgt = atol(argv[2]) + __rdtsc();
    while (__rdtsc() < tsc_tgt) {            //run for specified tsc
#ifndef RDTSC_ONLY
        _tpause(state, tsc_tgt);             //put proc in C0.x substate
#else
        asm("	NOP");
#endif
    }
}
