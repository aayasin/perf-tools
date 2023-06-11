//==========================================================================
// AUTHOR:       Grant Zhou - grant.x.zhou@intel.com
//==========================================================================

#include <stdio.h>
#include <stdlib.h>
#include <immintrin.h>
#define C0_1 1
#define C0_2 0

int main(int argc, char *argv[])
{
    long i,num;
    if (argc<2) {
        printf("%s: missing <num-tsc-cycles> arg!\n", argv[0]);
        exit(-1);
    }
    num= atol(argv[1]);
    const unsigned long long tsc_base = __rdtsc();
    while ((__rdtsc() - tsc_base) < num) {            //run for specified tsc
        _tpause(C0_2, (tsc_base + num));              //put proc in C0_2 substate
    }
}
