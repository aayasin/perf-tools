// A micro-benchmark for page faults
// Author: Ahmad Yasin
// edited: April 2022

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>
#include <assert.h>

#define MSG 0
#define DBG 0
#define KB  1024
#define MB  (KB*KB)
#define U64	uint64_t

#define Page  (4*KB)
#define ALLOC(B) {B = malloc(s); assert(B);}

int main(int argc, const char* argv[])
{
    uint64_t i,j,n,m,s,x,y=0;
    uint64_t tsc1, tsc2;
    char *B;
    if (argc<2) {
        printf("%s: missing <num-iterations> [num-pages=1000] args!\n", argv[0]);
        exit(-1);
    }
    if (MSG) printf("%s\n", MSG ? MSG : "");
    n= atol(argv[1]);
    m= (argc>2) ? atol(argv[2]) : 1000;
    x= (argc>3) ? atol(argv[3]) : 7;
    y= (argc>4) ? atol(argv[4]) : 0;
    s= m*Page;
    if (DBG) printf("%ld %ld %ld %ld\n", n, m, x, s);
    assert(x<m);
    if (!y) ALLOC(B)
    asm("	PAUSE");
    tsc1 = _rdtsc();
    for (i=0; i<n; i++) {
        if (y) ALLOC(B)
        for (j=0; j<m; j++) {
            B[j*Page]=x;
        }
        if (y) free(B);
    }
    asm(".align 512; Lbl_end:");
    tsc2 = _rdtsc();
    if (!y) free(B);
    printf("%s: average TSC of %.1f ticks/page for %.2f MB buffer. re-alloc=%ld\n",
       argv[0], (tsc2-tsc1)/(double)n/m, (double)s/MB, y);

    return 0;
}
