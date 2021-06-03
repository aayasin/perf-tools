// A micro-benchmark for String Operations (aka "rep movs")
// Author: Ahmad Yasin
// edited: June 2021

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

#define MSG 0
#define KB 	1024

#if 0
# define CC_SET(c) "\n\tset" #c " %[_cc_" #c "]\n"
# define CC_OUT(c) [_cc_ ## c] "=qm"
static inline int memcmp(const void *s1, const void *s2, size_t len)
{
        bool diff;
        asm("repe; cmpsb" CC_SET(nz)
            : CC_OUT(nz) (diff), "+D" (s1), "+S" (s2), "+c" (len));
        return diff;
}
#endif

char* alloc(uint64_t s, char i)
{
    char* b=(char*)malloc(s);
    if (0) {
        memset(b, i, s-2);
        b[s-1]='\0';
    }
    //printf("%c %c %s\n", b[0], b[s-1], b);
    return b;
}

int main(int argc, const char* argv[])
{
    uint64_t i,n,b,s;
    uint64_t tsc1, tsc2;
    char *B1, *B2;
    if (argc<4) {
        printf("%s: missing <num-iterations> <buffer-size-in-KB> <two-chars> args!\n", argv[0]);
        exit(-1);
    }
    if (MSG) printf("%s\n", MSG ? MSG : "");
    n= atol(argv[1]);
    b= atol(argv[2]);
    s= b*KB;
    B1=alloc(s, argv[3][0]);
    B2=alloc(s, argv[3][1]);
    asm("	PAUSE");
    tsc1 = _rdtsc();
    for (i=0; i<n; i++) {
        memcpy(B2, B1, s);
    }
    asm(".align 512; Lbl_end:");
    tsc2 = _rdtsc();
    printf("%s: Average TSC of %.1f ticks/KB for %ld KB buffers\n",
       argv[0], (tsc2-tsc1)/(double)n/b, b);
    free(B1);
    free(B2);

    return 0;
}
