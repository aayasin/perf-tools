// A micro-benchmark for String Operations (aka "rep movs")
// Author: Ahmad Yasin
// edited: June 2021

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>
#include <assert.h>

#define MSG 0
#define DBG 0
#define KB 	1024
#define U64	uint64_t

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

#define MAX_BUFFERS 2
char* buffers[MAX_BUFFERS];
int   buffers_idx=0;
char* alloc(U64 s, U64 a, char i)
{
    char* b=(char*)malloc(s);
    assert(b);
    if (DBG) printf("%p with s=%lu a=%lu i=%c\n", b, s, a, i);
    assert(buffers_idx<MAX_BUFFERS);
    buffers[buffers_idx++]=b;
    b = (char*)((U64)b & ~((U64)(a - 1)));
#if 0
    memset(b, i, s-2);
    b[s-1]='\0';
#endif
    //printf("%c %c %s\n", b[0], b[s-1], b);
    return b;
}
void freeall()
{
    for(int i=0; i<buffers_idx; i++)
        free(buffers[i]);
}

int main(int argc, const char* argv[])
{
    uint64_t i,n,b,s, a;
    uint64_t tsc1, tsc2;
    char *B1, *B2;
    if (argc<2) {
        printf("%s: missing <num-iterations> [<buffer-size-in-KB>] [alignment-offset-in-bytes] args!\n", argv[0]);
        exit(-1);
    }
    if (MSG) printf("%s\n", MSG ? MSG : "");
    n= atol(argv[1]);
    b= (argc>2) ? atol(argv[2]) : 10;
    a= (argc>3) ? atol(argv[3]) : 64;
    s= b*KB;
    B1=alloc(s, a, (argc>4) ? argv[4][0] : 'a');
    B2=alloc(s, a, (argc>4) && argv[4][1] ? argv[3][1] : 'b');
    asm("	PAUSE");
    tsc1 = _rdtsc();
    for (i=0; i<n; i++) {
        memcpy(B2, B1, s);
    }
    asm(".align 512; Lbl_end:");
    tsc2 = _rdtsc();
    printf("%s: average TSC of %.1f ticks/KB for %ld KB %ldB-aligned buffers\n",
       argv[0], (tsc2-tsc1)/(double)n/b, b, a);
    if (DBG) printf("%p %p\n", B1, B2);
    //TODO: fix why free seg-faults
    //freeall();

    return 0;
}
