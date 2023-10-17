// Do not modify!
//
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define MSG 0

int main(int argc, const char* argv[])
{
    register uint64_t n asm ("r10");
    register uint64_t i0 asm ("r9");
    register uint64_t i1 asm ("r8");
    if (argc<2) {
        printf("%s: missing <num-iterations> arg!\n", argv[0]);
        exit(-1);
    }
    if (MSG) printf("%s\n", MSG ? MSG : "");
    asm ("      mov %1,%0"
                 : "=r" (n)
                 : "r" (atol(argv[1])));
    asm("	PAUSE");
    for (i0=0; i0<n; i0++) {
        for(i1=0; i1<20; i1++) {
        asm("   nop");
        }
        for(i1=0; i1<100; i1++) {
        asm("   add %rax,%rax");
        }
    }
    asm(".align 512; Lbl_end:");
    return 0;
}
