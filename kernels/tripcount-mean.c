// Do not modify!
//
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define MSG 0
#ifndef ITER
#define ITER 20000
#endif

int main(int argc, const char* argv[])
{
    register uint64_t n asm ("r10") = argv[1] ? atoi(argv[1]) : ITER;
    register uint64_t i0 asm ("r9");
    register uint64_t i1 asm ("r8");
    if (MSG) printf("%s\n", MSG ? MSG : "");
    asm("	PAUSE");
    for (i0=0; i0<n; i0++) {
        for(i1=0; i1<20; i1++) {
            asm("   nop");
        }
        for(i1=0; i1<100; i1++) {
            asm("   add %rax,%rax");
        }
        i1 = 0;
        asm("   jmp Lbl_mid");
        for(; i1<70; i1++) {
            asm("   nop");
            asm("Lbl_mid:");
            asm("   add %rbx,%rbx");
        }
    }
    asm(".align 512; Lbl_end:");
    return 0;
}
