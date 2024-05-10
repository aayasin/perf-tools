// Microkernel to produce Store Fwd Block
// Original author:  Eric W Moore
// modified by Sinduri Gundu
// Feb 2024

#include <stdio.h>
#include <stdlib.h>
#ifndef ITER
#define ITER 20000
#endif

union fool_cpu {

	long l0;
	
	struct __attribute__ ((packed)) { //packed to prevent the compiler from padding.
        char c0;
	char c1;
        long l1; //l1 has an offset of 2 bytes from l0.
	};
};

int tab[10];

int main(int argc, char *argv[])
{
    int nloop = argv[1] ? atol(argv[1]) : ITER;
    int idx = 1;

    volatile union fool_cpu *tt = (union fool_cpu *)(tab + idx);
    long v=1;

    while ( nloop-- ) {
        tt->l0 = v;   //8 byte Store
                v = tt->l1;         //8 byte Load with 2 byte offset
                v++;
    }
}
