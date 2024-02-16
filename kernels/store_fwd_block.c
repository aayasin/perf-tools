// Microkernel to produce Store Fwd Block
// Original author:  Eric W Moore
// modified by Sinduri Gundu
// Feb 2024

#include <stdio.h>
#include <stdlib.h>

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
    if (argc<2) {
    printf("%s: missing <num-iterations> arg!\n", argv[0]);
    exit(-1);
    }

    int nloop = atol(argv[1]);
    int idx = 1;

    volatile union fool_cpu *tt = (union fool_cpu *)(tab + idx);
    long v=1;

    while ( nloop-- ) {
        tt->l0 = v;   //8 byte Store
                v = tt->l1;         //8 byte Load with 2 byte offset
                v++;
    }
}
