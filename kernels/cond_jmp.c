// Microbenchmark for branch mispredictions
// Author: Sinduri Gundu
// Dec 2023

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define N 20000

static int m_s1[N];

void init(void) {
    int i;
    unsigned state = 42;

    for (i = 0; i < N; i++) {
	unsigned x = state;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	state = x;
        m_s1[i] = x % N;
    }
}

void sel_arr(int *s1) {
  int i;
  for (i = 0; i < N; i++) {
    if(s1[i] < 10035)
    {
	asm("   inc %rcx");
	asm("   inc %rcx");
	asm("   inc %rcx");
	asm("   inc %rcx");
	asm("   inc %rcx");
	asm("   inc %rcx");
	asm("   inc %rcx");
	asm("   inc %rcx");
	asm("   inc %rcx");
	asm("   inc %rcx");
	asm("   inc %rcx");
        asm("   inc %rcx");
        asm("   inc %rcx");
        asm("   inc %rcx");
        asm("   inc %rcx");
        asm("   inc %rcx");
        asm("   inc %rcx");
        asm("   inc %rcx");
        asm("   inc %rcx");
        asm("   inc %rcx");
	asm("   inc %rcx");
        asm("   inc %rcx");
        asm("   inc %rcx");
        asm("   inc %rcx");
        asm("   inc %rcx");
        asm("   inc %rcx");
        asm("   inc %rcx");
        asm("   inc %rcx");
        asm("   inc %rcx");
        asm("   inc %rcx");
        asm("   inc %rcx");
        asm("   inc %rcx");
        asm("   inc %rcx");
        asm("   inc %rcx");
	asm("   inc %rcx");
        asm("   inc %rcx");
	asm("   inc %rcx");
        asm("   inc %rcx");
	asm("   inc %rcx");
        asm("   inc %rcx");
    }
    else
    {
	asm("   dec %rcx");
	asm("   dec %rcx");
	asm("   dec %rcx");
	asm("   dec %rcx");
	asm("   dec %rcx");
	asm("   dec %rcx");
	asm("   dec %rcx");
	asm("   dec %rcx");
	asm("   dec %rcx");
	asm("   dec %rcx");
	asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
	asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
        asm("   dec %rcx");
    }
    
  }
	
}

void run(int iter) {
  int i;
  for(i=0; i<iter; ++i)
    sel_arr(m_s1);
}

int main(int argc, char *argv[])
{
  int iter = argv[1] ? atoi(argv[1]) : 10000;

  init();
  run(iter);

  return 0;
}
