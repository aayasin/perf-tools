// Microbenchmark for branch mispredictions
// Author: Sinduri Gundu
// Dec 2023

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define N 20000

static int *m_s1;

void init(void) {
    m_s1 = malloc(sizeof(int)*N);
    srand(42);

    for (int i = 0; i < N; i++) {
        m_s1[i] = rand() % N;
    }
}

void sel_arr(int *s1) {

  for (int i = 0; i < N; i++) {
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
  for(int i=0; i<iter; ++i)
    sel_arr(m_s1);
}

int main(int argc, char *argv[])
{
  if (argc<2) {
      printf("%s: missing <num-iterations> arg!\n", argv[0]);
      exit(-1);
  }

  int iter = atol(argv[1]);

  init();
  run(iter);

  return 0;
}
