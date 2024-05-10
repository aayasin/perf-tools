#ifndef MSG
#define MSG "Reference: Establishing a Base of Trust with Performance Counters for Enterprise Workloads. Andrzej Nowak, Ahmad Yasin, Avi Mendelson, Willy Zwaenepoel. In 2015 USENIX Annual Technical Conference, USENIX ATC 2015."
#endif
#ifndef ITER
#define ITER 20000
#endif
#include <stdio.h>
#include <stdlib.h>

#define COO 1.354364576457745
double CO = COO;

#define noinline __attribute__((noinline))

noinline double h0(double a) {
    return CO*a;
}

noinline double f9(double a) {
    return h0(a*CO);
}

noinline double f8(double a) {
    return f9(a*CO);
}

noinline double f7(double a) {
    return f8(a*CO);
}

noinline double f6(double a) {
    return f7(a*CO);
}

noinline double f5(double a) {
    return f6(a*CO);
}

noinline double f4(double a) {
    return f5(a*CO);
}

noinline double f3(double a) {
    return f4(a*CO);
}

noinline double f2(double a) {
    return f3(a*CO);
}

noinline double f1(double a) {
    return f2(a*CO);
}

int main(int argc, const char* argv[])
{
  int i = 0;
  double r=1;
  long long len;
  
  if (argc<2) {
	  printf("error: number of iterations is missing !\n");
	  return (-1);
  }
  if (MSG) printf("%s\n", MSG ? MSG : "");

  len = atol(argv[1]);
  CO += 1.0f/len;

  for (i=0; i<len; i++)
    r = f1(3*CO); // r += f1(1);

  printf("%f\n", r);  
  return 0;
}
