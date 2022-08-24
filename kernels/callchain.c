// Here it is – the simple version with no variable instructions in between.

#include <stdio.h>
#include <stdlib.h>

#define COO 1.354364576457745
double CO = COO;

#define MSG "Reference: Establishing a Base of Trust with Performance Counters for Enterprise Workloads. Andrzej Nowak, Ahmad Yasin, Avi Mendelson, Willy Zwaenepoel. In 2015 USENIX Annual Technical Conference, USENIX ATC 2015."


double f0(double a) {
    return CO*a;
}

double f9(double a) {
    return f0(a*CO);
}

double f8(double a) {
    return f9(a*CO);
}

double f7(double a) {
    return f8(a*CO);
}

double f6(double a) {
    return f7(a*CO);
}

double f5(double a) {
    return f6(a*CO);
}

double f4(double a) {
    return f5(a*CO);
}

double f3(double a) {
    return f4(a*CO);
}

double f2(double a) {
    return f3(a*CO);
}

double f1(double a) {
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
    r += f1(1);

  printf("%f\n", r);  
  return 0;
}
