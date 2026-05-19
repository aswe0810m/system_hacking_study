// Name: oor_signflip.c
// Compile: gcc -o oor_signflip oor_signflip.c

#include <stdio.h>

unsigned long long factorial(unsigned int n) {
  unsigned long long res = 1;

  for (int i = 1; i <= n; i++) {
    res *= i;
  }

  return res;
}

int main() {
  int n;
  unsigned int res;

  printf("Input integer n: ");
  scanf("%d", &n);

  if (n >= 50) {
    fprintf(stderr, "Input is too large");
    return -1;
  }

  res = factorial(n);
  printf("Factorial of N: %u\n", res);
}