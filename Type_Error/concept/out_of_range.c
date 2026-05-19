// Name: out_of_range.c
// Compile: gcc -o out_of_range out_of_range.c

#include <stdio.h>

unsigned long long factorial(unsigned int n) {
  unsigned long long res = 1;

  for (int i = 1; i <= n; i++) {
    res *= i;
  }

  return res;
}

int main() {
  unsigned int n;
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