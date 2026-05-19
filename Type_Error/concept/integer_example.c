// Name: integer_example.c
// Compile: gcc -o integer_example integer_example.c

#include <limits.h>
#include <stdio.h>

int main() {
  unsigned int a = UINT_MAX + 1;
  int b = INT_MAX + 1;

  unsigned int c = 0 - 1;
  int d = INT_MIN - 1;

  printf("%u\n", a);
  printf("%d\n", b);

  printf("%u\n", c);
  printf("%d\n", d);
  return 0;
}