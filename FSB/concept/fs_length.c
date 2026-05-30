// Name: fs_length.c
// Compile: gcc -o fs_length fs_length.c

#include <stdio.h>

int main() {
  char a = 0x12;
  short b = 0x1234;
  long c = 0x12345678;
  long long d = 0x12345678abcdef01;

  printf("%hhd\n", a);    // "18"
  printf("%hd\n", b);     // "4660"
  printf("%ld\n", c);     // "305419896"
  printf("%lld\n", d);    // "1311768467750121217"
  return 0;
}