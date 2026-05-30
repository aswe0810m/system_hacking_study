// Name: fs_param.c
// Compile: gcc -o fs_param fs_param.c

#include <stdio.h>

int main() {
  int num;
  printf("%2$d, %1$d\n", 2, 1);  // "1, 2"
  return 0;
}