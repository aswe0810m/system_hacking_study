// Name: oor_bof.c
// Compile: gcc -o oor_bof oor_bof.c -m32

#include <stdio.h>

#define BUF_SIZE 32

int main() {
  char buf[BUF_SIZE];
  int size;
  
  printf("Input length: ");
  scanf("%d", &size);
  
  if (size > BUF_SIZE) {
    fprintf(stderr, "Buffer Overflow Detected");
    return -1;
  }
  
  read(0, buf, size);
  return 0;
}