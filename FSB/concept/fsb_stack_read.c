// Name: fsb_stack_read.c
// Compile: gcc -o fsb_stack_read fsb_stack_read.c

#include <stdio.h>

int main() {
  char format[0x100];
  
  printf("Format: ");
  scanf("%s", format);
  printf(format);
  
  return 0;
}