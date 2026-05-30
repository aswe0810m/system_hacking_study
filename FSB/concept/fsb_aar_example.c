// Name: fsb_aar_example.c
// Compile: gcc -o fsb_aar_example fsb_aar_example.c

#include <stdio.h>

char *secret = "THIS IS SECRET";

int main() {
  char *addr = secret;
  char format[0x100];

  printf("Format: ");
  scanf("%s", format);
  printf(format);

  return 0;
}