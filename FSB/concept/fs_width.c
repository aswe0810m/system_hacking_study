// Name: fs_width.c
// Compile: gcc -o fs_width fs_width.c

#include <stdio.h>

int main() {
  int num;

  printf("%8d\n", 123);                 // "     123"
  printf("%s%n: hi\n", "Alice", &num);  // "Alice: hi", num = 5
  printf("%*s: hello\n", num, "Bob");   // "  Bob: hello "
  return 0;
}