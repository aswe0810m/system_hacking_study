// Name: fs.c
// Compile: gcc -o fs fs.c

#include <stdio.h>

int main() {
    int num;

    printf("%d\n", 123); // 123
    printf("%s\n", "Hello, world"); // Hello, world
    printf("%x\n", 0xdeadbeef); // deadbeef
    printf("%p\n", &num); // 0x7ffe58004ce4
    return 0;
}