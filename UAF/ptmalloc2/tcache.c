// Name: tcache.c
// Compile: gcc -o tcache tcache.c
#include <stdio.h>
#include <stdlib.h>

const int kTcacheN = 7;

int main() {
	void *small_chuncks[kTcacheN + 1];
	void *from_tcache = NULL;
	void *from_fastbin = NULL;
	void *tmp = NULL;

	for (int i = 0; i < kTcacheN + 1; i++) small_chuncks[i] = malloc(0x20);
	for (int i = 0; i < kTcacheN; i++) free(small_chuncks[i]);

	free(small_chuncks[kTcacheN]);

	from_tcache = malloc(0x20);

	for (int i = 0; i < kTcacheN - 1; i++) tmp = malloc(0x20);
	from_fastbin = malloc(0x20);

	return 0;
}
