#include <stdio.h>

int main(){
	unsigned int random;
	random = rand();	// (not so) random value!
	
	printf("random val: %x\n", random);

	unsigned int key = 0xdeadbeef ^ random;
	printf("key: %x\n", key);

	return 0;
}

