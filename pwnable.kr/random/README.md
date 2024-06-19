# pwnable.kr: random

## Description

Daddy, teach me how to use random value in programming!

ssh random@pwnable.kr -p2222 (pw:guest)

## Initial findings

When we connect to the remote server, we find `random.c` and its compiled executable. Using `cat` we can look through its source code.


```c

#include <stdio.h>

int main(){
	unsigned int random;
	random = rand();	// random value!

	unsigned int key=0;
	scanf("%d", &key);

	if( (key ^ random) == 0xdeadbeef ){
		printf("Good!\n");
		system("/bin/cat flag");
		return 0;
	}

	printf("Wrong, maybe you should try 2^32 cases.\n");
	return 0;
}

```
The program using the function `rand`, a pseudo-random number generator, which will return an integer between 0 to RAND_MAX, inclusive. 

Looking through the linux man page we arrive at the following text:

```

The srand() function sets its argument as the seed for a new
sequence of pseudo-random integers to be returned by rand().
These sequences are repeatable by calling srand() with the same
seed value.

If no seed value is provided, the rand() function is
automatically seeded with a value of 1.

```

Looking back at the code we can see that rand() is called absent of srand(), so we are using the default seed of 1. This means that this so-called random value is actually no so random, but is deterministic and easily knowable. We can simply write a modified version of a srource code to print the random value to us, and reverse engineer the key. Again, since no seed was set, our randomly generated number will be the same.

```c
#include <stdio.h>

int main(){
	unsigned int random;
	random = rand();	// (not so) random value!
	
	printf("random val: %x\n", random);

	unsigned int key = 0xdeadbeef ^ random;
	printf("key: %x\n", key);

	return 0;
}

```

Notice, we can use xor here with **0xdeadbeef** and our random val to get the correct key value. This is due to xor's self-inversion property.

After compiling and running this code via gcc, we get this:

```
./reverse_key 
random val: 6b8b4567
key: b526fb88
```

The key 0xb526fb88, or 3039230856 in base 10, is the value we can send on the server, passing the key check and print the flag.

