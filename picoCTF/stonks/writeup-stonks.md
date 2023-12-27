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

This vulnerability results from uncontrolled format strings. A format string is a way to implement [string interpolation](https://en.wikipedia.org//wiki/String_interpolation), in this case through *printf* in the command line. Like many string interpolation functions, the important key here is that *printf* is a [variadic function](https://en.wikipedia.org/wiki/Variadic_function), meaning that it can pass in any number of arguments. 