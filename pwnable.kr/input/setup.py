#!/usr/bin/env python3

from pwn import *
from subprocess import call

# copy over the solve file
command = "scp -P2222 ./solve.py input2@pwnable.kr:/tmp"
call(command.split(" "))

# create a symbolic link with flag in temp file
conn = ssh(user='input2', host='pwnable.kr', port=2222, password='guest')
conn.process(['ln', '-s', '/home/input2/flag', 'flag'], cwd='/tmp')

# run python script manually
conn.interactive()

