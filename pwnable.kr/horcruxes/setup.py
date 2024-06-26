#!/usr/bin/env python3

from pwn import *
import subprocess

# ===========================================================
#                        FOR TESTING
# ===========================================================


# Run a command and capture its output                                               
result = subprocess.run(["./exploit.py"], stdout=subprocess.PIPE)                        
                                                                                         
# Print the output                                                                   
print(result.stdout.decode())

# copies the payload to the server, because I am unable to run
# the binary on my local machine :(
conn = ssh(host='pwnable.kr', user='horcruxes', port=2222, password='guest')

with open('payload', 'rb') as f:
    payload = f.read()

conn.run(f"python -c \"print({payload})\" > /tmp/cicero/payload")
conn.close()
