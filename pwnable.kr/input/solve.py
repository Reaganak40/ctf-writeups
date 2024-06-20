import os
from pwn import *
import socket

# Server address and port
SERVER_ADDR = '127.0.0.1'
SERVER_PORT = 8000

# command line arguments for ./input 
args = ['A'] * 100 # need argc to == 100
args[0] = '/home/input2/input'
args[ord('A')] = '\x00'
args[ord('B')] = '\x20\x0a\x0d'
args[ord('C')] = '{}'.format(SERVER_PORT)


# pipes
r1, w1 = os.pipe()
r2, w2 = os.pipe()

# send data through pipes, to be
# received by the subprocess
os.write(w1, '\x00\x0a\x00\xff') # stdin
os.write(w2, '\x00\x0a\x02\xff') # stderr

# setup environment variables
env = {"\xde\xad\xbe\xef" : "\xca\xfe\xba\xbe"}

# create a file
with open("\x0a", "w") as file:
    file.write('\x00\x00\x00\x00')

# start input subprocess
io = process(args, stdin=r1, stderr=r2, env=env)

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Connect to the server
    sock.connect((SERVER_ADDR, SERVER_PORT))

    # Send data
    message = b"\xde\xad\xbe\xef"
    sock.sendall(message)

except Exception as e:
    print("Stage 5 Error:", e)

finally:
    # Close the socket
    sock.close()


# Receive the flag
io.interactive()

