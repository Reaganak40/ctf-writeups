#!/usr/bin/env python3

from pwn import *

# filters gadgets in gadgets file to only include those
# where the address is in ascii range (0x20-0x7f)


with open('gadgets', 'r') as f:
    gadgets = f.readlines()

# skip first 2 lines
gadgets = gadgets[2:]

filtered_gadgets = []
for gadget in gadgets:
    try:
        addr = gadget.split()[0]
    except:
        continue
    
    if addr == 'Unique':
        continue

    # convert to 4 bytes to check
    addr = p32(int(addr, 16))

    for i in range(4):
        try:
            if 0x20 <= addr[i] <= 0x7f:
                filtered_gadgets.append(gadget)
                break
        except:
            print(addr, "|", gadget)

with open('filtered_gadgets', 'w') as f:
    f.writelines(filtered_gadgets)
