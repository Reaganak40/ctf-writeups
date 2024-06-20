
# key 1 logic
key1 = 0x00008ce4 

# key 2 logic
r3 =  0x00008d08
r3 += 4
key2 = r3

# key 3 logic
key3 = 0x00008d80

# compute the correct key
print('key1:', key1)
print('key2:', key2)
print('key3:', key3)
print('Correct key:', key1+key2+key3)
