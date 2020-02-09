import re
from hashlib import md5 as md5

# Definition of a dictionary in which will be stored the associations
# between a hash and the corresponding character
hashes = {}

# Definition of a string in which i will store MD5 reverses
MD5_reverse = ''

# Loop over ASCII table
for c in (range(128)):

    # Retrieve MD5 of the char
    hash = md5(chr(c).encode())
    hash = hash.hexdigest()

    # Add hash in dictionary
    hashes[hash] = chr(c)

# Retrieve challenge hashes
with open('secret.txt') as f:
    lines = [line.rstrip() for line in f]


for cur_hash in lines:

    c = hashes.get(cur_hash)

    # Ignore weird chars
    if c is None:
        continue

    MD5_reverse = MD5_reverse + c


# Extract flag
flag = re.search("HSR{.*?}", MD5_reverse)

# GG ?
print(flag[0])
