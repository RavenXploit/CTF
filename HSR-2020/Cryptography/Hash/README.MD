# Hash (75 points)

This challenge provides a simple text file which contains some md5 hashes : 

```
69691c7bdcc3ce6d5d8a1361f22d04ac
f623e75af30e62bbd73d6df5b50bb7b5
e4da3b7fbbce2345d7772b0674a318d5
84c40473414caf2ed4a7b1283e48bbf4
69691c7bdcc3ce6d5d8a1361f22d04ac
e1671797c52e15f763380b45e841ec32
03c7c0ace395d80182db07ae2c30f034
03c7c0ace395d80182db07ae2c30f034
0cc175b9c0f1b6a831c399e269772661
[...]
```

Let's get start ! 

I've try to get first hash on https://md5decrypt.net/ : 

```
Input: 69691c7bdcc3ce6d5d8a1361f22d04ac
Output: M
```

The second :
```
Input: f623e75af30e62bbd73d6df5b50bb7b5
Output: D
```

And the third : 

```
Input: e4da3b7fbbce2345d7772b0674a318d5
Output: 5
```

If we follow the logic, each line should be a one-character hash.

So we're going to take the MD5s of each characters of the ASCII table and we gonna decode the file with them. 

Let's go for the code! 

```python
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


# GG ?
print(MD5_reverse)

```

```MD5(MessageDigest5)estunefonctiondehachagecryptographiquequicalcule
[...] 
HSR{MD5_rUleZ_on3_l1n3_1n_BASH_!}
[...] 
```

![Exif data](./meme.jpg)

Well I obtain the flag but I preferred to modify my script to make an extraction by regex : 

```python
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

```

And after an other execution i obtain the flag only : 

```
HSR{MD5_rUleZ_on3_l1n3_1n_BASH_!}
```

Thanks for reading ! Keep hacking ! ;)