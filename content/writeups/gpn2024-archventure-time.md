---
title: "GPN - 'Archventure Time'"
description: "A writeup for the 'Archventure Time' challenge from the GPN 2024."
date: 2024-06-05T12:00:00+02:00
categories: ["Writeups", "rev"]
ctfs: ["GPN", "GPN 2024"]
---

> I found this funny multi-arch music software but I can't remember my license key.
> Can you recover it for me?

**Categories:** rev

**Flag:** `GPNCTF{W0nd3rful!_Y0u're_2_cl3ver_f0r_th4t_l1cens3_ch3ck!_W3ll_d0ne_<3}`

## Writeup

For this Challenge we got a binary called `chal` and a Dockerfile.

Loading the binary into Ghidra and taking a look at the main function, we can see that it asks for a license key, reads 24 characters of input and passes it to a function.

### Input Validation

At multiple points in this function it prints a message informing about an invalid format and terminates the proccess afterwards, so this function seems to validate the input somehow. All in all the function seems to check for three properties:

- The input has to be at least 23 characters long
- Every 6th character has to be a dash
- Every character except every 6th has to be alpha numeric

From this we know that the License key consists of 4 blocks of alpha numeric characters each seperated by one dash.

### Qemu

After the input validation, the main function creates a copy of the input, but without dashes. This is then passed to a different function.

After looking at this function for a while, it becomes clear that it iterates of an array of four structs which each contain a qemu command, some binary data and the length of that data. This data is then written to a temporary file. Afterwards the name of the temporary file together with the license key without dashes is appended to the command and then executed. The return value of the command is then checked, if it is zero the function informs the user that the license key is invalid and terminates the process.

Ok so it seems like these binaries can tell us some things about the license key which we seem to need to get.

### Validators

Poking around the first binary it seems to sort the input and compare it to `067889BBCKKMOPPUVWYY`, meaning the license key has to contain exactly those characters in exactly those counts.

The second binary seems to just sum up the letters ('A' has a value of 0, 'B' is 1, ... in this context) and numbers seperately for each block and compare those to hardcoded values. Extracting them reveals the following table:

| block nr. | alpha sum | num sum |
|-----------|-----------|---------|
| 1         | `61`        | `0`       |
| 2         | `36`        | `7`       |
| 3         | `44`        | `14`      |
| 4         | `50`        | `17`      |

The third binary seemed to be somewhat complicated so I decided not consider it for now and instead look at the fourth binary which turned out to have a bunch of implications hardcoded for every character in every block which it validates against the input.

However for a couple of characters it also validates that they have a certain exact value, this reveals to us that the  last block must match this regex: `Y.M8.`.

### Conclusions

So just from looking at three out of four validators we already have quite a lot of information, so let's try to get as far as we can with it.

We know which digits are contained in the license key and what they sum up to per block, so from this we know that:

The first block contains...

- 0-1 digits with a sum of 0
- and 4-5 letters with a sum of 61.

The second block contains...

- the digit `7`
- and 3-4 characteres with a sum of 36.

The third block contains...

- the digits `6` and `8`
- and 2-3 letters with a sum of 44

The fourth block...

- follows the pattern `Y.M8.`,
- contains the digit `9`
- and contains the letter `O`.

Ok so with this we have used up all the information from validators one and two, all that remains is to look through the implications in validator four and see where that leads us. Following the pattern of check every known character for implications that must be true, applying them and repeat I found these useful implications:

- `license[18] == '8'` => `license[ 5]='K'`
- `license[17] == 'M'` => `license[ 2]='P'`
- `license[15] == 'Y'` => `license[10]='6'`
- `license[ 5] == 'K'` => `license[14]='W'`
- `license[14] == 'W'` => `license[ 4]='K'`
- `license[ 4] == 'K'` => `license[17]='M'`

This leaves us with the folllowing skeleton of the license key:

`..P.K-K....-6...W-Y.M8.`

From here we can apply what we know about the letter sums and digits and we find that for the sums to work out...

- block one must contain the letters `B`, `P` and `U`,
- block two must contain the letters `Y`, `C` and the digit `0`
- and block three must contains the letters `B` and `V`.

At this point we can look at how many different possibilities there are for each block and we end up with...

- 6 for block one,
- 24 for block two,
- 6 for block three
- and 2 for block four.

### Getting the Flag

At this point we have two options, we can either start looking closer at validator three and try to narrow it down further that way, or we can just generate a list of the roughly 1700 different license keys and let the binary tell us which one is correct.

In this case we chose the latter option and came up with this python script:

```py
from itertools import permutations

for c0 in "BPU":
    b = list(f"{c0}.P.K-K....-6...W-Y.M8.")
    l = list("BPU")
    l.remove(c0)
    for c1 in l:
        b[1] = c1
        l2 = l[:]
        l2.remove(c1)
        b[3] = l2[0]
        for perm in permutations("YC70"):
            b = b[:7] + list(perm) + b[11:]
            for perm2 in permutations("BV8"):
                b = b[:13] + list(perm2) + b[16:]
                b[len(b)-4] = "O"
                b[len(b)-1] = "9"
                print("".join(b))
                b[len(b)-4] = "9"
                b[len(b)-1] = "O"
                print("".join(b))
```

which we can use to generate the list of candidates: `python gen_keys.py > key_candidates`. From here we wrote a small shell script that just enters each line into the binary and modified the Dockerfile a bit so we could run the script without having to install the qemu dependencies of the binary. For this we added these lines:

```
COPY ./brute_list.sh /app/
COPY ./key_candidates /app/
```

with `brute_list.sh` being:

```sh
#!/bin/bash
# Iterate over each line in the file
while IFS= read -r line; do
    echo "$line" | ./chal
done < "key_candidates"
```

After building the Dockerfile we can run the image interactively like so: `docker run -it archventure-time bash`. Once inside the container we can simply run `./brute_list.sh > outp` and once that finishes we can use `cat outp | grep GPN` to get the flag from the output file.
