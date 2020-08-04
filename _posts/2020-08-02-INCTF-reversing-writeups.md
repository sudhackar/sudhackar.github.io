---
layout: post
title: "INCTF 2020 Reversing Writeups"
date: 2020-08-02 17:02:00 +0530
categories: blog
tags: [reversing, radare2, r2pipe, angr, qiling]
---

### INCTF

I had some time this weekend. [INCTF](https://ctf.inctf.in) was running, so I decided to try reversing challenges for sometime. Here are the writeups for the challenges I managed to solve.


#### ArchRide

~40 solves

A file is attached.

```bash
[inctf-surp] file surprise
surprise: bzip2 compressed data, block size = 900k
[inctf-surp] bzip2 -df surprise
bzip2: Can't guess original name for surprise -- using surprise.out
[inctf-surp] file surprise.out
surprise.out: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=ac59cee04b8dcea207d9eb67ea3f03859a819f06, stripped
```

This ELF is pretty small in code size. `main` looks like this

```c
  printf("Enter Key:");
  for ( i = 0; i <= 13; ++i )
    key[i] = 0;
  fgets(&s, 15, stdin);
  initKey(&s, 15LL);
  if ( check1(&s) != 1 || check2(&s) != 1 || strlen(&s) != 14 )
  {
    puts("Need a better key :(");
  }
  else
  {
    dumpFile(&s);
    puts("Surprise!");
  }
```

`check1` and `check2` are pretty simple functions. They check the input with hardcoded xor values in the binary.
Pretty easy to solve with [angr](https://github.com/angr/angr)
Once the input passes both checks, a `key` of 13 bytes is calculated which is used to xor an embedded `bzip2` file in the binary.

```c
  s = fopen("surprise", "wb");
  ptr = malloc(0xFFEF1uLL);
  if ( s )
  {
    for ( i = 0; i <= 1048305LL; ++i )
      ptr[i] = LOBYTE(key[i % 13]) ^ bin[i];
    fwrite(ptr, 0xFFEF1uLL, 1uLL, s);
    fclose(s);
    free(ptr);
  }
```

This process needs to be done multiple times - all the binaries dropped are one of multiple arch's

```
ELF 32-bit LSB shared object, ARM, EABI5
ELF 32-bit LSB shared object, Intel 80386,
ELF 64-bit LSB shared object, ARM aarch64,
ELF 64-bit LSB shared object, x86-64,
ELF 64-bit MSB executable, 64-bit PowerPC or cisco 7500,
```

While x86/64 can be run on my machine to drop the next binaries, arm and powerpc need to be emulated. `angr` can handle with solving constraints for all these.

On the other hand the file `surprise` dropped is a `bzip2` file and is calculated by xoring the input. `bzip2` has a pretty predictable structure that can help us recover the key without caring about the symbolic execution to calculate the inputs from `check1` and `check2`. I eventually resorted to this technique as one of the iterations had weak constraints.

Here's how the `bzip2` files look like

```bash
[inctf-surp] hd 1.bz2 | head -n 4
00000000  42 5a 68 39 31 41 59 26  53 59 0c 49 a7 2b 06 47  |BZh91AY&SY.I.+.G|
00000010  e8 ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
00000020  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
00000030  ff ff ff e1 8d df 3b bd  57 95 44 af af 4b de ee  |......;.W.D..K..|
[inctf-surp] hd 2.bz2 | head -n 4
00000000  42 5a 68 39 31 41 59 26  53 59 16 f6 e7 a8 06 47  |BZh91AY&SY.....G|
00000010  82 ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
00000020  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
00000030  ff ff ff e1 8d b6 f7 bd  67 b3 dd cb b7 af 3d ed  |........g.....=.|
[inctf-surp] hd 3.bz2 | head -n 4
00000000  42 5a 68 39 31 41 59 26  53 59 28 d7 4e a8 06 48  |BZh91AY&SY(.N..H|
00000010  36 7f ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |6...............|
00000020  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
00000030  ff ff ff e1 8d df 3d 9e  fb 3e bd b7 bc d7 6e 9e  |......=..>....n.|
```

The header is somewhat predictable - `425a6839314159265359`

```
.magic:16                       = 'BZ' signature/magic number
.version:8                      = 'h' for Bzip2 ('H'uffman coding), '0' for Bzip1 (deprecated)
.hundred_k_blocksize:8          = '1'..'9' block-size 100 kB-900 kB (uncompressed)
.compressed_magic:48            = 0x314159265359 (BCD (pi))
```
Not just that it has a bunch of 0xff's which can be used to calculate the key. We can script this with [r2pipe](https://github.com/radareorg/radare2-r2pipe)

```python
import r2pipe
import subprocess
import struct
import string
import sys

def fix(i):
    # convert QWORDs to bytes and dump to file for backup
    cont = open("/tmp/new/%d.bin" % i, 'rb').read()
    w =  open("/tmp/new/%d-fix.bin" % i, 'wb')
    # powerpc is MSB, arm, x86 is LSB
    endian = "<Q"
    if struct.unpack(endian, cont[0:8])[0] > 255:
        endian = ">Q"
    for i in range(0,len(cont), 8):
        w.write(bytes([struct.unpack(endian, cont[i:i+8])[0]]))
    w.close()

def dec(i):
    # decrypt the file using the 0xff's
    cont = open("/tmp/new/%d-fix.bin" % i, 'rb').read()
    key = [0xff ^ cont[i] for i in range(26, 39)]
    space = set(string.ascii_lowercase+string.ascii_uppercase+string.digits+"+=/")
    for k in key:
        if chr(k) not in space:
            print("fucked up : %s" % ("".join(map(chr,key))))
            sys.exit(1)
    print("Key %d ::: %s" % (i,"".join(map(chr,key))))
    w =  open("/tmp/new/%d-dec.elf" % i, 'wb')
    for idx, c in enumerate(cont):
        w.write(bytes([key[idx%13]^c]))
    w.close()

i = int(sys.argv[1])
while True:
    subprocess.check_output(["cp", "surprise", "/tmp/new/%d.bz2" % i])
    subprocess.check_output(["bzip2", "-dfk", "surprise"])
    subprocess.check_output(["cp", "/tmp/new/surprise.out", "/tmp/new/%d.out" % i])
    r2 = r2pipe.open("/tmp/new/%d.out" % i)
    r2.cmd('aaa')
    # locate the .data in the ELF
    for section in r2.cmdj("iSj"):
        if section["name"] == ".data":
            vaddr = section["vaddr"]
            size = section["size"]
    r2.cmd("s %d" % vaddr)
    start = vaddr
    # non stripped files have the bin symbol for the file bytes
    bin_addr = 0
    sym_bin = r2.cmd("is~bin[2]~:1").strip()
    if sym_bin != "":
        print("Symbol bin"+sym_bin)
        bin_addr = int(sym_bin, 16)
    else:
        # stripped files have bytes stored in QWORDs
        while True:
            word = int(r2.cmd("pxWq @ 0x%x~:0" % start).strip(), 16)
            if word:
                w1 = int(r2.cmd("pxWq @ 0x%x~:0" % (start+4)).strip(), 16)
                w2 = int(r2.cmd("pxWq @ 0x%x~:0" % (start+12)).strip(), 16)
                w3 = int(r2.cmd("pxWq @ 0x%x~:0" % (start+20)).strip(), 16)
                w4 = int(r2.cmd("pxWq @ 0x%x~:0" % (start+28)).strip(), 16)
                if w1 == 0 and w2 == 0 and w3 == 0 and w4 == 0:
                    bin_addr = start
                    break
            start += 4
    assert(bin_addr!=0)

    r2.cmd("s %d" % bin_addr)
    r2.cmd("wtf %d.bin %d" % (i, size-(bin_addr - vaddr)))
    # read the encrypted file
    fix(i)
    # decrypt and save the file
    dec(i)
    subprocess.check_output(["cp", "/tmp/new/%d-dec.elf" % i, "surprise"])
    i += 1
    print(f"done {i}")
```

When this file is run it'll continue to solve for keys and dump the next files. On the last iteration, an elf is dropped from an arm binary which can be solved using angr and emulated using [qiling](https://github.com/qilingframework/qiling)

```python
from angr import Project, SimProcedure
import sys
import subprocess
import json
import claripy
elf = sys.argv[1]
x = subprocess.check_output(
    ["r2", "-AAA", "-qq", "-c", "pdbj @@=`axt sym.imp.puts ~[1]`", elf])
locate = []
for line in x.split(b"\n")[:2]:
    print(json.loads(line)[0]["offset"])
    locate.append(int(json.loads(line)[0]["offset"]))

p = Project(elf)
flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(15)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

base = 0x400000

for target in locate:
    state = p.factory.entry_state(stdin=flag)
    for k in flag_chars:
        state.solver.add(k >= 0x31)
        state.solver.add(k < 0x7f)
    for ii in "?@":
        state.solver.add(k != ord(ii))

    ex = p.factory.simulation_manager(state)
    ex.explore(find=base+target)
    if ex.found:
        solution_state = ex.found[0]
        inp = solution_state.posix.dumps(sys.stdin.fileno())
        print(inp)
```

yields inctf{x32_x64_ARM_MAC_powerPC_4rch_maz3_6745}

#### jazz

~15 solves

rust compiled binary with name `jazz::main`. The function is a little complex to look at

![main](https://i.imgur.com/QwOmPNi.png)

Here I have used [lighthouse](https://github.com/gaasedelen/lighthouse) to get some coverage information from some testcases. Decompilation doesn't yield much. We can use a pintool to taint and track the input from `argv[1]` to this function.

This takes us to this code

![sbox](https://i.imgur.com/VXUeFZ1.png)

Bytes from `argv[1]` are used as indexes to read from from an array in an `sbox` like fashion. There were 0x25 sboxes and input was translated as

```c
output = malloc(strlen(input))
for(i = 0; i < strlen(input); i++){
    output[i] = sbox[input[i%0x25]]
}
```

This `output` can then be followed to a `crypto::aes::cbc_encryptor`. While debugging I found out that the key and IV was static and dumped it with gdb. After the encryption if the encrypted output is matched with a hardcoded buffer.

All these sboxes, key, iv and final buffer can be dumped in a gdb session.

```python
arr = [0xbc, 0xc0, 0x0a, 0xbc, 0x5e, 0xf9, 0xb6, 0xd5, 0xc5, 0x08, 0x4d, 0xb1, 0x55, 0x09, 0x34, 0x95, 0x12, 0xce, 0x67, 0x08, 0xfb, 0x8a, 0xf1, 0xd2, 0x1a, 0xd8, 0x2b, 0x64, 0x28, 0xc2, 0x39, 0x72, 0xb4, 0x42, 0x68, 0x7a, 0x38, 0x23, 0xcf, 0x04, 0x90, 0x34, 0x98, 0xe1, 0xe8, 0xb0, 0x0c, 0x69, 0x1d, 0x22, 0xb9, 0x61, 0x1f, 0x17, 0x2a, 0x5d, 0xe1, 0xff, 0x5c, 0x7d, 0x31, 0xbe, 0x1a, 0x6b, 0xd7, 0x1f, 0xa2, 0x43, 0x18, 0xab, 0xcc, 0x57, 0xd0, 0x8d, 0x5f, 0xcc, 0x43, 0x2c, 0x43, 0x69, 0x96, 0xec, 0xce, 0x78, 0xa9, 0x06, 0xdd, 0x8e, 0x11, 0xa1, 0xfe, 0xca, 0x34, 0x0b, 0x90, 0xcb]
key = [0xec, 0xad, 0xe9, 0x18, 0xdb, 0xfa, 0xbf, 0x53, 0x03, 0x4f, 0x65, 0x4b, 0xef, 0x52, 0x32, 0x92, 0xae, 0xc1, 0xc4, 0xd0, 0x13, 0xdd, 0x5d, 0x28, 0x05, 0xea, 0x53, 0x97, 0x14, 0xe0, 0x6d, 0xd1]
iv = [0xd7, 0x1c, 0x2d, 0x1b, 0x9b, 0x71, 0xfb, 0x9e, 0xae, 0x77, 0x75, 0x64, 0x01, 0x6c, 0xfa, 0x3a]

from Crypto.Cipher import AES

sbox = []

"""
dump memory 1 0x5555555a2d80 0x5555555a2d80+0x100
dump memory 2 0x5555555a2eb0 0x5555555a2eb0+0x100
dump memory 3 0x5555555a3000 0x5555555a3000+0x100
dump memory 4 0x5555555a3180 0x5555555a3180+0x100
dump memory 5 0x5555555a3290 0x5555555a3290+0x100
dump memory 6 0x5555555a3470 0x5555555a3470+0x100
dump memory 7 0x5555555a3580 0x5555555a3580+0x100
dump memory 8 0x5555555a3690 0x5555555a3690+0x100
dump memory 9 0x5555555a37a0 0x5555555a37a0+0x100
dump memory 10 0x5555555a3a40 0x5555555a3a40+0x100
dump memory 11 0x5555555a3b50 0x5555555a3b50+0x100
dump memory 12 0x5555555a3c60 0x5555555a3c60+0x100
dump memory 13 0x5555555a3d70 0x5555555a3d70+0x100
dump memory 14 0x5555555a3e80 0x5555555a3e80+0x100
dump memory 15 0x5555555a3f90 0x5555555a3f90+0x100
dump memory 16 0x5555555a40a0 0x5555555a40a0+0x100
dump memory 17 0x5555555a41b0 0x5555555a41b0+0x100
dump memory 18 0x5555555a45d0 0x5555555a45d0+0x100
dump memory 19 0x5555555a46e0 0x5555555a46e0+0x100
dump memory 20 0x5555555a47f0 0x5555555a47f0+0x100
dump memory 21 0x5555555a4900 0x5555555a4900+0x100
dump memory 22 0x5555555a4a10 0x5555555a4a10+0x100
dump memory 23 0x5555555a4b20 0x5555555a4b20+0x100
dump memory 24 0x5555555a4c30 0x5555555a4c30+0x100
dump memory 25 0x5555555a4d40 0x5555555a4d40+0x100
dump memory 26 0x5555555a4e50 0x5555555a4e50+0x100
dump memory 27 0x5555555a4f60 0x5555555a4f60+0x100
dump memory 28 0x5555555a5070 0x5555555a5070+0x100
dump memory 29 0x5555555a5180 0x5555555a5180+0x100
dump memory 30 0x5555555a5290 0x5555555a5290+0x100
dump memory 31 0x5555555a53a0 0x5555555a53a0+0x100
dump memory 32 0x5555555a54b0 0x5555555a54b0+0x100
dump memory 33 0x5555555a55c0 0x5555555a55c0+0x100
dump memory 34 0x5555555a5ce0 0x5555555a5ce0+0x100
dump memory 35 0x5555555a5df0 0x5555555a5df0+0x100
dump memory 36 0x5555555a5f00 0x5555555a5f00+0x100
dump memory 37 0x5555555a6010 0x5555555a6010+0x100
"""
for i in xrange(1,38):
    sbox.append(open("%d" % i, "rb").read())

cipher = AES.new("".join(map(chr,key)), AES.MODE_CBC, "".join(map(chr,iv)))
x = cipher.decrypt("".join(map(chr, arr)))
print "".join(map(chr,[sbox[i%0x25].index(c) for i,c in enumerate(x)]))
```

yields inctf{fly_m3_70_7h3_m00n_l37_m3_pl4y_4m0n6_7h3_574r5_4nd_l37_m3_533_wh47_5pr1n6_15_l1k3}

####  RE warmup

~30 solves

```bash
[warm] file warmup
warmup: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=f9f27d58a31e0dd6c85af549c97a274bb95e5093, stripped
```

Although its stripped but On opening it in IDA, Lumina found out and renamed a lot of functions. This meant its a known binary. On running it

```
[warm] ./warmup -v
GNU strings (GNU Binutils) 2.35
Copyright (C) 2020 Free Software Foundation, Inc.
This program is free software; you may redistribute it under the terms of
the GNU General Public License version 3 or (at your option) any later version.
This program has absolutely no warranty.
[1]    24231 segmentation fault (core dumped)  ./warmup -v
```

We see that the binary is is actually binutils strings and crashes for some reason. I built the same version of strings and started renaming the global variables required to analyze `main`.

This shows that an additional flag `-z` has been added to strings
```c
case 'z':
    dword_7ECB88 = 1;
```

The crash is in a function referenced in `fini_array` when it tries to call puts on a null ptr. Looking for xrefs to some of the pointers and `dword_7ECB88` we see that they are only mentioned in 3 functions - `crash`, `main` and `print_strings`. `print_strings` from binutils had been modified to add some code around `dword_7ECB88`.

Looking at the `crash`(sub_400E10) function shows some xor operations being performed and comparison to a hardcoded string - `char byte_571B08[45]`

```
"".join(map(chr, [(i^j-(65-(66%(i+1)))) for i, j in enumerate(x[:44])]))
```
yields the flag

#### P1Ayground

~10 solves

This was the last chall I tried.

```
[/tmp] file Win_chal.exe
Win_chal.exe: PE32 executable (GUI) Intel 80386, for MS Windows
```

Sadly I couldn't run it unless I setup debug libraries. I proceeded to RE it statically.

Looking for god/bad boy messages in strings take us to a couple of different locations - One of which is very simple and on solving says that its a fake.

Other location that xref's the input is `sub_416090`. The flag verification is broken into a couple of functions

##### sub_416090

1. Reads 2 consecutive bytes from the flag removing the inctf{} i.e flag[6:-1]
1. Looks them up in 2 tables - like an inverse sbox. Tables are 8*8 with alphabets+digits+!_
1. Uses the (i,j) location pair to mix and read bytes from 2 other hardcoded 8*8 tables

This gives out `sbox_location` array of len `strlen(flag[6:-1])` should be 0x39.

##### sub_416370

1. Sets up a bool 26*strlen(sbox_location) table - `char_location`
1. xors `sbox_location` with a static array = `xor_sbox_location` = the bytes are now in a-z range
1. Sets true to the `char_location` table for the bytes in `xor_sbox_location`
1. Calulates sum of 2**i for each byte in `xor_sbox_location`. Since only one value is set to true this means only one bit is set for this sum.

##### sub_416600

1. Compares the 2 power sum to static values in the binary.

Each of these can be trivially reversed to this

```python
from math import log2
# 2raised array
pw = [0x00400000, 0x00004000, 0x00000002, 0x00040000, 0x00002000, 0x00000001, 0x00000800, 0x00000040, 0x00010000, 0x00000100, 0x00080000, 0x02000000, 0x00040000, 0x00008000, 0x00010000, 0x02000000, 0x00001000, 0x00000800, 0x00000200, 0x00004000, 0x00000020, 0x00000200, 0x00000100, 0x00004000, 0x00010000, 0x00200000, 0x00080000, 0x00040000, 0x00000080, 0x00800000, 0x00000800, 0x00008000, 0x00000008, 0x00000040, 0x00002000, 0x00040000, 0x00000400, 0x00000200, 0x00002000, 0x00000020, 0x00002000, 0x00010000, 0x00400000, 0x00000008, 0x00000010, 0x00000020, 0x00000200, 0x00010000, 0x00000001, 0x02000000, 0x01000000, 0x00008000, 0x00040000, 0x00800000, 0x00002000, 0x00200000]
w = list(map(lambda x: int(log2(x))+97, pw))
# xor_sbox_location
xw = [0x00000039, 0x00000027, 0x0000001B, 0x00000019, 0x00000028, 0x00000017, 0x0000003E, 0x0000003F, 0x00000040, 0x00000030, 0x0000002C, 0x0000003D, 0x0000003F, 0x00000041, 0x00000042, 0x0000004B, 0x0000005C, 0x00000009, 0x0000000C, 0x00000005, 0x0000003C, 0x00000004, 0x00000007, 0x00000009, 0x00000020, 0x00000029, 0x00000038, 0x00000018, 0x0000003A, 0x00000001, 0x0000002B, 0x00000009, 0x00000031, 0x00000010, 0x00000018, 0x00000047, 0x0000000F, 0x00000012, 0x0000003D, 0x00000014, 0x0000002A, 0x00000022, 0x00000030, 0x0000001D, 0x00000029, 0x00000017, 0x00000020, 0x00000017, 0x00000003, 0x00000012, 0x00000036, 0x00000013, 0x00000052, 0x0000001D, 0x0000005F, 0x00000013]

# sboxes
a = "\x39\x69\x62\x50\x77\x52\x33\x6B\x65\x6A\x5A\x4F\x70\x64\x5F\x72\x63\x4E\x21\x6E\x4B\x36\x41\x46\x37\x34\x49\x4D\x32\x42\x48\x31\x68\x66\x54\x56\x51\x4C\x61\x71\x7A\x35\x75\x55\x47\x6C\x38\x6D\x74\x6F\x45\x78\x53\x4A\x44\x57\x67\x43\x73\x59\x58\x79\x30\x76\x00"
b = "\x55\x48\x46\x42\x36\x6C\x67\x37\x66\x6E\x53\x50\x5F\x4A\x73\x21\x6B\x72\x59\x45\x33\x69\x32\x65\x71\x75\x4E\x4F\x4C\x63\x34\x74\x44\x78\x4D\x35\x62\x77\x57\x4B\x58\x6D\x64\x68\x54\x6F\x43\x30\x52\x7A\x5A\x70\x51\x6A\x47\x49\x79\x38\x31\x56\x76\x61\x39\x41\x00"
c = "\x38\x57\x6D\x4C\x62\x7A\x46\x71\x65\x6B\x36\x75\x49\x56\x48\x35\x6C\x4F\x45\x37\x67\x39\x64\x43\x79\x53\x47\x73\x54\x6A\x77\x58\x6E\x51\x6F\x59\x76\x4A\x72\x4B\x4D\x34\x32\x5F\x69\x52\x4E\x21\x68\x42\x44\x31\x41\x30\x66\x33\x70\x55\x78\x61\x74\x50\x5A\x63\x00"
d = "\x34\x31\x52\x35\x73\x6F\x37\x7A\x21\x39\x33\x70\x63\x67\x54\x6E\x53\x49\x62\x76\x69\x57\x4F\x78\x5F\x65\x47\x75\x66\x44\x68\x51\x56\x4A\x30\x64\x32\x46\x6A\x55\x79\x4C\x38\x4D\x72\x71\x41\x5A\x36\x45\x42\x59\x61\x43\x4E\x4B\x77\x6B\x58\x6C\x48\x50\x74\x6D\x00"

f = [i^j for i, j in zip(xw,w)]
s = ""
for i in range(0, len(f), 2):
    idx1 = b.index(chr(f[i]))
    idx2 = c.index(chr(f[i+1]))
    q1, r1 = int(idx1/8) , idx1%8
    q2, r2 = int(idx2/8) , idx2%8
    s += a[8*q1+r2]+d[8*q2+r1]
print(s)
```

reveals H3y_w0W_Y0u_Manag3d_t0_Exr4ct_th3_CruX_0f_th1s_Cha1leng3
