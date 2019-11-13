
---
layout: post
title: "CSAW CTF Finals 2019 mystery boi rev-400 writeup"
date: 2019-11-22 10:10:00 +0530
categories: blog
tags: [reversing, ida, pintool]
---

Description

```
who am I? none of your business

nc ip port
```
No binary is provided. However 2 files `launcher.py` and `Dockerfile` were
attached.

```python
url = input("Where are you sending me this from?>>>")

r = requests.get(url, stream=True)

tmpfile_path = "/tmp/" + str(uuid.uuid4())

with open(tmpfile_path, "wb") as f:
    for chunk in r.iter_content(chunk_size=1024):
        if chunk:
            f.write(chunk)

st = os.stat(tmpfile_path)
env = {"LD_PRELOAD": tmpfile_path}

subprocess.run("./mystery_boi", env=env)
```

According to this a file can be provided which will be loaded in the process
using `LD_PRELOAD`.

Making some assumptions on the binary such as x64, we compiled a small shared
object that called `system("/bin/sh")` when loaded.

For this we implemented `__libc_start_main` in the so and sent it to the server.
We got a shell and found a ELF `mystery_boi` and multiple other small files -
boi0, boi1 ..., boi26 - we'll call the bois for now.

We wrote other .so that reads and hex-dumps out files to stdout. This file is
loosely based on the challenge author's
[own](https://github.com/Tnek/dumb-unpacker/blob/master/fake.c)

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdint.h>

#define DEBUG

void dump(char*fl){
    int64_t i, sz;
    FILE *fp = fopen(fl, "r");
    if (fp == NULL) {
        perror("Failed: ");
        return;
    }
    fseek(fp, 0L, SEEK_END);
    sz = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    for(i=0; i < sz; ++i)
        printf("%02x", fgetc(fp));
    putchar(10);
    fclose(fp);
}

int __libc_start_main(int *(main) (int, char * *, char * *),
        int argc,
        char * * ubp_av,
        void (*init) (void),
        void (*fini) (void),
        void (*rtld_fini) (void),
        void (* stack_end)) {

    char filename[100];
    int64_t sz;
    while(1){
        scanf("%s", filename);
        dump(filename);
    }

    void *dls_handle;
    if ( !(dls_handle = dlopen("libc.so.6", RTLD_LAZY)) ) {
#ifdef DEBUG
        printf("Failed to load grab libc.so.6");
#endif
        exit(EXIT_FAILURE);
    }

    typeof(__libc_start_main) *old_libc_start_main;
    old_libc_start_main = dlsym(RTLD_NEXT, "__libc_start_main");

    return old_libc_start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}
```

Pairing it with this pwntools script, we get all the files.
```python
for i in "boi0 boi1 boi10 boi11 boi12 boi13 boi14 boi15 boi16 boi17 boi18 boi19 boi2 boi20 boi21 boi22 boi23 boi24 boi25 boi26 boi3 boi4 boi5 boi6 boi7 boi8 boi9 mystery_boi".split():
    s.sendline(i)
    print s.recvline()
    open(i, "w").write(s.recvline().strip().decode("hex"))
```

All bois are small with no particular format, they mostly look like x64
code
```bash
$ file boi*
boi0:  data
boi1:  data
boi10: data
...
$ file mystery_boi
mystery_boi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, BuildID[sha1]=1d460017e491a2a609549c68299c7654505490c2, for GNU/Linux 3.2.0, stripped
```

Loading mystery_boi in ida, `main` doesn't have much code. A function has been
referenced in `_init_array`. It has code similar to this

```c
  handle = dlopen("libc.so.6", 1);
  if ( !handle )
  {
    write(1, "Nice try but my LD gongfu is stronger than your LD gongfu\n", 0x3AuLL);
    exit(1);
  }
  v0 = dlsym(handle, "mmap");
  if ( v0 != dlsym((void *)0xFFFFFFFFFFFFFFFFLL, "mmap") )
  {
    write(1, "Nice try but my LD gongfu is stronger than your LD gongfu\n", 0x3AuLL);
    exit(1);
  }
```
These checks go on for a lot of functions which were imported.

Another function is called from this function that verifies the hash of
.text section
```c
  curr = (unsigned __int8 *)&start;
  hash = 0;
  v2 = 0;
  v3 = 0;
  while ( curr != (unsigned __int8 *)0x401BED )
  {
    if ( v3 == 8 )
    {
      hash ^= v2;
      v2 = 0;
      v3 = 0;
    }
    v2 = (v2 << 8) | (unsigned __int8)*(_DWORD *)curr;
    ++v3;
    ++curr;
  }
  result = text_hash;
  if ( hash != text_hash )
```

This is probably done to test any software breakpoints set in the `.text`.
Based on the hash comparison it creates a thread with another function.

```c
  boi_count = 0;
  if ( !ptrace(0, 0LL, 1LL, 0LL) )              // This should return 0 if no debugger is attached
    boi_count = 1;
  if ( ptrace(0, 0LL, 1LL, 0LL) == -1 )         // This should return -1 as its the second ptrace in the binary
    boi_count *= 2;
  strcpy(boi, "boi0");
  boi[3] += boi_count;
  v1 = open(boi, 0);
  handle_boi(v1, ctx);
```

When run without a debugger `boi2` is the first to get loaded in the elf. bois
work upon a vm context passed as `ctx` here. The context has general purpose
regsiters, call stack, instruction pointers, different opcodes to red flag,
check length, verify bytes - correct/incorrect. To analyze all bois in IDA we
load them up in the same IDB and create structs and enums for the VM. This takes
the most time in a VM based challenge.

Here's the script to load all the bois to page aligned functions in the current
idb of `mystery_boi`

```python
import sys
import logging
from collections import namedtuple

import idc
import idaapi
import idautils

logger = logging.getLogger(__name__)

Segment = namedtuple('SegmentBuffer', ['path', 'name', 'addr'])

start = 0x405000
for j in xrange(27):
    i = "boi%d" % j
    seg = Segment(r"Z:\home\sudhakar\Desktop\csaw\%s" % (i), i, start)
    with open(seg.path, 'rb') as f:
        buf = f.read()

    seglen = len(buf)
    if seglen % 0x1000 != 0:
        seglen = seglen + (0x1000 - (seglen % 0x1000))
    print hex(start)
    start += seglen
    if not idc.AddSeg(seg.addr, seg.addr + seglen, 0, 1, 0, idaapi.scPub):
        logger.error('failed to add segment: 0x%x', seg.addr)
        sys.exit()

    if not idc.RenameSeg(seg.addr, seg.name):
        logger.warning('failed to rename segment: %s', seg.name)

    if not idc.SetSegClass(seg.addr, 'CODE'):
        logger.warning('failed to set segment class CODE: %s', seg.name)

    idc.SetSegAddressing(seg.addr, 2)

    if not idc.SegAlign(seg.addr, idc.saRelPara):
        logger.warning('failed to align segment: %s', seg.name)

    idaapi.patch_many_bytes(seg.addr, buf)
    idc.MakeCode(seg.addr)
    idc.MakeFunction(seg.addr)
    pt = idc.parse_decl("int %s(ctx* ctx_t)" % i, idc.PT_SILENT)
    idc.set_name(seg.addr, i)
    idc.ApplyType(seg.addr, pt)
```

This creates multiple segments in ida - one for each boi, marks that as a
function and sets the proper prototype. `ctx` is something like

```
struct ctx
{
  void *code_mmap;
  void *stack;
  int *fd_stack;
  int current_boi;
  int * flag;
  __int64 registers[13];
};
```
Now we can disassemble and decompile all bois. `boi2` starts the execution,
`boi1` is the win and `boi0` is the lose function. `boi4` reads the flag. `boi5`
checks the length of the flag.

Each boi has multiple `if` conditions for different opcodes, state and call
stack of the VM. Here's an example for `boi2`

```c
  v1 = a1;
  jump_flag_local = a1->registers[5];
  if ( jump_flag_local == vm_actions_check_length )
  {
    v6 = a1->fd_stack;
    a1->fd_stack = v6 + 1;
    v6[1] = a1->current_boi;
    __asm { syscall; LINUX - sys_open }
    result = 2LL;
    a1->current_boi = 2;
    return result;
  }
  if ( jump_flag_local <= vm_actions_check_length )
  {
    if ( !jump_flag_local )
    {
      a1->registers[0] = 32LL;
      v5 = a1->fd_stack;
      a1->fd_stack = v5 + 1;
      v5[1] = a1->current_boi;
      __asm { syscall; LINUX - sys_open }
      result = 2LL;
      a1->current_boi = 2;
      return result;
    }
  }
  else
  {
    if ( jump_flag_local == 2 )
    {
      a1->registers[ctx_registers_state] = 4LL;
      a1->registers[3] = 0LL;
      v7 = a1->current_boi;
      __asm
      {
        syscall; LINUX - sys_close
        syscall; LINUX - sys_open
      }
      result = 2LL;
      a1->current_boi = 2;
      return result;
    }
    if ( jump_flag_local == vm_actions_fail_boi_0 )
    {
      v3 = a1->fd_stack;
      a1->fd_stack = v3 + 1;
      v3[1] = a1->current_boi;
      __asm { syscall; LINUX - sys_open }
      result = 2LL;
      a1->current_boi = 2;
      return result;
    }
  }
  v8 = a1->current_boi;
  __asm { syscall; LINUX - sys_close }
  v9 = v1->fd_stack;
  result = (unsigned int)*v9;
  v1->current_boi = result;
  v1->fd_stack = v9 - 1;
  return result;
```
control is transferred by returning the next fd/boi to be executed which the
handler function then writes to the code page and calls it with `ctx`.

```c
  fd = a1;
  v4 = a2;
  result = (ssize_t)a2;
  a2->current_boi = a1;
  while ( fd != -1 )
  {
    lseek(fd, 0LL, 0);
    v3 = v4->code_mmap;
    result = read(fd, v4->code_mmap, 0x1FFFuLL);
    if ( result )
    {
      result = ((__int64 (__fastcall *)(ctx *, void *))v4->code_mmap)(v4, v3);
      fd = result;
    }
  }
  return result;
```
There were around 10 states and 10 registers to reverse.
The solution is based around the source code that was released
[here](https://github.com/osirislab/CSAW-CTF-2019-Finals/tree/master/rev/mystery_boi/distribute)
after the CTF.
