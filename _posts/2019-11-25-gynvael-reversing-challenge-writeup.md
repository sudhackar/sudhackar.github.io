---
layout: post
title: "Gynvael's Reversing Challenge Writeup"
date: 2019-11-22 10:10:00 +0530
categories: blog
tags: [reversing, ida, pintool]
---

[gynvael](https://twitter.com/gynvael) submitted a challenge for winja CTF which was held onsite at [Nullcon](https://nullcon.net/website/) 2018. AFAIK no team there was able to solve it. 

While looking at my inbox recently I found the challenge files and finally decided to give it a try. I don't have a description of the chall, just have the file. It was a reversing challenge and a pyc was provided.

```sh
$ file risky.pyc
risky.pyc: python 2.7 byte-compiled
```

This can be very accurately decompiled with [uncompyle](https://pypi.org/project/uncompyle/)

```
$ uncompyle6 risky.pyc > /tmp/risky.py
```

This file accepts flag as arg1, checks the arch and os, flag length and characters.

```python
if platform.system() != 'Linux' or platform.architecture()[0] != '64bit' or sys.version_info.major != 2 or sys.version_info.minor != 7:
    sys.exit('This application requires a 64-bit Python 2.7 running on Linux.')
if len(sys.argv) != 2:
    sys.exit('usage: risky.py <flag>')
flag = sys.argv[1]
if len(flag) >= 32:
    sys.exit('Meh.')
alphabet = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}')
for ch in flag:
    if ch not in alphabet:
        sys.exit('No.')
```

After this a marshalled string is loaded which implements a `check` function

```python
loader = types.FunctionType(marshal.loads(loader), globals())
loader()
if check(flag):
    print 'Well done!'
else:
    print 'Nope.'
```

This can also be decompiled using uncompyle

```python
import marshal
x = marshal.loads(loader)
from uncompyle6.main import decompile
decompile(2.7,s,sys.stdout)
```

This code is like an elf loader. It contains an elf in string, `mmaps` pages for code and stack and then calls them using `ctypes`

```python
from ctypes import *
libc = CDLL('libc.so.6')
mmap_type = CFUNCTYPE(c_void_p, c_void_p, c_ulong, c_int, c_int, c_int, c_ulong)
mmap = cast(libc.mmap, mmap_type)
memcpy_type = CFUNCTYPE(None, c_void_p, c_void_p, c_ulong)
memcpy = cast(libc.memcpy, memcpy_type)
text = mmap(1107296256, 4096, 7, 50, -1, 0)
data = mmap(1107300352, 36864, 7, 50, -1, 0)
text_sz = 2680
data_sz = 12328
memcpy(text, create_string_buffer(prog[4096:4096 + text_sz]), text_sz)
memcpy(data + text_sz, create_string_buffer(prog[4096 + text_sz:4096 + text_sz + data_sz]), data_sz)
func_type = CFUNCTYPE(c_int, c_void_p)
func = cast(1107298560, func_type)

def check(s):
    s = s.ljust(32, '\x00')
    return func(create_string_buffer(s))
```

So this is the final `check` function implemented in an elf. It is also the entry point for the elf. 

```sh
$ file elf 
elf: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
$ r2 -AAA -qq -c ie elf
[Entrypoints]
vaddr=0x42000900 paddr=0x00001900 haddr=0x00000018 hvaddr=0x42000018 type=program

1 entrypoints
```

The binary won't be able to run normally as the entry - `check` function expects a `char *` which should be in `rdi` but it actually gets `int argc` and `char **argv` on the stack.

Opening in IDA shows 4 more functions, one of which `0x42000000` is actually `memcpy`.
The `start` or `check` function reads the flag into a struct and initializes some vars and then calls `sub_42000290`. The struct initialized is passed as arg to the function and one of its member decides the return value of `check`.

Now `sub_42000290` is a pretty huge function by itself. It has a lot of weird shifts and other bitwise arithmetic

![cfg](https://i.imgur.com/QBGsf7E.png)

```c
v31 = (v44 >> 15) & 0x1F;
v32 = (v44 >> 20) & 0x1F;
v33 = (v44 >> 31 << 12) | (v44 >> 7) & 0x1E | 16 * (_WORD)v44 & 0x800 | (v44 >> 20) & 0x7E0;
v21 = 0xFFFFE000 * (v33 >> 12) | v33;
```
At the start of this function some static bytes are retrieved from the `.data` and decoded using the above logic spread across around 300 lines of decompiled C.

This usually suggests that some VM has been implemented and the code is trying to decode opcode, registers, immediate etc. Based on the value of operation - there were multiple operations involved - add, sub, or, xor, load, store, shift, jump, branch etc.

The VM was pretty intensive and it has 32 registers. While solving such tasks in CTFs I usually implement a pintool and instrument the position where instructions are decoded and operations are performed. This usually involves going to and fro between IDA and the pintool source.

With this I was able to figure out the decoding scheme of some of the instructions as such.

```c
reg_dest = (instruction >> 7) & 0x1F;
reg_src1 = (instruction >> 15) & 0x1F;
operation = 8 * (instruction >> 25) | (v42 >> 12) & 7;
reg_src2 = (instruction >> 20) & 0x1F;
```

I spend more than a good hour to implement the pintool for all operations and trying to debug the VM. For the context struct I started naming variables as they were needed.

```c
struct __attribute__((aligned(8))) ctx
{
  __int64 a0_init1000;
  __int64 regs[32];
  void *a33;
  void *a34;
  void *a35;
  void *a36;
  void *a37;
  void *a38;
  void *a39;
  void *instruction_pointer;
  __int64 a41;
  __int64 a42;
  __int64 a43;
  void *a44;
  ...
};
```

While I was working on the VM opcodes I tried to google some opcodes to see if such a VM has already been implemented. I found out that it was a RISC-V VM and specs matched the analysis I had done on the decoding and operation.

Since I was almost there I decided to write a working RISC-V disassembler based on the binary and the spec sheet. This worked quite well and I was able to introspect the VM. 

For completeness here's the pintool which I used finally with some debug statements. If you use this code please verify/test it. YMMV.

```c
#include "pin.H"
#include <fstream>
#include <stdio.h>

using namespace std;
PIN_LOCK globalLock;
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "pin.out",
                            "specify output file name");
ofstream outFile;
ADDRINT l, h;

VOID dump_dis(UINT64 insAddr, std::string insDis) {
    outFile << std::hex << insAddr << " : " << insDis << endl;
}

VOID log_cpy(CONTEXT *ctx) {
    PIN_REGISTER rdx, rdi, rsi;
    PIN_GetContextRegval(ctx, REG_RDX, reinterpret_cast<UINT8 *>(&rdx));
    PIN_GetContextRegval(ctx, REG_RSI, reinterpret_cast<UINT8 *>(&rsi));
    PIN_GetContextRegval(ctx, REG_RDI, reinterpret_cast<UINT8 *>(&rdi));
    outFile << std::hex << "memcpy(" << rdi.qword[0] << ", " << rsi.qword[0]
            << ", " << rdx.qword[0] << ")" << std::dec << endl;
    if (rsi.qword[0] >= 0x42004A80 && rsi.qword[0] <= 0x42004A9F)
        outFile << "Flag Read idx : " << rsi.qword[0] - 0x42004A80 << endl;
    if (rsi.qword[0] >= 0x42002CA0 && rsi.qword[0] <= 0x42002CBF)
        outFile << "Hash Read idx : " << rsi.qword[0] - 0x42002CA0 << endl;
    if (rsi.qword[0] >= 0x42002AA0 && rsi.qword[0] < 0x42002BA0)
        outFile << "Table Read idx : " << rsi.qword[0] - 0x42002AA0 << endl;
    if (rsi.qword[0] >= 0x42002BA0 && rsi.qword[0] < 0x42002CA0)
        outFile << "Bool Read idx : " << rsi.qword[0] - 0x42002BA0 << endl;
    if (rdi.qword[0] >= 0x42005280 && rdi.qword[0] <= 0x4200529F)
        outFile << "Hash Write idx : " << rdi.qword[0] - 0x42005280 << endl;
    if (rsi.qword[0] >= 0x42005280 && rsi.qword[0] <= 0x4200529F)
        outFile << "Temp Hash Read idx : " << rsi.qword[0] - 0x42005280 << endl;
}

void log_ins(CONTEXT *ctx) {
    ADDRINT value;
    PIN_REGISTER rdx, rbx;
    int i = 0;
    PIN_GetContextRegval(ctx, REG_RDX, reinterpret_cast<UINT8 *>(&rdx));
    PIN_GetContextRegval(ctx, REG_RBX, reinterpret_cast<UINT8 *>(&rbx));
    PIN_GetLock(&globalLock, 1);
    for (; i < 32; i++) {
        ADDRINT *op2 = (ADDRINT *)(rbx.qword[0] + 0x8 + i * 8);
        PIN_SafeCopy(&value, op2, sizeof(ADDRINT));
        if (value)
            outFile << "r" << i << " : " << std::hex << value << std::dec
                    << endl;
    }
    PIN_ReleaseLock(&globalLock);

    // outFile << std::hex << rdx.dword[0] << endl;
    uint32_t opcode, instruction, f3, f7, rd, rs1, rs2, imm, shamt;
    instruction = rdx.dword[0];
    opcode = instruction & 0x7f;
    f3 = (instruction >> 12) & 0x7;
    f7 = (instruction >> 25) & 0x7f;
    rd = (instruction >> 7) & 0x1f;
    rs1 = (instruction >> 15) & 0x1f;
    rs2 = (instruction >> 20) & 0x1f;
    shamt = (instruction >> 20);
    imm = (instruction >> 20) & 0xfff;
    // outFile << std::hex << "opcode : " << opcode << ", funct3 : " << f3
    //         << ", funct7 : " << f7 << ", rd : " << rd << ", rs1 : " << rs1
    //         << ", rs2 : " << rs2 << ", imm : " << imm << std::dec << endl;
    switch (opcode) {
    case 0x37:
        imm = (instruction >> 12);
        outFile << "lui r" << rd << ", " << imm << endl;
        break;
    case 0x17:
        imm = (instruction >> 12);
        outFile << "auipc r" << rd << ", " << imm << endl;
        break;
    case 0x6f:
        imm = (instruction >> 12);
        outFile << "jal r" << rd << ", " << imm << endl;
        break;
    case 0x67:
        imm = (instruction >> 20);
        outFile << "jalr r" << rd << ", r" << rs1 << ", " << imm << endl;
        break;
    case 0x63:
        imm = (instruction >> 31 << 12) | ((instruction >> 7) & 0x1E) |
              ((instruction & 0x800) << 4) | ((instruction >> 20) & 0x7E0);
        switch (f3) {
        case 0:
            outFile << "beq r" << rs1 << ", r" << rs2 << " ," << imm << endl;
            break;
        case 1:
            outFile << "bne r" << rs1 << ", r" << rs2 << " ," << imm << endl;
            break;
        case 2:
        case 3:
            outFile << "WTF?" << __FILE__ << ":" << __LINE__ << " in "
                    << __PRETTY_FUNCTION__ << endl;
            break;
        case 4:
            outFile << "blt r" << rs1 << ", r" << rs2 << " ," << imm << endl;
            break;
        case 5:
            outFile << "bge r" << rs1 << ", r" << rs2 << " ," << imm << endl;
            break;
        case 6:
            outFile << "bltu r" << rs1 << ", r" << rs2 << " ," << imm << endl;
            break;
        case 7:
            outFile << "bgeu r" << rs1 << ", r" << rs2 << " ," << imm << endl;
            break;
        default:
            outFile << "WTF?" << __FILE__ << ":" << __LINE__ << " in "
                    << __PRETTY_FUNCTION__ << endl;
            break;
        }
        break;
    case 0x3:
        imm = instruction >> 20;
        switch (f3) {
        case 0:
            outFile << "lb r" << rd << " ," << imm << "(r" << rs1 << ")"
                    << endl;
            break;
        case 1:
            outFile << "lh r" << rd << " ," << imm << "(r" << rs1 << ")"
                    << endl;
            break;
        case 2:
            outFile << "lw r" << rd << " ," << imm << "(r" << rs1 << ")"
                    << endl;
            break;
        case 4:
            outFile << "lbu r" << rd << " ," << imm << "(r" << rs1 << ")"
                    << endl;
            break;
        case 5:
            outFile << "lhu r" << rd << " ," << imm << "(r" << rs1 << ")"
                    << endl;
            break;
        default:
            outFile << "WTF?" << __FILE__ << ":" << __LINE__ << " in "
                    << __PRETTY_FUNCTION__ << endl;
            break;
        }
        break;
    case 0x23:
        imm = ((instruction >> 7) & 0x1F) | ((instruction >> 25) << 5);
        switch (f3) {
        case 0:
            outFile << "sb r" << rs2 << " ," << imm << "(r" << rs1 << ")"
                    << endl;
            break;
        case 1:
            outFile << "sh r" << rs2 << " ," << imm << "(r" << rs1 << ")"
                    << endl;
            break;
        case 2:
            outFile << "sw r" << rs2 << " ," << imm << "(r" << rs1 << ")"
                    << endl;
            break;
        case 3:
            outFile << "sd r" << rs2 << " ," << imm << "(r" << rs1 << ")"
                    << endl;
            break;
        default:
            outFile << "WTF?" << __FILE__ << ":" << __LINE__ << " in "
                    << __PRETTY_FUNCTION__ << endl;
            break;
        }
        break;
    case 0x13:
        imm = instruction >> 20;
        switch (f3) {
        case 0:
            outFile << "addi r" << rd << " ,r" << rs1 << " ," << imm << endl;
            break;
        case 2:
            outFile << "slti r" << rd << " ,r" << rs1 << " ," << imm << endl;
            break;
        case 3:
            outFile << "sltiu r" << rd << " ,r" << rs1 << " ," << imm << endl;
            break;
        case 4:
            outFile << "xori r" << rd << " ,r" << rs1 << " ," << imm << endl;
            break;
        case 6:
            outFile << "ori r" << rd << " ,r" << rs1 << " ," << imm << endl;
            break;
        case 7:
            outFile << "andi r" << rd << " ,r" << rs1 << " ," << imm << endl;
            break;
        case 1:
            outFile << "slli r" << rd << " ,r" << rs1 << " ," << shamt << endl;
            break;
        case 5:
            outFile << "srli r" << rd << " ,r" << rs1 << " ," << rs2 << endl;
            // switch (f7) {
            // case 0:
            //     outFile << "srli r" << rd << " ,r" << rs1 << " ," << rs2
            //             << endl;
            //     break;
            // case 0x20:
            //     outFile << "srai r" << rd << " ,r" << rs1 << " ," << rs2
            //             << endl;
            //     break;
            // default:
            //     outFile << "WTF?" << __FILE__ << ":" << __LINE__ << " in "
            //             << __PRETTY_FUNCTION__ << endl;
            //     break;
            // }
            break;
        default:
            outFile << "WTF?" << __FILE__ << ":" << __LINE__ << " in "
                    << __PRETTY_FUNCTION__ << endl;
            break;
        }
        break;
    case 0x33:
        switch (f7) {
        case 1:
            switch (f3) {
            case 0:
                outFile << "mul r" << rd << ", r" << rs1 << ", r" << rs2
                        << endl;
                break;
            case 1:
                outFile << "mulh r" << rd << ", r" << rs1 << ", r" << rs2
                        << endl;
                break;
            case 2:
                outFile << "mulhsu r" << rd << ", r" << rs1 << ", r" << rs2
                        << endl;
                break;
            case 3:
                outFile << "mulhu r" << rd << ", r" << rs1 << ", r" << rs2
                        << endl;
                break;
            case 4:
                outFile << "div r" << rd << ", r" << rs1 << ", r" << rs2
                        << endl;
                break;
            case 5:
                outFile << "divu r" << rd << ", r" << rs1 << ", r" << rs2
                        << endl;
                break;
            case 6:
                outFile << "rem r" << rd << ", r" << rs1 << ", r" << rs2
                        << endl;
                break;
            case 7:
                outFile << "remu r" << rd << ", r" << rs1 << ", r" << rs2
                        << endl;
                break;
            default:
                outFile << "WTF?" << __FILE__ << ":" << __LINE__ << " in "
                        << __PRETTY_FUNCTION__ << endl;
                break;
            }
            break;
        }
        switch (f3) {
        case 0:
            switch (f7) {
            case 0:
                outFile << "add r" << rd << ", r" << rs1 << ", r" << rs2
                        << endl;
                break;
            case 0x20:
                outFile << "sub r" << rd << ", r" << rs1 << ", r" << rs2
                        << endl;
                break;
            default:
                outFile << "WTF?" << __FILE__ << ":" << __LINE__ << " in "
                        << __PRETTY_FUNCTION__ << endl;
                break;
            }
            break;
        case 5:
            switch (f7) {
            case 0:
                outFile << "srl r" << rd << ", r" << rs1 << ", r" << rs2
                        << endl;
                break;
            case 0x20:
                outFile << "sra r" << rd << ", r" << rs1 << ", r" << rs2
                        << endl;
                break;
            default:
                outFile << "WTF?" << __FILE__ << ":" << __LINE__ << " in "
                        << __PRETTY_FUNCTION__ << endl;
                break;
            }
            break;
        case 1:
            outFile << "sll r" << rd << ", r" << rs1 << ", r" << rs2 << endl;
            break;
        case 2:
            outFile << "slt r" << rd << ", r" << rs1 << ", r" << rs2 << endl;
            break;
        case 3:
            outFile << "sltu r" << rd << ", r" << rs1 << ", r" << rs2 << endl;
            break;
        case 4:
            outFile << "xor r" << rd << ", r" << rs1 << ", r" << rs2 << endl;
            break;
        case 6:
            outFile << "or r" << rd << ", r" << rs1 << ", r" << rs2 << endl;
            break;
        case 7:
            outFile << "and r" << rd << ", r" << rs1 << ", r" << rs2 << endl;
            break;
        default:
            outFile << "WTF?" << __FILE__ << ":" << __LINE__ << " in "
                    << __PRETTY_FUNCTION__ << endl;
            break;
        }
        break;
    case 0x1b:
        switch (f3) {
        case 0:
            imm = instruction >> 20;
            outFile << "addiw r" << rd << " ,r" << rs1 << " ," << imm << endl;
            break;
        case 1:
            outFile << "slliw r" << rd << " ,r" << rs1 << " ," << rs2 << endl;
            break;
        case 5:
            switch (f7) {
            case 0:
                outFile << "srliw r" << rd << " ,r" << rs1 << " ," << rs2
                        << endl;
                break;
            case 32:
                outFile << "sraiw r" << rd << " ,r" << rs1 << " ," << rs2
                        << endl;
                break;
            default:
                outFile << "WTF?" << __FILE__ << ":" << __LINE__ << " in "
                        << __PRETTY_FUNCTION__ << endl;
                break;
            }
            break;
        default:
            outFile << "WTF?" << __FILE__ << ":" << __LINE__ << " in "
                    << __PRETTY_FUNCTION__ << endl;
            break;
        }
        break;
    case 0x3b:
        switch (f3) {
        case 0:
            switch (f7) {
            case 0:
                outFile << "addw r" << rd << " ,r" << rs1 << " ,r" << rs2
                        << endl;
                break;
            case 32:
                outFile << "subw r" << rd << " ,r" << rs1 << " ,r" << rs2
                        << endl;
                break;
            default:
                outFile << "WTF?" << __FILE__ << ":" << __LINE__ << " in "
                        << __PRETTY_FUNCTION__ << endl;
                break;
            }
            break;
        case 1:
            outFile << "sllw r" << rd << " ,r" << rs1 << " ,r" << rs2 << endl;
            break;
        case 5:
            switch (f7) {
            case 0:
                outFile << "srlw r" << rd << " ,r" << rs1 << " ,r" << rs2
                        << endl;
                break;
            case 32:
                outFile << "sraw r" << rd << " ,r" << rs1 << " ,r" << rs2
                        << endl;
                break;
            default:
                outFile << "WTF?" << __FILE__ << ":" << __LINE__ << " in "
                        << __PRETTY_FUNCTION__ << endl;
                break;
            }
            break;
        default:
            outFile << "WTF?" << __FILE__ << ":" << __LINE__ << " in "
                    << __PRETTY_FUNCTION__ << endl;
            break;
        }
        break;
    default:
        outFile << "WTF?" << __FILE__ << ":" << __LINE__ << " in "
                << __PRETTY_FUNCTION__ << endl;
        break;
    }
}

VOID callback_instruction(INS ins, VOID *v) {

    // INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)dump_dis, IARG_ADDRINT,
    //                INS_Address(ins), IARG_PTR, new
    //                string(INS_Disassemble(ins)), IARG_END);
    if (INS_Address(ins) == 0x420002BB) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)log_ins, IARG_CONTEXT,
                       IARG_END);
    }
    if (INS_Address(ins) == 0x42000000) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)log_cpy, IARG_CONTEXT,
                       IARG_END);
    }
}

VOID fini(INT32 code, VOID *v) { outFile.close(); }

int main(int argc, char *argv[]) {
    if (PIN_Init(argc, argv)) {
        perror("init");
        return 0;
    }
    outFile.open(KnobOutputFile.Value().c_str());
    //    IMG_AddInstrumentFunction(callback_image, 0);
    INS_AddInstrumentFunction(callback_instruction, 0);
    PIN_AddFiniFunction(fini, 0);
    PIN_StartProgram();
    return 0;
}
```

Additionally I found out that [radare2](https://github.com/radareorg/radare2) was the only disassembler that worked for RISC-V.

So for static analysis I used r2 to disassemble after dumping the code from binary using the following snipped in ida python

```python
open("risk", "w").write(idaapi.get_many_bytes(0x0000000042001AA0, 54*4))
```
and then

```sh
$ r2 -a riscv -m 0x42001AA0 risk 
[0x42001aa0]> pd54
            0x42001aa0      b7280000       lui a7, 0x2
            0x42001aa4      130101fe       addi sp, sp, -32
            0x42001aa8      938e0800       mv t4, a7
            0x42001aac      23300100       sd zero, 0(sp)
            0x42001ab0      23340100       sd zero, 8(sp)
            0x42001ab4      23380100       sd zero, 16(sp)
            0x42001ab8      233c0100       sd zero, 24(sp)
            0x42001abc      93880800       mv a7, a7
            0x42001ac0      13830e10       addi t1, t4, 256
            0x42001ac4      93050000       li a1, 0
            0x42001ac8      13070000       li a4, 0
            0x42001acc      130f0010       li t5, 256
            0x42001ad0      6f008000       j 0x42001ad8
        ┌─> 0x42001ad4      834506fe       lbu a1, -32(a2)
        ╎   0x42001ad8      03c60800       lbu a2, 0(a7)
        ╎   0x42001adc      034e0300       lbu t3, 0(t1)
        ╎   0x42001ae0      9b563700       srliw a3, a4, 0x3
        ╎   0x42001ae4      13583600       srli a6, a2, 0x3
        ╎   0x42001ae8      33080501       add a6, a0, a6
        ╎   0x42001aec      83470800       lbu a5, 0(a6)
        ╎   0x42001af0      13767600       andi a2, a2, 7
        ╎   0x42001af4      13787700       andi a6, a4, 7
        ╎   0x42001af8      bbd7c740       sraw a5, a5, a2
        ╎   0x42001afc      93f71700       andi a5, a5, 1
        ╎   0x42001b00      b3c7c701       xor a5, a5, t3
        ╎   0x42001b04      93960602       slli a3, a3, 0x20
        ╎   0x42001b08      bb970701       sllw a5, a5, a6
        ╎   0x42001b0c      1b071700       addiw a4, a4, 1
        ╎   0x42001b10      b3e7f500       or a5, a1, a5
        ╎   0x42001b14      93d60602       srli a3, a3, 0x20
        ╎   0x42001b18      93050102       addi a1, sp, 32
        ╎   0x42001b1c      1b563700       srliw a2, a4, 0x3
        ╎   0x42001b20      b386d500       add a3, a1, a3
        ╎   0x42001b24      13160602       slli a2, a2, 0x20
        ╎   0x42001b28      13560602       srli a2, a2, 0x20
        ╎   0x42001b2c      2380f6fe       sb a5, -32(a3)
        ╎   0x42001b30      3386c500       add a2, a1, a2
        ╎   0x42001b34      93881800       addi a7, a7, 1
        ╎   0x42001b38      13031300       addi t1, t1, 1
        └─< 0x42001b3c      e31ce7f9       bne a4, t5, 0x42001ad4
            0x42001b40      93870e20       addi a5, t4, 512
            0x42001b44      93060100       mv a3, sp
            0x42001b48      938e0e22       addi t4, t4, 544
            0x42001b4c      13050000       li a0, 0
        ┌─> 0x42001b50      03c70600       lbu a4, 0(a3)
        ╎   0x42001b54      03c60700       lbu a2, 0(a5)
        ╎   0x42001b58      93871700       addi a5, a5, 1
        ╎   0x42001b5c      93861600       addi a3, a3, 1
        ╎   0x42001b60      3347c700       xor a4, a4, a2
        ╎   0x42001b64      3b05a700       addw a0, a4, a0
        └─< 0x42001b68      e394fefe       bne t4, a5, 0x42001b50
            0x42001b6c      13351500       seqz a0, a0
            0x42001b70      13010102       addi sp, sp, 32
            0x42001b74      67800000       ret
```

The functiopn is quite small -> 54 lines with 2 loops. The first loop calculates some buffer based on the input and some static data. There were 2 tables of 256 bytes - one with random looking bytes - `table` and other will just 0/1 - `bol`.

The pseudocode looks like this

```c
for (i = 0; i < 256; i++) {
        t = table[i];
        b = bol[i];
        curr = flag[t >> 3];
        curr = curr >> (t & 0x7);
        curr = curr & 1;
        curr ^= b;
        curr <<= (i & 7);
        h[i >> 3] |= curr;
    }
```

In the final loop `h` has was compared with a static buffer inside the binary. The operations above can be reversed to derive the actual flag(0x20 bytes) from the stored tables - 0x100 bytes and the hash - 0x20 bytes.

```c
for (i = 0; i < 256; i++) {
        t = table[i];
        b = bol[i];
        curr = ff[i >> 3];
        idx = t >> 3;
        flag[idx] |= (((curr >> (i & 7)) & 1) ^ b) << (t & 0x7);
    }
```

Here `ff` is the hardcoded hash in the binary.
This will give us the flag
> flag{APrettyRiskvTask}

I wanted to see if this could have been solved by [angr](https://github.com/angr/angr) since the actual code is so simple.


```python
p = angr.Project("/tmp/elf")

state = p.factory.entry_state()

flag_addr = 0x1000
state.regs.rdi = flag_addr

for i in range(32):
    state.mem[flag_addr + i].byte = state.solver.BVS('c', 8)

ex = p.factory.simulation_manager(state)
ex.explore(find=0x42000a54)

f = ex.found[0]
f.solver.add(f.regs.rax == 1)
print("".join(chr(f.solver.eval(f.memory.load(flag_addr+i, 1)))
              for i in range(32)))
```

This ran for about 15 minutes and gave the same flag. Guess I could have saved quite a bit of time.

Thanks @gynvael for the great chall. You can download the challenge [here](https://drive.google.com/file/d/16rn-I7I24m-V5mSQC3fINbf34bZP6W5Y/view?usp=sharing)