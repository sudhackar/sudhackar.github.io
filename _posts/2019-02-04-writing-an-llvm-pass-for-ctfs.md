---
layout: post
title: "Writing an LLVM pass for CTFs"
date: 2019-02-04 10:10:00 +0530
categories: blog
tags: [reversing, llvm, obfuscation]
---

# Motive

With a couple of my friends I recently organized [nullcon's](https://twitter.com/nullcon/) [HackIM](https://ctf.nullcon.net/) ctf. I authored **0bfusc8 much** An RE chall that had 11 solves during the CTF and I got positive reviews about it.

The idea was to keep the challenge simple enough yet tricky so that it can't be solved directly with angr.


# Background

If you're not into reverse engineering/compilers you might need to look into these terms

### [Basic Block](https://en.wikipedia.org/wiki/Basic_block)
A basic block(bb) is a piece of code in the program which only has one path of execution - a stright line. There will be no braches/loops inside a basic block except at the end which means if we execute the first line we will execute all lines in that basic block. This concept is not just in assembly but also compilers in the context of generated code, analyzed code and intermediate code.

### [Control Flow](https://en.wikipedia.org/wiki/Control_flow_graph)
A control flow graph defines the paths of execution in a program. The nodes are usually basic blocks in a CFG. To keep a picture in perspective

```c
int main(int argc, char **argv) {
    if (argc == 2)
        puts("two");
    else
        puts("not two");
    return 0;
}
```
Here's how the cfg and bbs look
![cfg](https://i.imgur.com/Qjl8EKc.png)

`main` was broken into 4 bbs - one entry, one exit and two for if/else. We can see this CFG has only 2 paths.

### [Opaque Predicate](https://en.wikipedia.org/wiki/Opaque_predicate)
An opaque predicate is a condition in a code whose value we know at compile time yet it is still calculated during run time. We'll see how they're useful in a moment.

### [LLVM](http://llvm.org/)
The LLVM Project is a collection of modular and reusable compiler and toolchain technologies. It is a great project to implement your own compilers or play around with static analysis of code. These libraries are built around a well specified code representation known as the LLVM intermediate representation ("LLVM IR"). LLVM IR makes it easier to write automated analysis by exposing APIs to change it at will.

# LLVM Pass
When some C code is passed through a compiler it goes through a number of steps - parsing, lexing, semantic analysis, IR code gen, optimizations and native code gen respectively. LLVM as a project offers you to just write a frontend for a language of your choice which parses your specific language and emits LLVM IR. LLVM project then has all the proper backends and analysis/optimizations built in to generate a binary. Passes perform the transformations and optimizations that make up the compiler, they build the analysis results that are used by these transformations, and they are, above all, a structuring technique for compiler code. 

If we want to instrument a program at compile time, a pass would be the best way to achieve that.

# How make RE harder with an LLVM pass
When we analyze code usually the size and complexity of code determines the time/efforts needed. A function with a very complex cfg with a lot of paths is much harder to analyze and understand. Typically all obfuscators at a function level try to do that.

My idea was to use a lot of Opaque Predicates in the code and create paths that will never be executed. This will throw off the reverse engineer to do something else.

If we have this code

```c
int a, b, c;
...
a = b + c;
...
```

This will usually be just a couple of instructions in assembly - normal stuff. 

### Idea 1

```c
int a, b, c;
...
int x = rand()
a = b + x;
a += c;
a -= x;
...
```

This will have multiple instructions in assembly. However an optimizing decompiler/code analyzer like IDA will detect this and show you version 1 when decompiled.

### Idea 2

```c
int a, b, c;
...
s:
...
switch(b%2){
    case 1: a = b + c; break;
    case 0: a = b + c; break;
    case 2: goto s;
}
...
```
In this case we create an opaque predicate: case 2 for `b%2` which loops back to the start of the code. Now if we use these two ideas together we'll have a very complex piece of code for a simple addition.


```c
int a, b, c;
...
s:
...
switch(b%2){
    case 1: a = b + 0x333435;
            c -= 0x333435;
            a += c;
            break;
    case 0: a = b - 0x414243;
            c += 0x414243;
            a +=c;
            break;
    case 2: a = b + c;
            goto s;
}
...
```

The cfg for this will have multiple branches and a loop which was just a basic block earlier. This increases the complexity of the code. Also if you see we have used addition/subtraction operations to obfuscate addition. If we do this obfuscation recursively this could even go upto a million basic blocks.

To do this I implemented a `FunctionPass` in llvm. Source was released for this pass [here](https://github.com/nullcon/hackim-2019/tree/master/re/obfusc8_much/src/gg).
We can use Clang to generate a bitcode - LLVM IR code for a C program and then run our pass over it. `FunctionPass` are run over every function in a program so you can efficiently instrument each function individually. To do this we implement a `runOnFunction` in our pass. Here are some portions of the code.

```cpp
while(obfuscated < level){
    errs() << "Round : " << obfuscated << "/" << level << "\n";
    toDoAdd.clear();
    toDoSub.clear();
    toDoOr.clear();
    toDoXor.clear();
    for (Function::iterator bb = F.begin(); bb != F.end(); ++bb) {
        for (BasicBlock::iterator I = bb->begin(); I != bb->end(); ++I) {
            if (I->getOpcode() == BinaryOperator::Xor) {
                auto &ins = *I;
                toDoXor.push_back(&ins);
                obfuscated++;
                break;
            }
            if (I->getOpcode() == BinaryOperator::Add) {
                auto &ins = *I;
                toDoAdd.push_back(&ins);
                obfuscated++;
                break;
            }
            if (I->getOpcode() == BinaryOperator::Sub) {
                auto &ins = *I;
                toDoSub.push_back(&ins);
                obfuscated++;
                break;
            }
            if (I->getOpcode() == BinaryOperator::Or) {
                auto &ins = *I;
                toDoOr.push_back(&ins);
                obfuscated++;
                break;
            }
            if (obfuscated > level) {
                break;
            }
        }
        if (obfuscated > level) {
            break;
        }
    }

    for (auto &I : toDoAdd) {
        AddSwitch(cast<Instruction>(I), addfnc);
    }

    for (auto &I : toDoSub) {
        AddSwitch(cast<Instruction>(I), subfnc);
    }

    for (auto &I : toDoOr) {
        AddSwitch(cast<Instruction>(I), orfnc);
    }

    for (auto &I : toDoXor) {
        AddSwitch(cast<Instruction>(I), xorfnc);
    }
}
```

It iterates over a all instructions in a function and checks if they one of ^, | , +, -. Such operators are pushed in a set so that we can work on them later. Later we'll replace each binary operator with a switch-case by calling `AddSwitch` which is where the actual magic happens.


```cpp
// Adds a switch with a dummy loop, second param is a list of functions
// which replace an instruction
void AddSwitch(Instruction *I,
               Value *(*genfnc[3])(Instruction *, BasicBlock *)) {
    Value *op1 = I->getOperand(0);
    Value *op2 = I->getOperand(1);

    auto F = I->getFunction();
    auto BB = I->getParent();

    Type *type = I->getType();
    IRBuilder<> *builder = new IRBuilder<>(I);

    // A place on the stack to store values from all the paths in the
    // switch.
    Value *substitute =
        builder->CreateAlloca(Type::getInt32Ty(F->getContext()));

    auto two = ConstantInt::get(type, 2);
    auto zero_c = ConstantInt::get(Type::getInt32Ty(I->getContext()), 0);
    ;
    auto one_c = ConstantInt::get(Type::getInt32Ty(I->getContext()), 1);
    ;

    BasicBlock *swDefault =
        BasicBlock::Create(F->getContext(), "defaultCase", F);
    BasicBlock *zeroCase =
        BasicBlock::Create(F->getContext(), "zeroCase", F);
    BasicBlock *oneCase = BasicBlock::Create(F->getContext(), "oneCase", F);

    // Create op1%2 check
    builder->SetInsertPoint(I);
    auto checkCond = builder->CreateURem(op1, two);

    // create switch for op1%2
    builder->SetInsertPoint(I);
    auto switch_main = builder->CreateSwitch(checkCond, swDefault, 2);
    switch_main->addCase(zero_c, zeroCase);
    switch_main->addCase(one_c, oneCase);

    // split at the instruction and switch to create loop
    auto N = BB->splitBasicBlock(I);
    auto S = BB->splitBasicBlock(switch_main);

    // default case. never hit. dummy loop
    builder->SetInsertPoint(swDefault);
    builder->CreateStore(genfnc[0](I, swDefault), substitute);
    builder->CreateBr(S);

    // use one of the obfuscators to generate a substitiue instruction
    builder->SetInsertPoint(zeroCase);
    builder->CreateStore(genfnc[1](I, zeroCase), substitute);
    builder->CreateBr(N);

    builder->SetInsertPoint(oneCase);
    builder->CreateStore(genfnc[2](I, oneCase), substitute);
    builder->CreateBr(N);

    // really?
    swDefault->moveBefore(N);
    zeroCase->moveBefore(N);
    oneCase->moveBefore(N);

    // load the stack variable and replace the occurence of result with it
    BasicBlock::iterator DI = N->begin();
    Instruction &Inst = *DI;
    builder->SetInsertPoint(&Inst);
    Value *checker = builder->CreateLoad(substitute);
    I->replaceAllUsesWith(checker);

    // remove dummy jump and original instruction
    S->getTerminator()->eraseFromParent();
    I->eraseFromParent();
}
```

Here we separate the current basic block at the binary operator and put a switch case instead. To save the calculated values in all paths consistent I had to add a local variable for each operation. This made the size of the stack enormous.

If we run this function over some program, it'll add some basic blocks with more binary operators. We run this pass again over that code to increase the number exponentially. If we don't control this it can get huge pretty quick resulting in binaries in 10s MBs of size.

Here's a simple example on fibonacci function


Normal
![normal](https://i.imgur.com/Ki5U98Q.png)


After
![ob](https://i.imgur.com/PsJWubX.png)

Tune in next time when we'll see what kinds of approach can we take to solve such challenges.