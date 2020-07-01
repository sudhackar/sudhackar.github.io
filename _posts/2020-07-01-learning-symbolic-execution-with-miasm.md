---
layout: post
title: "Learning Symbolic Execution With Miasm"
date: 2020-07-01 17:10:00 +0530
categories: blog
tags: [reversing, miasm, symbolic-execution]
---

# miasm

From [cea-sec](https://github.com/cea-sec/miasm) github

> Miasm is a free and open source (GPLv2) reverse engineering framework. Miasm aims to analyze / modify / generate binary programs.

It has a bunch of cool features ranging like static binary analysis, IR representation, unpacking, de-obfuscation etc

I usually like to try out a new tool and have a look at it features if they are later needed in a project or CTFs.

A couple of points to note if you're new to Symbolic Execution
+ Symbolize - mark memory/register as "symbol" - like a mathematical variable. Symbolized memory doesn't have a value. The solvers use this variable to calculate constraints and solve to get values.
+ Concretize - set "actual" value to memory like 0x41 for a byte, -22 for an int, etc.

The general idea of a symbolic execution engine is to let the user select parts of a program that needs to be evaluated, then symbolize parts of the memory and let the engine evaluate expressions for memory to a final state. On this final state, query the constraints solver to solve for selected memory to set condition/s true/false.
In this challenge there were some equations that need to be verified for bytes of the flag. The symbolic execution engine should automatically calculate these equations and solve them to get the flag


# Problem

A friend participated in a CTF and got a reverse task which was a trivial solve for [angr](https://github.com/angr/angr). While solving that task I thought why not give `miasm` a try.

There was only 1 function of interest - `main` which looked like

![main cfg](https://i.imgur.com/83cOoZa.png)

Each smaller basic block connected with a red line is a classic "Bad Boy", final one at the bottom right is the "Good Boy". `flag` is read as `argv[1]` and its length is compared to 9 in the first basic block.
Each basic block then had a small equation for consecutive pair of bytes.
Solving with `angr` was trivial.

```python
p = angr.Project('/tmp/ctf-bin')

base = 0x400000
flag_addr = 0x1000
argv_addr = 0x1020
flag_addr_ptr = 0x1028

state = p.factory.blank_state(addr=base+0x11e4)
state.regs.rbp = 0x1200
state.mem[state.regs.rbp - 0x40].qword = argv_addr
state.mem[flag_addr_ptr].qword = flag_addr

for i in range(9):
    state.mem[flag_addr + i].byte = state.solver.BVS('C_%d' %i, 8)

ex = p.factory.simulation_manager(state)
ex.explore(find=base+0x1454)
if ex.found:
    s=""
    for i in range(9):
        s+=chr(ex.found[0].solver.eval(ex.found[0].memory.load(flag_addr + i, 1)))
    print(s)
```

yielded the flag

Since I already have knowledge on how the challenge works and have a solution I can give `miasm` a try. The documentation is quite lacking and there are very little number of blogs out including their [own](https://miasm.re/blog). The source is somewhat documented and can be worked with.

My script was heavily based on [this](https://github.com/cea-sec/miasm/blob/master/example/symbol_exec/dse_crackme.py)

If you want to learn about a tool you should first start by solving small challenges with it.

### Sandbox

To execute a binary within miasm's env a `sandbox` is needed. It has a `jitter` that jits the elf that can be then "executed".

```python
from miasm.analysis.sandbox import Sandbox_Linux_x86_64
parser = Sandbox_Linux_x86_64.parser()
parser.add_argument("--f", default="/tmp/ctf-bin", required=False) # set a default elf path
options = parser.parse_args()

solution = "........."
options.mimic_env = True
options.command_line = [solution] # set argv[1] for the elf
sb = Sandbox_Linux_x86_64(options.f, options, globals())

sb.jitter.init_run(sb.entry_point)
```

Here we setup the `sandbox` sb and let it setup the `entry_point`. I have also setup a dummy solution as it goes into `argv[1]`

### Dynamic Symbolic Execution(DSE) with miasm

Based on the emulation we can set up constraints on the memory by hooking functions or setting breakpoints in the code. If nothing is done, concrete values can be used by `miasm`

We need a `DSEPathConstraint` hooked up with our `sandbox` sb. According to its documentation

> DSEPathConstraint is Dynamic Symbolic Execution Engine keeping the path constraint. Possible new "solutions" are produced along the path, by inversing concrete path constraint. Thus, a "solution" is a potential initial context leading to a new path.

While evaluating a path we can set constraints that can be solved by the backend `z3` solver to produce new paths. Its similar to `angr`'s simulation manager but we need to symbolize and concretize the memory. It has 3 evaluating techniques - PRODUCE_SOLUTION_CODE_COV, PRODUCE_SOLUTION_BRANCH_COV and PRODUCE_SOLUTION_PATH_COV
For this simple and small CFG all 3 performed same.

So we setup the necessary DSE variables and attach the `jitter` with the `dse` instance. A `Machine` is a generic wrapper over all architectures supported by `miasm` - x86/64, arm, ppc etc.

```python
from miasm.analysis.dse import DSEPathConstraint
from miasm.analysis.machine import Machine

machine = Machine("x86_64")
dse = DSEPathConstraint(
    machine, produce_solution=DSEPathConstraint.PRODUCE_SOLUTION_BRANCH_COV)

dse.attach(sb.jitter)
dse.update_state_from_concrete()
sb.run()
```
`update_state_from_concrete` updates the values from the CPU, so the symbolic execution will be completely concrete from that point.

If the script fails upto running here change `dse` with an instance of `DSEEngine`

```
dse = DSEEngine(
    machine)
```

### Hooking Functions

if we run the script we have now we might have an error like

```
RuntimeError: Symbolic stub 'b'xxx___libc_start_main_symb'' not found
```

This means that `__libc_start_main` which is a part of the libc will have to be implemented in the miasm env. This can be copied from a similar [blog](https://miasm.re/blog/2017/10/05/playing_with_dynamic_symbolic_execution.html) All the functions which are dynamically linked have to be implemented in the script as `xxx_<function_name>_symb` for symbolic execution.

```python
def xxx___libc_start_main_symb(dse):
    # ['RDI', 'RSI', 'RDX', 'RCX', 'R8', 'R9']
    regs = dse.ir_arch.arch.regs
    top_stack = dse.eval_expr(regs.RSP) # read registers to replicate while returning
    main_addr = dse.eval_expr(regs.RDI)
    argc = dse.eval_expr(regs.RSI)
    argv = dse.eval_expr(regs.RDX)
    hlt_addr = ExprInt(sb.CALL_FINISH_ADDR, 64)

    dse.update_state({
        ExprMem(top_stack, 64): hlt_addr,
        regs.RDI: argc,
        regs.RSI: argv,
        dse.ir_arch.IRDst: main_addr,
        dse.ir_arch.pc: main_addr,
    })
```

This updates the dse as if `__libc_start_main` has been executed. This needs to be implemented before

```
dse.add_lib_handler(sb.libs, globals())
```

We also know that the paths have a "Bad Boy" path which has termination with a call to `puts` followed by `exit`.
We will hook them too and setup such that we can find what paths to not finish on.

```python
class FinishOn(Exception):

    def __init__(self, string):
        self.string = string
        super(FinishOn, self).__init__()

def xxx_exit_symb(dse):
    raise FinishOn("Fail")

from miasm.os_dep.win_api_x86_32 import get_win_str_a

def xxx_puts_symb(dse):
    string = get_win_str_a(dse.jitter, dse.jitter.cpu.RDI)
    raise FinishOn(string)
```

Next error that we hit is

```
RuntimeError: Symbolic stub 'b'xxx_strlen_symb'' not found
```

`strlen` is called to verify if the length of the string is 9. This will be an apt location to set the string as symbolic and setup constraints that can be later solved.

```python
from miasm.expression.expression import *

str_ptr = 0
curr = b""
expr_map = dict()

strln = ExprId("strln", 64) # symbolize string length
z3_strln = dse.z3_trans.from_expr(strln)
dse.cur_solver.add(0 < z3_strln)
dse.cur_solver.add(z3_strln < 10)

def xxx_strlen_symb(dse):
    global str_ptr
    regs = dse.ir_arch.arch.regs
    ptr = dse.eval_expr(regs.RDI) # read string pointer
    str_ptr = int(ptr) # save string pointer to inspect later
    ret_addr = ExprInt(dse.jitter.get_stack_arg(0), regs.RIP.size)
    ret_value = strln
    update = {}

    # symbolize the string buffer as bytes
    for i, content in enumerate(curr):
        addr = dse.symb.expr_simp(ptr + ExprInt(i, ptr.size))
        expr_map[i] = ExprId("C_%d" % (i), 8) # save expressions so that we can query the solver for these

        dse.cur_solver.add(0x2f < dse.z3_trans.from_expr(expr_map[i])) # should be printable ascii alphanumeric
        update[ExprMem(addr, 8)] = expr_map[i]
    # update the state and emulate strlen call
    dse.update_state({
        regs.RSP: dse.eval_expr(regs.RSP + ExprInt(8, regs.RSP.size)),
        dse.ir_arch.IRDst: ret_addr,
        regs.RIP: ret_addr,
        regs.RAX: ret_value,
    })
    dse.update_state(update)
```

Here we do a couple of things
+ Symbolize the string length as the return values in `rax` when the function returns
+ Set limits on the length as we already know
+ Symbolize the bytes of the string so that constraints can be calculated by the z3 solver in `DSEPathConstraint`
+ Add constraints on bytes to be alpha numeric(optional)

This serves as the init logic for our solver. `update_state` takes a map of `expression` to `expression` instead of integer values.

### Path exploration

With all the needed functions hooked, we can proceed to evaluate the paths.
For quicker emulation we can take a snapshot of the `dse` and restore it when needed from init. We then solve constraints from the last path, concretize the values from the solution and add it to a queue which can be then precessed.

```python
dse.add_lib_handler(sb.libs, globals())
snapshot = dse.take_snapshot()
found = False
curr = b""
todo = set([b""])

while todo:
    flag = todo.pop() # take 1 input to process
    curr = flag # set curr so that xxx_strlen_symb can iterate over it
    dse.restore_snapshot(snapshot, keep_known_solutions=True) # restore to "init" snapshot
    # Concretize the known bytes from curr
    if str_ptr:
        # read the current bytes
        print("Already {}".format(sb.jitter.vm.get_mem(int(str_ptr), 9)))
        for idx, content in enumerate(curr):
            currb = sb.jitter.vm.get_mem(int(str_ptr) + idx, 1)
            # . was the original value set in argv[1]
            if currb == b'.' and content > 0x30:
                # update if a better solution was found
                sb.jitter.vm.set_mem(int(str_ptr) + idx, bytes([content]))
        # read the updated bytes of the string
        print("Done {}".format(sb.jitter.vm.get_mem(int(str_ptr), 9)))
    try:
        sb.run()
    # puts and exit trigger a FinishOn which also has good boy/bad boy string
    except FinishOn as finish_info:
        print(finish_info.string)
        if "Level Unlocked" in finish_info.string:
            found = True
            break
    # iterate over all solutions and query the expr_map expressions for new candidate string bytes
    for sol_ident, model in viewitems(dse.new_solutions):
        candidate = []
        ln = max(model.eval(dse.z3_trans.from_expr(strln)).as_long(), 9)
        for i in range(ln):
            try:
                candidate.append(int_to_byte(model.eval(
                    dse.z3_trans.from_expr(expr_map[i])).as_long()))
            except (KeyError, AttributeError) as _:
                candidate.append(b"\x00")
        # add the new candidate to queue
        todo.add(b"".join(candidate))
```

Once a solution is found for the 2 paths from a basic block, constraints on expressions from `expr_map` - bytes of "flag" string can be solved and concretized.
Since the checks are progressive, this will eventually solve all the constraints upto the good boy block - Level Unlocked