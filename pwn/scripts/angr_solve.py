#!/usr/bin/env python3
# angr skeleton: reach FIND while avoiding AVOID, recover the input that does it.
import angr
import claripy
import logging

logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)

BINARY = "./chall"

# grab these from the disassembly (objdump -d -M intel chall, or pwndbg)
FIND = 0x401337           # win / print-flag block
AVOID = [0x401300]        # failure / exit block

proj = angr.Project(BINARY, auto_load_libs=False)


def solve_stdin(nbytes=32):
    flag = claripy.BVS("flag", nbytes * 8)
    state = proj.factory.full_init_state(
        stdin=flag,
        add_options=angr.options.unicorn,
    )
    for byte in flag.chop(8):   # printable ascii; drop if the flag is raw bytes
        state.solver.add(byte >= 0x20, byte <= 0x7E)

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=FIND, avoid=AVOID)

    if not simgr.found:
        print("[-] no path to FIND (check the addresses)")
        return None
    found = simgr.found[0]
    solution = found.posix.dumps(0)
    print("[+] stdin:", solution)
    return solution


def solve_argv(nbytes=32):
    arg = claripy.BVS("arg", nbytes * 8)
    state = proj.factory.full_init_state(args=[BINARY, arg])
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=FIND, avoid=AVOID)
    if not simgr.found:
        print("[-] no path to FIND")
        return None
    solution = simgr.found[0].solver.eval(arg, cast_to=bytes)
    print("[+] argv[1]:", solution)
    return solution



if __name__ == "__main__":
    solve_stdin()
