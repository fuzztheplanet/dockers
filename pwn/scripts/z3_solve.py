#!/usr/bin/env python3
# z3 skeleton: recover the input that satisfies a set of checks
# (keygens, xor/arith obfuscation, small equation systems off a disasm).
from z3 import *

# model each input byte as an 8-bit BitVec
N = 16
flag = [BitVec(f"b{i}", 8) for i in range(N)]

# create a solver and add constraints
s = Solver()
for b in flag:
    s.add(b >= 0x20, b <= 0x7E)          # printable ascii

# replace with the real check, e.g. input[i] ^ 0x37 == cipher[i]
CIPHER = [0x00] * N
for i in range(N):
    s.add(flag[i] ^ 0x37 == CIPHER[i])
# checksum:  s.add(Sum([ZeroExt(24, b) for b in flag]) == 0x4d2)
# relation:  s.add(flag[3] == flag[0] + flag[1])

def recover():
    if s.check() != sat:
        print("[-] unsat")
        return None
    m = s.model()
    out = bytes(m[b].as_long() for b in flag)
    return out


def all_solutions(limit=10):
    # enumerate solutions when the constraints are under-determined
    found = []
    while len(found) < limit and s.check() == sat:
        m = s.model()
        found.append(bytes(m[b].as_long() for b in flag))
        s.add(Or([b != m[b] for b in flag]))   # block it, look for the next
    return found


# max/min an objective instead:
# opt = Optimize(); x = Int("x"); opt.add(x > 0, x < 100)
# opt.maximize(x); print(opt.check(), opt.model())

if __name__ == "__main__":
    recover()
