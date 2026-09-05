#!/usr/bin/env python3
# Shared helpers. Pull them in with `from utils import *`.
# Assumes context.binary is already set by the solve script.
from pwn import *


def pk(x):
    return pack(x)


def upk(x):
    size = context.bytes
    return unpack(x.ljust(size, b"\x00")[:size])


def upk_leak(x):
    # unpack a leak with a trailing newline/garbage (e.g. a puts leak)
    x = x.strip()
    return unpack(x.ljust(context.bytes, b"\x00")[: context.bytes])


def leak_hex(io, before=None):
    # read a %p-style hex leak as an int
    if before is not None:
        io.recvuntil(before)
    return int(io.recvline().strip(), 16)


def libc_base(leak, symbol, libc):
    # base = libc_base(leaked_puts, "puts", libc); libc.address = base
    return leak - libc.symbols[symbol]


def one_gadgets(libc_path):
    out = subprocess.check_output(["one_gadget", "--raw", libc_path])
    return [int(o, 16) for o in out.decode().split()]


def fmt_find_offset(io, sendline=None, max_offset=20):
    # spam AAAA%N$p until it echoes 0x41414141, return N
    sendline = sendline or io.sendline
    for n in range(1, max_offset + 1):
        sendline(b"AAAA%" + str(n).encode() + b"$p")
        if b"0x41414141" in io.recvline():
            return n
    log.warning("format string offset not found within %d slots", max_offset)
    return None


def de_ptr(mangled):
    # undo safe-linking (glibc >= 2.32) when a ptr is mangled against its own
    # address, i.e. fd == value ^ (chunk_addr >> 12). converges block by block.
    plain = 0
    for _ in range(6):
        plain = mangled ^ (plain >> 12)
    return plain


def mangle_ptr(pos, ptr):
    return (pos >> 12) ^ ptr


def ret2csu(io):
    # TODO: fill in the __libc_csu_init gadgets per binary
    raise NotImplementedError("implement ret2csu for this binary")


# io shortcuts
def sla(io, delim, data):
    return io.sendlineafter(delim, data)


def sa(io, delim, data):
    return io.sendafter(delim, data)


def sl(io, data):
    return io.sendline(data)


def s(io, data):
    return io.send(data)


def rl(io):
    return io.recvline()


def ru(io, delim):
    return io.recvuntil(delim)


# one cached ssh session, reused to start the target and upload payloads
_SSH = None


def get_ssh(host, port=22, user=None, password=None, keyfile=None,
            set_wd=False, **kw):
    # key auth if keyfile else password; set_wd gives every remote process a
    # fresh temp cwd (handy when the exploit drops a file next to the target)
    global _SSH
    if _SSH is None:
        _SSH = ssh(host=host, port=port, user=user,
                   password=password, keyfile=keyfile, **kw)
        if set_wd:
            _SSH.set_working_directory()
    return _SSH


def ssh_session():
    return _SSH


def put_payload(data, name="payload.bin", shell=None):
    # write a file the target can open(): local cwd, or upload over ssh.
    # returns the path to feed back into the challenge.
    shell = shell or _SSH
    if shell is not None:
        wd = shell.cwd or b"."
        wd = wd.decode() if isinstance(wd, (bytes, bytearray)) else wd
        path = wd.rstrip("/") + "/" + name
        shell.upload_data(data, path)
        return path
    path = os.path.abspath(name)
    write(path, data)
    return path


def stack_top(io, default=0x7ffffffff000):
    # [stack] top from /proc for a local process, for no-aslr targets.
    # SUID maps aren't readable, so fall back to the usual no-randomize top.
    try:
        for line in open("/proc/%d/maps" % io.pid):
            if line.rstrip().endswith("[stack]"):
                return int(line.split("-")[1].split()[0], 16)
    except Exception as e:
        log.warning("stack_top: /proc read failed (%s), using %#x", e, default)
    return default
