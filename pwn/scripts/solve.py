#!/usr/bin/env python3
from pwn import *

from utils import *

BINARY = "./chall"

HOST = "challenge.example.com"
PORT = 1337

# ssh target (some challs give creds instead of a tcp port)
SSH_HOST = "challenge.example.com"
SSH_PORT = 22
SSH_USER = "ctf"
SSH_KEY = None            # private key path; falls back to SSH_PASS if None
SSH_PASS = "ctf"
SSH_BINARY = "/home/ctf/chall"
SSH_WORKDIR = False       # give the ssh session a temp cwd (for put_payload)

exe = context.binary = ELF(BINARY, checksec=False)
# libc = ELF("./libc.so.6", checksec=False)

context.terminal = ["tmux", "splitw", "-h"]
context.log_level = "info"


def in_tmux():
    return bool(os.environ.get("TMUX"))


def debug_local(argv, *a, **kw):
    # inside tmux gdb opens in a split; otherwise run it and attach by hand
    if in_tmux():
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)

    io = process([exe.path] + argv, *a, **kw)
    script_path = os.path.abspath(".gdbscript")
    with open(script_path, "w") as f:
        f.write(gdbscript + "\n")
    log.warn_once(
        "no tmux, can't open a gdb split.\n"
        "    attach with:  %s -p %d -x %s\n"
        "    (or start tmux for the automatic split)"
        % (context.gdb_binary, io.pid, script_path)
    )
    pause()
    return io


def start(argv=[], *a, **kw):
    # local | GDB | REMOTE | SSH | SSH GDB, picked from the cli args.
    # e.g. python3 solve.py SSH SSH_HOST=1.2.3.4 SSH_USER=hacker
    if args.REMOTE:
        return remote(args.HOST or HOST, int(args.PORT or PORT), *a, **kw)

    if args.SSH:
        shell = get_ssh(
            host=args.SSH_HOST or SSH_HOST,
            port=int(args.SSH_PORT or SSH_PORT),
            user=args.SSH_USER or SSH_USER,
            keyfile=args.SSH_KEY or SSH_KEY,
            password=(args.SSH_PASS or SSH_PASS) if not (args.SSH_KEY or SSH_KEY) else None,
            set_wd=SSH_WORKDIR,
        )
        remote_bin = args.SSH_BINARY or SSH_BINARY
        if args.GDB:
            # local gdb -> remote gdbserver, so it still wants a terminal
            if not in_tmux():
                log.warn_once("SSH GDB needs tmux for the gdb window; start it first.")
            return gdb.debug([remote_bin] + argv, gdbscript=gdbscript,
                             ssh=shell, *a, **kw)
        return shell.process([remote_bin] + argv, *a, **kw)

    if args.GDB:
        return debug_local(argv, *a, **kw)

    return process([exe.path] + argv, *a, **kw)


context.gdb_binary = "gdb-pwndbg"   # or gdb-gef
gdbscript = """
init-pwndbg
# break *main
continue
""".strip()


# === exploit ===============================================================
io = start()

# offset = 40
# payload = flat({offset: exe.sym.win})
# io.sendlineafter(b"> ", payload)
#
# drop a file the target open()s (uploads over ssh in SSH mode):
# path = put_payload(shellcode, "sc.bin")
#
# no-aslr stack:
# buf = stack_top(io) - DELTA

io.interactive()
