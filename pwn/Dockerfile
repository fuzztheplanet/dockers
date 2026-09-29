FROM skw/base-archlinux

ENV PWNDBG_NO_AUTOUPDATE=1

RUN pacman --noconfirm -Syu --needed \
        python-pip \
        binutils gcc libedit sagemath ruby \
        strace ltrace nasm yasm gdb elfutils binwalk openssl \
        unzip \
        base-devel cmake rust && \
    mkdir /root/tools && \
    pip install --break-system-packages --upgrade angr z3-solver && \
    git clone --depth=1 https://github.com/Gallopsled/pwntools.git /root/tools/pwntools && \
    pip install --break-system-packages -e /root/tools/pwntools && \
    gem install --no-user-install one_gadget seccomp-tools && \
    wget -q https://github.com/0vercl0k/rp/releases/download/v2.1.4/rp-lin-clang.zip -P /tmp && \
    unzip /tmp/rp-lin-clang.zip -d /usr/local/bin/ && \
    rm /tmp/rp-lin-clang.zip && \
    pip install --break-system-packages --upgrade \
        lz4 zstandard git+https://github.com/clubby789/python-lzo@b4e39df \
        git+https://github.com/marin-m/vmlinux-to-elf && \
    git clone --depth 1 https://github.com/pwndbg/pwndbg /root/tools/pwndbg && \
    cd /root/tools/pwndbg && echo n | ./setup.sh && \
    mkdir /root/tools/gef && \
    wget -q https://raw.githubusercontent.com/bata24/gef/dev/gef.py -O /root/tools/gef/gef.py && \
    git clone --depth 1 https://github.com/mahaloz/decomp2dbg.git /root/tools/decomp2dbg && \
    pip install --break-system-packages /root/tools/decomp2dbg && \
    git clone --depth 1 https://github.com/yrp604/rappel /root/tools/rappel && \
    make -C /root/tools/rappel && \
    cp /root/tools/rappel/bin/rappel /usr/local/bin/rappel && \
    git clone --depth 1 https://github.com/jerdna-regeiz/splitmind /root/tools/splitmind && \
    git clone --depth 1 https://github.com/niklasb/libc-database /root/tools/libc-database && \
    cd / && \
    pacman --noconfirm -Rns base-devel cmake rust && \
    rm -rf /var/cache/pacman/pkg/* /root/.cargo /root/.cache /root/.gem

# Copy local scripts
COPY pwn/files/gdbinit /root/.gdbinit
COPY pwn/files/gdb-gef /usr/bin/gdb-gef
COPY pwn/files/gdb-pwndbg /usr/bin/gdb-pwndbg

# Solve templates + the pwn-init bootstrap command that drops them in $PWD
COPY pwn/scripts/solve.py /root/scripts/solve.py
COPY pwn/scripts/utils.py /root/scripts/utils.py
COPY pwn/scripts/angr_solve.py /root/scripts/angr_solve.py
COPY pwn/scripts/z3_solve.py /root/scripts/z3_solve.py
COPY pwn/scripts/sage_solve.py /root/scripts/sage_solve.py
COPY pwn/files/pwn-init /usr/bin/pwn-init
RUN chmod +x /usr/bin/pwn-init

# Done!
WORKDIR /work
CMD ["/bin/bash"]
