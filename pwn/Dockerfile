FROM skw/base-archlinux

# Store tools under /root/tools
RUN mkdir /root/tools

# Every Arch package in one -Syu transaction: three separate -Syu layers is a
# partial upgrade, and each one re-resolves against a different DB snapshot.
# unzip is listed explicitly — rp-lin below needs it, and it only ever arrived
# here as somebody else's transitive dependency.
RUN pacman --noconfirm -Syu --needed \
    base-devel \
    python-pip python-pipx python-uv \
    cmake binutils rust libedit sagemath ruby \
    strace ltrace nasm yasm gdb elfutils binwalk openssl \
    unzip && \
    rm -rf /var/cache/pacman/pkg/* && \
    pipx ensurepath

# Install angr and z3 for Python. Sage comes from the sagemath package above;
# the PyPI project of that name is a different (stub) package.
RUN pip install --break-system-packages --upgrade \
    angr z3-solver

# Install pwntools
RUN cd /root/tools && \
    git clone --depth=1 https://github.com/Gallopsled/pwntools.git && \
    pip install --break-system-packages -e pwntools

# Install one_gadget and seccomp-tools
RUN gem install --no-user-install one_gadget seccomp-tools

# Install rp-lin
RUN wget -q https://github.com/0vercl0k/rp/releases/download/v2.1.4/rp-lin-clang.zip -P /tmp && \
    unzip /tmp/rp-lin-clang.zip -d /usr/local/bin/ && \
    rm /tmp/rp-lin-clang.zip

# Install vmlinux-to-elf
RUN pip install --break-system-packages --upgrade \
    lz4 zstandard git+https://github.com/clubby789/python-lzo@b4e39df \
    git+https://github.com/marin-m/vmlinux-to-elf

# Install pwndbg
ENV PWNDBG_NO_AUTOUPDATE=1
RUN cd /root/tools && \
    git clone --depth 1 https://github.com/pwndbg/pwndbg && \
    cd pwndbg && echo n | ./setup.sh && \
    cd /root/tools

# Install GEF
RUN mkdir /root/tools/gef && \
    wget -q https://raw.githubusercontent.com/bata24/gef/dev/gef.py -O /root/tools/gef/gef.py && \
    cd /root/tools

# Install dcomp2dbg
RUN cd /root/tools && git clone --depth 1 https://github.com/mahaloz/decomp2dbg.git && \
    cd decomp2dbg && \
    pip install --break-system-packages .

# Install rappel
RUN cd /root/tools && git clone --depth 1 https://github.com/yrp604/rappel && \
    cd rappel && make && cp bin/rappel /usr/local/bin/rappel

# Install splitmind
RUN cd /root/tools && git clone --depth 1 https://github.com/jerdna-regeiz/splitmind

# Install libc-database
RUN cd /root/tools && git clone --depth 1 https://github.com/niklasb/libc-database

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
