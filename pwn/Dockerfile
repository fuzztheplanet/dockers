FROM skw/base-archlinux

# Store tools under /root/tools
RUN mkdir /root/tools

RUN pacman --noconfirm -Syu base-devel && \
    pacman --noconfirm -Scc && pacman --noconfirm -Sc

# Setup pipx
RUN pacman --noconfirm -Syu python-pip python-pipx python-uv && \
    pacman --noconfirm -Scc && pacman --noconfirm -Sc && \
    pipx ensurepath

# Various tools and dependencies
RUN pacman --noconfirm -Syu cmake binutils rust libedit sagemath ruby \
    strace ltrace nasm yasm gdb elfutils binwalk openssl && \
    pacman --noconfirm -Scc && pacman --noconfirm -Sc

# Install angr, z3 and sagemath for Python
RUN pip install --break-system-packages --upgrade \
    angr z3-solver sagemath

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
RUN cd /root/tools && \
    git clone https://github.com/pwndbg/pwndbg && \
    cd pwndbg && echo n | ./setup.sh && \
    cd /root/tools

# Install GEF
RUN mkdir /root/tools/gef && \
    wget -q https://raw.githubusercontent.com/bata24/gef/dev/gef.py -O /root/tools/gef/gef.py && \
    cd /root/tools

# Install dcomp2dbg
RUN cd /root/tools && git clone https://github.com/mahaloz/decomp2dbg.git && \
    cd decomp2dbg && \
    pip install --break-system-packages . && python setup.py install

# Install rappel
RUN cd /root/tools && git clone https://github.com/yrp604/rappel && \
    cd rappel && make && cp bin/rappel /usr/local/bin/rappel

# Install splitmind
RUN cd /root/tools && git clone https://github.com/jerdna-regeiz/splitmind

# Install libc-database
RUN cd /root/tools && git clone https://github.com/niklasb/libc-database

# Copy local scripts
COPY pwn/files/gdbinit /root/.gdbinit
COPY pwn/files/gdb-gef /usr/bin/gdb-gef
COPY pwn/files/gdb-pwndbg /usr/bin/gdb-pwndbg

# Done!
WORKDIR /work
CMD ["/bin/bash"]
