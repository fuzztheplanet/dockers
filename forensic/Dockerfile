FROM skw/base-archlinux

# Arch Packages
RUN pacman --noconfirm -S base-devel \
    binwalk foremost volatility3 \
    perl-image-exiftool \
    libewf \
    python-minidump && \
    pacman --noconfirm -Scc && pacman --noconfirm -Sc

# /root/tools contains manually installed tools
RUN mkdir /root/tools

# angecryption.py
RUN pacman --noconfirm -S python-pycryptodome python-termcolor \
    && curl -o /usr/local/bin/angecryption.py \
    https://raw.githubusercontent.com/1sis/Angecryption/refs/heads/main/angecryption.py \
    && chmod +x /usr/local/bin/angecryption.py

# bmc-tools.py
RUN curl -o /usr/local/bin/bmc-tools.py \
    https://raw.githubusercontent.com/ANSSI-FR/bmc-tools/refs/heads/master/bmc-tools.py \
    && chmod +x /usr/local/bin/bmc-tools.py

# coldboot attacks (aesfix & aeskeyfind)
RUN git clone https://github.com/DonnchaC/coldboot-attacks /root/tools/coldboot-attacks && \
    cd /root/tools/coldboot-attacks && find . -type f -name '*.tar.gz' -exec tar zxvf {} \; && \
    cd aesfix && make && cd .. && \
    cd aeskeyfind && make && cd .. && \
    cp aesfix/aesfix aeskeyfind/aeskeyfind /usr/local/bin/

# keepass-dump-masterkey.py
RUN curl -o /usr/local/bin/keepass-dump-masterkey.py \
    https://raw.githubusercontent.com/matro7sh/keepass-dump-masterkey/refs/heads/main/poc.py \
    && chmod +x /usr/local/bin/keepass-dump-masterkey.py \
    && sed -i '1s/^/#!\/usr\/bin\/env python\n/' /usr/local/bin/keepass-dump-masterkey.py

# Copy custom volatility symbols
COPY forensic/symbols /symbols

# Set workdir
WORKDIR /work
CMD ["/bin/bash"]
