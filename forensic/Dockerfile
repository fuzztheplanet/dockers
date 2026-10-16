FROM skw/base-archlinux

RUN pacman --noconfirm -Syu --needed base-devel && \
    rm -rf /var/cache/pacman/pkg/*

# Binwalk, foremost, vol3, tshark, unsquashfs
RUN pacman --noconfirm -Syu --needed \
    binwalk foremost volatility3 \
    perl-image-exiftool \
    libewf squashfs-tools \
    wireshark-cli \
    python-minidump \
    python-pycryptodome python-termcolor \
    gcc-libs && \
    rm -rf /var/cache/pacman/pkg/*

# aesfix and aeskeyfind
RUN git clone --depth 1 https://github.com/DonnchaC/coldboot-attacks /tmp/coldboot && \
    cd /tmp/coldboot && \
    for t in aesfix aeskeyfind; do tar zxf "$t"-*.tar.gz; done && \
    make -C aesfix && make -C aeskeyfind && \
    cp aesfix/aesfix aeskeyfind/aeskeyfind /usr/local/bin/


# angecryption.py
RUN curl -o /usr/local/bin/angecryption.py \
    https://raw.githubusercontent.com/1sis/Angecryption/refs/heads/main/angecryption.py \
    && chmod +x /usr/local/bin/angecryption.py

# bmc-tools.py
RUN curl -o /usr/local/bin/bmc-tools.py \
    https://raw.githubusercontent.com/ANSSI-FR/bmc-tools/refs/heads/master/bmc-tools.py \
    && chmod +x /usr/local/bin/bmc-tools.py

# keepass-dump-masterkey.py
RUN curl -o /usr/local/bin/keepass-dump-masterkey.py \
    https://raw.githubusercontent.com/matro7sh/keepass-dump-masterkey/refs/heads/main/poc.py \
    && chmod +x /usr/local/bin/keepass-dump-masterkey.py \
    && sed -i '1s/^/#!\/usr\/bin\/env python\n/' /usr/local/bin/keepass-dump-masterkey.py

# Volatility symbols
COPY forensic/symbols /symbols

RUN S="$(python -c 'import volatility3, os; print(os.path.join(os.path.dirname(volatility3.__file__), "symbols"))')" \
    && mkdir -p "$S/linux" \
    && ln -s /symbols/linux/*.json.xz "$S/linux/"

# Add perl (exiftools & co) to PATH
ENV PATH="/usr/bin/vendor_perl:/usr/bin/site_perl:/usr/bin/core_perl:${PATH}"

WORKDIR /work
CMD ["/bin/bash"]
