FROM skw/base-archlinux

# Arch packages — one -Syu for the whole image (python-pycryptodome and
# python-termcolor are angecryption.py's runtime deps; installing them in a
# later layer would be a partial upgrade against a stale DB).
RUN pacman --noconfirm -Syu --needed \
    base-devel \
    binwalk foremost volatility3 \
    perl-image-exiftool \
    libewf \
    wireshark-cli \
    python-minidump \
    python-pycryptodome python-termcolor && \
    rm -rf /var/cache/pacman/pkg/*

# /root/tools contains manually installed tools
RUN mkdir /root/tools

# angecryption.py
RUN curl -o /usr/local/bin/angecryption.py \
    https://raw.githubusercontent.com/1sis/Angecryption/refs/heads/main/angecryption.py \
    && chmod +x /usr/local/bin/angecryption.py

# bmc-tools.py
RUN curl -o /usr/local/bin/bmc-tools.py \
    https://raw.githubusercontent.com/ANSSI-FR/bmc-tools/refs/heads/master/bmc-tools.py \
    && chmod +x /usr/local/bin/bmc-tools.py

# coldboot attacks (aesfix & aeskeyfind)
RUN git clone --depth 1 https://github.com/DonnchaC/coldboot-attacks /root/tools/coldboot-attacks && \
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

# Link the symbols to volatility3's own search path
RUN S="$(python -c 'import volatility3, os; print(os.path.join(os.path.dirname(volatility3.__file__), "symbols"))')" \
    && mkdir -p "$S/linux" \
    && ln -s /symbols/linux/*.json.xz "$S/linux/"

# Add perl scripts (exiftool, ...) to $PATH
ENV PATH="/usr/bin/vendor_perl:/usr/bin/site_perl:/usr/bin/core_perl:${PATH}"

# Set workdir
WORKDIR /work
CMD ["/bin/bash"]
