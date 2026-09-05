FROM skw/base-archlinux

# Arch packages + pipx, in a single -Syu transaction: splitting them across
# layers (and using a bare -S against the base image's stale DB) is a partial
# upgrade, which 404s on package files as soon as the mirrors rotate.
RUN pacman --noconfirm -Syu --needed \
    base-devel rust \
    proxychains \
    smbclient krb5 \
    python-pip python-pipx python-uv && \
    rm -rf /var/cache/pacman/pkg/* && \
    pipx ensurepath
ENV PATH="$PATH:/root/.local/bin"

# Pipx packages
RUN pipx upgrade-all && PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 pipx install \
    git+https://github.com/fortra/impacket \
    bloodyAD==2.1.23 autobloody \
    bloodhound bloodhound-ce \
    git+https://github.com/Pennyw0rth/NetExec \
    coercer certipy-ad

# /root/tools contains manually installed tools
RUN mkdir /root/tools

# Responder
RUN git clone --depth 1 https://github.com/lgandx/responder /root/tools/responder && \
    cd /root/tools/responder && \
    pip install --break-system-packages -r requirements.txt
ENV PATH="$PATH:/root/tools/responder"

# PetitPotam
RUN git clone --depth 1 https://github.com/topotam/PetitPotam /root/tools/petitpotam && \
    chmod +x /root/tools/petitpotam/PetitPotam.py
ENV PATH="$PATH:/root/tools/petitpotam"

# Copy custom config files
COPY common/proxychains.conf /etc/proxychains.conf

# Set workdir
WORKDIR /work
CMD ["/bin/bash"]
