FROM skw/base-archlinux

ENV PATH="$PATH:/root/.local/bin"

# Proxychains, smbclient, pip(x), impacket, bloodyAD, bloodhound, nxc, certipy,
# responder
RUN pacman --noconfirm -Syu --needed \
        proxychains \
        smbclient krb5 \
        python-pip python-pipx \
        base-devel rust && \
    pipx ensurepath && \
    PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 pipx install \
        git+https://github.com/fortra/impacket \
        bloodyAD==2.1.23 autobloody \
        bloodhound bloodhound-ce \
        git+https://github.com/Pennyw0rth/NetExec \
        coercer certipy-ad && \
    mkdir -p /root/tools && \
    git clone --depth 1 https://github.com/lgandx/responder /root/tools/responder && \
    pip install --break-system-packages -r /root/tools/responder/requirements.txt && \
    pacman --noconfirm -Rns base-devel rust && \
    rm -rf /var/cache/pacman/pkg/* /root/.cargo /root/.cache

ENV PATH="$PATH:/root/tools/responder"

# PetitPotam
RUN git clone --depth 1 https://github.com/topotam/PetitPotam /root/tools/petitpotam && \
    chmod +x /root/tools/petitpotam/PetitPotam.py
ENV PATH="$PATH:/root/tools/petitpotam"

COPY common/proxychains.conf /etc/proxychains.conf

WORKDIR /work
CMD ["/bin/bash"]
