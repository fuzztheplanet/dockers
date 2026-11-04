FROM skw/base-archlinux

ENV PATH="$PATH:/root/.local/bin"

# Proxychains, smbclient, pip(x), impacket, bloodyAD, bloodhound, nxc, certipy,
# ldeep, AD Miner, DonPAPI, krbrelayx, PetitPotam
# AD Miner pins NumPy 2.1.1, which does not build on Arch's Python 3.14; the
# local source checkout retains the NumPy 2.x API while allowing a newer wheel.
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
        coercer certipy-ad \
        ldeep \
        git+https://github.com/login-securite/DonPAPI.git && \
    pipx inject impacket ldap3-ad-auth && \
    mkdir -p /root/tools && \
    git clone --depth 1 https://github.com/AD-Security/AD_Miner /tmp/ad-miner && \
    sed -i 's/numpy = "==2.1.1"/numpy = ">=2.1.1,<3"/' /tmp/ad-miner/pyproject.toml && \
    pipx install /tmp/ad-miner && \
    rm -rf /tmp/ad-miner && \
    git clone --depth 1 https://github.com/dirkjanm/krbrelayx /root/tools/krbrelayx && \
    pacman --noconfirm -Rns base-devel rust && \
    rm -rf /var/cache/pacman/pkg/* /root/.cargo /root/.cache

# Run the krbrelayx toolkit with Impacket's isolated Python environment.
COPY ad/scripts/krbrelayx-tool /usr/local/bin/krbrelayx-tool
RUN chmod +x /usr/local/bin/krbrelayx-tool && \
    for tool in addspn dnstool krbrelayx printerbug; do \
        ln -s /usr/local/bin/krbrelayx-tool "/usr/local/bin/$tool"; \
        ln -s /usr/local/bin/krbrelayx-tool "/usr/local/bin/$tool.py"; \
    done

# PetitPotam
RUN git clone --depth 1 https://github.com/topotam/PetitPotam /root/tools/petitpotam && \
    chmod +x /root/tools/petitpotam/PetitPotam.py
COPY ad/scripts/petitpotam-tool /usr/local/bin/petitpotam-tool
RUN chmod +x /usr/local/bin/petitpotam-tool && \
    ln -s /usr/local/bin/petitpotam-tool /usr/local/bin/petitpotam && \
    ln -s /usr/local/bin/petitpotam-tool /usr/local/bin/PetitPotam.py

COPY common/proxychains.conf /etc/proxychains.conf

WORKDIR /work
CMD ["/bin/bash"]
