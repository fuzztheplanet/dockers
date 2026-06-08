FROM skw/base-archlinux

# Arch Packages
RUN pacman --noconfirm -S base-devel go bind && \
    pacman --noconfirm -Scc && pacman --noconfirm -Sc

RUN mkdir /root/tools
ENV PATH="$PATH:/root/go/bin"

# Amass (https://github.com/owasp-amass/amass)
RUN CGO_ENABLED=0 go install -v github.com/owasp-amass/amass/v5/cmd/amass@main

# GAU (https://github.com/lc/gau)
RUN go install github.com/lc/gau/v2/cmd/gau@latest

# MassDNS (https://github.com/blechschmidt/massdns)
RUN git clone https://github.com/blechschmidt/massdns /root/tools/massdns && \
    cd /root/tools/massdns && make && cp /root/tools/massdns/bin/massdns /usr/local/bin/

# Subfinder (https://github.com/projectdiscovery/subfinder)
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# unfurl (https://github.com/tomnomnom/unfurl)
RUN go install github.com/tomnomnom/unfurl@latest

# httpx (https://github.com/projectdiscovery/httpx)
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# gowitness (https://github.com/sensepost/gowitness)
RUN go install github.com/sensepost/gowitness@latest

# Cleanup go packages
RUN go clean -cache -modcache

# Copy custom scripts
COPY recon/scripts/ /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh

# Copy custom config
COPY common/* /root/

WORKDIR /work
CMD ["/bin/bash"]
