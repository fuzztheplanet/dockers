FROM ubuntu:latest

# Core packages. apt-get, not apt: apt has no stable CLI and warns as much in
# non-interactive use. `apt autopurge` with no package was a no-op.
RUN apt-get update && apt-get -y upgrade && \
    DEBIAN_FRONTEND=noninteractive apt-get install -qy \
    bash curl git jq nano tmux wget \
    tzdata locales unzip && \
    apt-get -y autoremove && apt-get clean && rm -rf /var/lib/apt/lists/*

# Without this the container runs under POSIX/C and mangles UTF-8 tool output.
ENV LANG=C.UTF-8

# Copy local configuration files
COPY common/bashrc    /root/.bashrc
COPY common/tmux.conf /root/.tmux.conf

# Set workdir
WORKDIR /work
CMD ["/bin/bash"]
