FROM alpine:latest

# Core package
RUN apk update && apk add --no-cache \
    bash curl git jq nano tmux wget \
    binutils coreutils \
    python3 py3-pip

# Copy local configuration files
COPY common/bashrc    /root/.bashrc
COPY common/tmux.conf /root/tmux.conf

# Set workdir
WORKDIR /work
CMD ["/bin/bash"]
