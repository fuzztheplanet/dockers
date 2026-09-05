FROM alpine:latest

# Core packages (--no-cache fetches the index itself; a preceding `apk update`
# only downloads it twice)
RUN apk add --no-cache \
    bash curl git jq nano tmux wget \
    binutils coreutils \
    python3 py3-pip

# Copy local configuration files
COPY common/bashrc    /root/.bashrc
COPY common/tmux.conf /root/.tmux.conf

# Set workdir
WORKDIR /work
CMD ["/bin/bash"]
