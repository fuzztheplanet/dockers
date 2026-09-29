FROM alpine:latest

RUN apk add --no-cache \
    bash curl git jq nano tmux wget \
    binutils coreutils \
    python3 py3-pip

COPY common/bashrc    /root/.bashrc
COPY common/tmux.conf /root/.tmux.conf

WORKDIR /work
CMD ["/bin/bash"]
