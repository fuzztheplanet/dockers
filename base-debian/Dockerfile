FROM debian:13-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash curl git jq nano tmux wget \
        ca-certificates locales tzdata \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV LANG=C.UTF-8

COPY common/bashrc    /root/.bashrc
COPY common/tmux.conf /root/.tmux.conf

WORKDIR /work
CMD ["/bin/bash"]
