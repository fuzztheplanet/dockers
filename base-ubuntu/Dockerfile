FROM ubuntu:latest

RUN apt-get update && apt-get -y upgrade && \
    DEBIAN_FRONTEND=noninteractive apt-get install -qy \
    bash curl git jq nano tmux wget \
    tzdata locales unzip && \
    apt-get -y autoremove && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV LANG=C.UTF-8

COPY common/bashrc    /root/.bashrc
COPY common/tmux.conf /root/.tmux.conf

WORKDIR /work
CMD ["/bin/bash"]
