FROM ubuntu:latest

# Core packages
RUN apt -y update && apt -y upgrade && DEBIAN_FRONTEND=noninteractive apt -qy install \
    bash curl git jq nano tmux wget \
    tzdata locales unzip && \
    apt -y autoremove && apt -y autoclean && apt -y autopurge

# Copy local configuration files
COPY common/bashrc    /root/.bashrc
COPY common/tmux.conf /root/tmux.conf

# Set workdir
WORKDIR /work
CMD ["/bin/bash"]
