FROM archlinux:latest

# Core packages
RUN pacman --noconfirm -Syu \
    bash curl git jq nano tmux wget man-pages && \
    pacman --noconfirm -Sc && pacman --noconfirm -Scc

# Set local
RUN echo en_US.UTF-8 UTF-8 > /etc/locale.gen && locale-gen

# Copy local configuration files
COPY common/bashrc    /root/.bashrc
COPY common/tmux.conf /root/tmux.conf

# Set workdir
WORKDIR /work
CMD ["/bin/bash"]
