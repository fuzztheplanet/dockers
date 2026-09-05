FROM archlinux:latest

# Core packages
RUN pacman --noconfirm -Syu --needed \
    bash curl git jq nano tmux wget man-pages && \
    rm -rf /var/cache/pacman/pkg/*

# Set locale — generating it is not enough, LANG has to point at it or every
# child image runs under POSIX/C and mangles UTF-8 output.
RUN echo en_US.UTF-8 UTF-8 > /etc/locale.gen && locale-gen
ENV LANG=en_US.UTF-8

# Copy local configuration files
COPY common/bashrc    /root/.bashrc
COPY common/tmux.conf /root/.tmux.conf

# Set workdir
WORKDIR /work
CMD ["/bin/bash"]
