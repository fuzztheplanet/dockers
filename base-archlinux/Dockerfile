FROM archlinux:latest

RUN pacman --noconfirm -Syu --needed \
    bash curl git jq nano tmux wget man-pages && \
    rm -rf /var/cache/pacman/pkg/*

RUN echo en_US.UTF-8 UTF-8 > /etc/locale.gen && locale-gen
ENV LANG=en_US.UTF-8

COPY common/bashrc    /root/.bashrc
COPY common/tmux.conf /root/.tmux.conf

WORKDIR /work
CMD ["/bin/bash"]
