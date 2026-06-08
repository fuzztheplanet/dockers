FROM debian:12-slim

# Core packages
RUN apt-get install bash && \
    apt-get purge -y && apt-get remove -y

# Copy local configuration files
COPY common/bashrc /root/.bashrc
COPY common/tmux.conf /root/tmux.conf

# Set workdir
WORKDIR /work
CMD ["/bin/bash"]
