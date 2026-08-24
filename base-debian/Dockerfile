FROM debian:12-slim

# Core packages — kept in line with the other base images.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash curl git jq nano tmux wget \
        ca-certificates locales tzdata \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy local configuration files
COPY common/bashrc    /root/.bashrc
COPY common/tmux.conf /root/tmux.conf

# Set workdir
WORKDIR /work
CMD ["/bin/bash"]
