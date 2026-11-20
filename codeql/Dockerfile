FROM skw/base-debian

# Python, JS/TS and Ruby are extracted straight from source, but their extractors
# still call out to python3 and node. Compiled languages are only as good as the
# build that runs in here, so the image also carries their toolchains. fzf and
# less are for codeql-findings.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        zstd unzip fzf less \
        python3 nodejs \
        build-essential clang cmake ninja-build pkg-config autoconf automake libtool \
        golang-go \
        default-jdk-headless maven \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Debian's Go defaults to GOTOOLCHAIN=local. auto lets a go.mod that asks for a
# newer Go download it, instead of failing the autobuild.
ENV GOTOOLCHAIN=auto

# The bundle is the CLI, every extractor and the standard query packs already
# compiled, so the stock suites run with no network. The ARG sits here rather
# than at the top so that bumping it leaves the apt layer cached.
# The tarball ships the precompiled queries (.codeql/precompiled/*.qlx) as 0600,
# which root's tar keeps: any other uid then can't read them, has to compile
# every query from source and runs out of heap. Hence the chmod.
# Releases: https://github.com/github/codeql-action/releases
ARG CODEQL_VERSION=2.27.5
RUN curl -fsSL \
      "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.zst" \
      | tar --zstd -xf - -C /opt && \
    chmod -R a+rX /opt/codeql && \
    ln -s /opt/codeql/codeql /usr/local/bin/codeql && \
    codeql resolve languages

# The aliases run this image as your uid, which has no passwd entry and cannot
# use /root. HOME is sticky and world-writable instead, like /tmp, so CodeQL and
# the build tools have somewhere to cache. It goes away with the container.
# Set only after the RUN above, so nothing root-owned gets created inside it.
RUN mkdir -m 1777 /home/codeql && cp /root/.bashrc /root/.tmux.conf /home/codeql/
ENV HOME=/home/codeql

# The skw-codeql skill's database discovery, run in here where codeql exists,
# and a SARIF viewer. Last, so editing them doesn't rebuild the layers above.
COPY codeql/find_databases.sh /usr/local/bin/find_databases.sh
COPY codeql/codeql-findings.py /usr/local/bin/codeql-findings

WORKDIR /work
ENTRYPOINT ["codeql"]
