# skw/web — CLI tooling for testing web applications, all built on a single
# Alpine image (skw/base-alpine). The Go toolchain is installed, used to build
# ffuf + nomore403, then removed together with every build cache in the same
# layer, so none of it ships. Built from the repo root: make web

FROM skw/base-alpine

LABEL org.opencontainers.image.title="web" \
      org.opencontainers.image.description="web app testing CLI tools: ffuf, nomore403, sqlmap, bypass-url-parser, batchql, arjun"

# /root/.local/bin: where pipx exposes app entrypoints.
ENV HOME=/root \
    PATH="/usr/local/bin:/root/.local/bin:${PATH}" \
    PIP_NO_CACHE_DIR=1

# base-alpine already ships python3/py3-pip/curl/git. Add pipx (isolated venvs
# for the Python CLIs) and py3-requests (requests + urllib3 for batchql, from
# the system interpreter, so that one script needs no venv). curl is required at
# runtime by bypass-url-parser.
RUN apk add --no-cache pipx py3-requests

# --- Go tools -------------------------------------------------------------
# Go is added as a throwaway virtual package and removed in the SAME RUN, along
# with the module cache and build cache, so the ~500MB toolchain never lands in
# a committed layer. CGO off => static binaries; GOTOOLCHAIN=auto lets Go fetch
# a newer toolchain if a module needs one. ffuf: a plain go install. nomore403:
# built from a clone because it reads its payload lists from a folder at runtime
# (go install would not ship them) — the payloads/ dir stays under /opt.
RUN apk add --no-cache --virtual .gobuild go \
    && export CGO_ENABLED=0 GOFLAGS=-buildvcs=false GOTOOLCHAIN=auto \
       GOBIN=/usr/local/bin GOPATH=/root/go GOCACHE=/root/.cache/go-build \
    && go install -v -ldflags="-s -w" github.com/ffuf/ffuf/v2@latest \
    && git clone --depth 1 https://github.com/devploit/nomore403 /opt/nomore403 \
    && ( cd /opt/nomore403 && go build -ldflags="-s -w" -o nomore403 . ) \
    && rm -rf /opt/nomore403/.git \
    && apk del .gobuild \
    && rm -rf /root/go /root/.cache/go-build

# nomore403 defaults to ./payloads relative to the working directory (/work).
# Wrap it so the shipped list is used unless the caller passes their own -f.
RUN printf '%s\n' \
        '#!/bin/sh' \
        '# Point nomore403 at its bundled payloads unless the caller set -f/--folder.' \
        'for a in "$@"; do' \
        '  case "$a" in -f|--folder) exec /opt/nomore403/nomore403 "$@";; esac' \
        'done' \
        'exec /opt/nomore403/nomore403 -f /opt/nomore403/payloads "$@"' \
        > /usr/local/bin/nomore403 \
    && chmod +x /usr/local/bin/nomore403

# --- sqlmap (git clone is upstream's recommended install; wrap with python3 so
#     it does not depend on a bare `python` on PATH) ------------------------
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap /opt/sqlmap \
    && rm -rf /opt/sqlmap/.git \
    && printf '%s\n' '#!/bin/sh' 'exec python3 /opt/sqlmap/sqlmap.py "$@"' \
        > /usr/local/bin/sqlmap \
    && chmod +x /usr/local/bin/sqlmap

# --- batchql (single script: python batch.py, needs requests + urllib3) ---
RUN git clone --depth 1 https://github.com/assetnote/batchql /opt/batchql \
    && rm -rf /opt/batchql/.git \
    && printf '%s\n' '#!/bin/sh' 'exec python3 /opt/batchql/batch.py "$@"' \
        > /usr/local/bin/batchql \
    && chmod +x /usr/local/bin/batchql

# --- pipx apps: each isolated in its own venv, entrypoints on PATH ---------
# bypass-url-parser (needs curl), arjun (param discovery).
RUN pipx install bypass-url-parser \
    && pipx install arjun \
    && rm -rf /root/.cache

WORKDIR /work
CMD ["/bin/bash"]
