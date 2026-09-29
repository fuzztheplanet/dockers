# Stage 1 builds the Go tools; stage 2 is skw/base-alpine plus the Python tools
# and receives only the finished binaries. Chromium is baked in so katana
# -headless works with no browser on the host.

FROM golang:1.26-alpine AS builder

# CGO off => static binaries. -ldflags "-s -w" drops symbols/DWARF at link time.
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOBIN=/out/bin \
    GOFLAGS=-buildvcs=false \
    GOTOOLCHAIN=auto
ARG GO_LDFLAGS="-s -w"

# git: module fetches + the clones below. gcc/musl-dev: katana and jsluice
# embed tree-sitter, so those two are cgo builds.
RUN apk add --no-cache git gcc musl-dev \
    && mkdir -p /out/bin

# One layer per group so an upstream breakage does not invalidate everything.

# content discovery / 40X bypass
RUN go install -v -ldflags="$GO_LDFLAGS" github.com/ffuf/ffuf/v2@latest

# nomore403 needs its payloads/ folder at runtime and go install would not ship
# it, so build from a clone and keep both.
RUN git clone --depth 1 https://github.com/devploit/nomore403 /tmp/nomore403 \
    && ( cd /tmp/nomore403 && go build -ldflags="$GO_LDFLAGS" -o nomore403 . ) \
    && mkdir -p /out/nomore403 \
    && mv /tmp/nomore403/nomore403 /tmp/nomore403/payloads /out/nomore403/ \
    && rm -rf /tmp/nomore403

# URL / endpoint discovery
RUN go install -v -ldflags="$GO_LDFLAGS" github.com/lc/gau/v2/cmd/gau@latest \
 && go install -v -ldflags="$GO_LDFLAGS" github.com/lc/subjs@latest \
 && go install -v -ldflags="$GO_LDFLAGS" github.com/denandz/sourcemapper@latest \
 && go install -v -ldflags="$GO_LDFLAGS" github.com/tomnomnom/anew@latest \
 && go install -v -ldflags="$GO_LDFLAGS" github.com/tomnomnom/unfurl@latest

# crawling + JS analysis. Both link tree-sitter, so CGO is on here.
# -linkmode external forces the system linker: without it Go links small cgo
# packages internally and silently ignores -extldflags. The static musl link is
# what lets the runtime image ship nothing but the binary.
RUN CGO_ENABLED=1 go install -v -ldflags="$GO_LDFLAGS -linkmode external -extldflags -static" \
        github.com/projectdiscovery/katana/cmd/katana@latest
        
RUN CGO_ENABLED=1 go install -v -ldflags="$GO_LDFLAGS -linkmode external -extldflags -static" \
        github.com/BishopFox/jsluice/cmd/jsluice@latest

# payload rewriting + XSS. gf is driven by the pattern files baked in below.
RUN go install -v -ldflags="$GO_LDFLAGS" github.com/tomnomnom/qsreplace@latest \
 && go install -v -ldflags="$GO_LDFLAGS" github.com/tomnomnom/gf@latest \
 && go install -v -ldflags="$GO_LDFLAGS" github.com/hahwul/dalfox/v2@latest

# nuclei; its templates are baked into the runtime stage.
RUN go install -v -ldflags="$GO_LDFLAGS" github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# takeover + reflection
RUN go install -v -ldflags="$GO_LDFLAGS" github.com/PentestPad/subzy@latest \
 && go install -v -ldflags="$GO_LDFLAGS" github.com/KathanP19/Gxss@latest \
 && go install -v -ldflags="$GO_LDFLAGS" github.com/Emoe/kxss@latest

# trufflehog's go.mod carries replace directives, which go install refuses, so
# build it from a clone like nomore403.
RUN git clone --depth 1 https://github.com/trufflesecurity/trufflehog /tmp/trufflehog \
    && ( cd /tmp/trufflehog && go build -ldflags="$GO_LDFLAGS" -o /out/bin/trufflehog . ) \
    && rm -rf /tmp/trufflehog

# ==========================================================================
FROM skw/base-alpine

LABEL org.opencontainers.image.title="web" \
      org.opencontainers.image.description="web app testing CLI tools: ffuf, nomore403, sqlmap, sstimap, bypass-url-parser, batchql, arjun, paramspider, clairvoyance, katana, gau, waymore, uro, subjs, jsluice, xnLinkFinder, sourcemapper, js-beautify, anew, unfurl, qsreplace, gf, dalfox, nuclei, subzy, Gxss, kxss, corsy, git-dumper, trufflehog, jwt_tool, dig"

# /root/.local/bin: where pipx exposes app entrypoints.
ENV HOME=/root \
    PATH="/usr/local/bin:/root/.local/bin:${PATH}" \
    PIP_NO_CACHE_DIR=1

# pipx: isolated venvs for the Python CLIs. py3-requests: lets batchql run off
# the system interpreter. bind-tools: dig/host for DNS and AXFR checks.
RUN apk add --no-cache pipx py3-requests bind-tools

# chromium for katana -headless/-hybrid, ~760MB and always on: this image is
# meant to run on servers with no browser of their own. ttf-freefont gives it
# one font so text layout works. The build fails if it cannot render a page.
RUN apk add --no-cache chromium ttf-freefont \
    && chromium --headless --no-sandbox --disable-gpu --disable-dev-shm-usage \
           --dump-dom about:blank 2>/dev/null | grep -q '<html' \
    || { echo "ERROR: headless chromium does not run" >&2; exit 1; } \
    && rm -rf /root/.config/chromium /tmp/org.chromium.*

COPY --from=builder /out/bin/ /usr/local/bin/
COPY --from=builder /out/nomore403/ /opt/nomore403/

# Templates baked in, as in skw/recon: scans run with -disable-update-check, so
# they have to be here at build time. The build fails on an empty set.
RUN nuclei -update-templates \
    && [ -d "$HOME/nuclei-templates" ] \
    && [ -n "$(find "$HOME/nuclei-templates" -name '*.yaml' -print -quit)" ] \
    || { echo "ERROR: nuclei templates failed to install" >&2; exit 1; }

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

# sqlmap: the clone is upstream's recommended install, and the wrapper avoids
# depending on a bare `python` on PATH.
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap /opt/sqlmap \
    && rm -rf /opt/sqlmap/.git \
    && printf '%s\n' '#!/bin/sh' 'exec python3 /opt/sqlmap/sqlmap.py "$@"' \
        > /usr/local/bin/sqlmap \
    && chmod +x /usr/local/bin/sqlmap

# batchql is a single script and needs requests + urllib3.
RUN git clone --depth 1 https://github.com/assetnote/batchql /opt/batchql \
    && rm -rf /opt/batchql/.git \
    && printf '%s\n' '#!/bin/sh' 'exec python3 /opt/batchql/batch.py "$@"' \
        > /usr/local/bin/batchql \
    && chmod +x /usr/local/bin/batchql

# corsy gets its own venv so its deps never collide with the system ones.
RUN git clone --depth 1 https://github.com/s0md3v/Corsy /opt/corsy \
    && rm -rf /opt/corsy/.git \
    && python3 -m venv /opt/corsy/.venv \
    && /opt/corsy/.venv/bin/pip install requests tld \
    && printf '%s\n' '#!/bin/sh' 'exec /opt/corsy/.venv/bin/python /opt/corsy/corsy.py "$@"' \
        > /usr/local/bin/corsy \
    && chmod +x /usr/local/bin/corsy \
    && rm -rf /root/.cache

# jwt_tool: own venv, wrapped like sqlmap.
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool \
    && rm -rf /opt/jwt_tool/.git \
    && python3 -m venv /opt/jwt_tool/.venv \
    && /opt/jwt_tool/.venv/bin/pip install -r /opt/jwt_tool/requirements.txt \
    && printf '%s\n' '#!/bin/sh' 'exec /opt/jwt_tool/.venv/bin/python /opt/jwt_tool/jwt_tool.py "$@"' \
        > /usr/local/bin/jwt_tool \
    && chmod +x /usr/local/bin/jwt_tool \
    && /opt/jwt_tool/.venv/bin/python /opt/jwt_tool/jwt_tool.py -h >/dev/null \
    && rm -rf /root/.cache

# SSTImap: own venv, wrapped like sqlmap. The -h smoke test runs from /work to
# prove it finds its core/ and plugins/ packages from any working directory.
RUN git clone --depth 1 https://github.com/vladko312/SSTImap /opt/sstimap \
    && rm -rf /opt/sstimap/.git \
    && python3 -m venv /opt/sstimap/.venv \
    && /opt/sstimap/.venv/bin/pip install -r /opt/sstimap/requirements.txt \
    && printf '%s\n' '#!/bin/sh' 'exec /opt/sstimap/.venv/bin/python /opt/sstimap/sstimap.py "$@"' \
        > /usr/local/bin/sstimap \
    && chmod +x /usr/local/bin/sstimap \
    && sstimap -h >/dev/null \
    && rm -rf /root/.cache

# pipx apps: each isolated in its own venv, entrypoints on PATH.
RUN pipx install bypass-url-parser \
    && pipx install arjun \
    && pipx install clairvoyance \
    && rm -rf /root/.cache

RUN pipx install git+https://github.com/devanshbatham/paramspider.git \
    && pipx install git-dumper \
    && rm -rf /root/.cache

# waymore has no PyPI release, hence the git URL.
RUN pipx install uro \
    && pipx install jsbeautifier \
    && pipx install git+https://github.com/xnl-h4ck3r/waymore.git \
    && rm -rf /root/.cache

# xnLinkFinder declares playwright, which has no musl wheel. It is only used
# lazily by --heap, so install the package without deps and list the rest by
# hand (pipx can't: --no-deps makes it abort on the missing metadata). --heap is
# therefore unsupported here. Keep the list in sync with upstream setup.py.
RUN python3 -m venv /opt/xnlinkfinder \
    && /opt/xnlinkfinder/bin/pip install --no-deps git+https://github.com/xnl-h4ck3r/xnLinkFinder.git \
    && /opt/xnlinkfinder/bin/pip install requests psutil pyyaml termcolor urlparse3 \
           beautifulsoup4 lxml html5lib urllib3 tldextract 'inflect>=7.3.0' pypdf \
    && ln -s /opt/xnlinkfinder/bin/xnLinkFinder /usr/local/bin/xnLinkFinder \
    && xnLinkFinder -h >/dev/null \
    && rm -rf /root/.cache

# waymore writes to DEFAULT_OUTPUT_DIR from its config, which defaults to
# ~/.config/waymore and would be lost with the container. The config is only
# generated on first run, so run it once here and point it at /work.
RUN waymore -h >/dev/null \
    && sed -i 's#^DEFAULT_OUTPUT_DIR:.*#DEFAULT_OUTPUT_DIR: /work#' /root/.config/waymore/config.yml \
    && grep -q '^DEFAULT_OUTPUT_DIR: /work$' /root/.config/waymore/config.yml \
    && rm -f /root/.config/waymore/config.yml.NEW \
    || { echo "ERROR: waymore config.yml not generated/patched" >&2; exit 1; }

# gf reads its patterns from ~/.gf. The build fails if that ends up empty.
RUN mkdir -p /root/.gf \
    && git clone --depth 1 https://github.com/tomnomnom/gf /tmp/gf \
    && git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gfp \
    && cp /tmp/gf/examples/*.json /root/.gf/ \
    && cp /tmp/gfp/*.json /root/.gf/ \
    && rm -rf /tmp/gf /tmp/gfp \
    && [ -n "$(find /root/.gf -name '*.json' -print -quit)" ] \
    || { echo "ERROR: gf patterns not installed" >&2; exit 1; }

# katana only uses a system browser when given -system-chrome-path; otherwise
# rod downloads a glibc chrome that cannot run on Alpine. So the wrapper adds
# that flag (plus -no-sandbox, we run as root) whenever a browser mode is asked
# for, and stays out of the way if the caller already picked one. katana exits 0
# even when it cannot start, so the check below greps its log for [ERR].
RUN printf '%s\n' \
        '#!/bin/sh' \
        '# Point katana at the baked-in chromium whenever a browser mode is requested.' \
        'browser=0; chosen=0' \
        'for a in "$@"; do' \
        '  case "$a" in' \
        '    -hl|-headless|-hh|-hybrid|-sc|-system-chrome) browser=1 ;;' \
        '    -scp|-system-chrome-path|-cwu|-chrome-ws-url) chosen=1 ;;' \
        '  esac' \
        'done' \
        'if [ "$browser" = 1 ] && [ "$chosen" = 0 ]; then' \
        '  exec /usr/local/bin/katana.bin -system-chrome-path /usr/bin/chromium -no-sandbox "$@"' \
        'fi' \
        'exec /usr/local/bin/katana.bin "$@"' \
        > /usr/local/bin/katana \
    && chmod +x /usr/local/bin/katana \
    && katana -headless -u http://127.0.0.1:9/ -timeout 2 -disable-update-check -no-color 2>&1 \
       | tee /tmp/katana-headless.log | { ! grep -q '\[ERR\]' ; } \
    || { cat /tmp/katana-headless.log >&2; echo "ERROR: katana -headless cannot launch the baked-in chromium" >&2; exit 1; } \
    && rm -rf /tmp/katana-headless.log /tmp/katana-chrome-data-* /tmp/leakless-* /tmp/org.chromium.*

WORKDIR /work
CMD ["/bin/bash"]
