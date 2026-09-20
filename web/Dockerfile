# skw/web — CLI tooling for testing web applications: content discovery, 40X
# bypass, injection (SQLi, SSTI), param/endpoint discovery, JS source analysis,
# plus template-driven detection (nuclei), subdomain-takeover, reflection and
# CORS candidate checks, and secret scanning.
# Stage 1 (golang:alpine) builds the Go tools; stage 2 is skw/base-alpine plus
# the Python tools, receiving only the finished binaries — no toolchain, no
# module cache. Chromium is baked in so katana -headless works out of the box,
# with no browser on the host. Built from the repo root: make web

FROM golang:1.26-alpine AS builder

# CGO off => static binaries; GOTOOLCHAIN=auto lets Go fetch a newer toolchain
# if a module needs one. -ldflags "-s -w" drops symbols/DWARF at link time.
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOBIN=/out/bin \
    GOFLAGS=-buildvcs=false \
    GOTOOLCHAIN=auto
ARG GO_LDFLAGS="-s -w"

# git: module fetches + the nomore403 clone. gcc/musl-dev: katana and jsluice
# embed tree-sitter (C), so those two are cgo builds (see below).
RUN apk add --no-cache git gcc musl-dev \
    && mkdir -p /out/bin

# One layer per group so an upstream breakage does not invalidate everything.

# --- content discovery / 40X bypass ---------------------------------------
RUN go install -v -ldflags="$GO_LDFLAGS" github.com/ffuf/ffuf/v2@latest

# nomore403 reads its payload lists from a folder at runtime (go install would
# not ship them): build from a clone, keep only the binary and payloads/.
RUN git clone --depth 1 https://github.com/devploit/nomore403 /tmp/nomore403 \
    && ( cd /tmp/nomore403 && go build -ldflags="$GO_LDFLAGS" -o nomore403 . ) \
    && mkdir -p /out/nomore403 \
    && mv /tmp/nomore403/nomore403 /tmp/nomore403/payloads /out/nomore403/ \
    && rm -rf /tmp/nomore403

# --- URL / endpoint discovery ---------------------------------------------
# gau: known URLs from wayback/commoncrawl/otx/urlscan. subjs: JS URLs
# out of a URL list. sourcemapper: rebuilds sources from a .js.map. anew/unfurl:
# tomnomnom's dedupe-append and URL-part extractor, the glue between the rest.
RUN go install -v -ldflags="$GO_LDFLAGS" github.com/lc/gau/v2/cmd/gau@latest \
 && go install -v -ldflags="$GO_LDFLAGS" github.com/lc/subjs@latest \
 && go install -v -ldflags="$GO_LDFLAGS" github.com/denandz/sourcemapper@latest \
 && go install -v -ldflags="$GO_LDFLAGS" github.com/tomnomnom/anew@latest \
 && go install -v -ldflags="$GO_LDFLAGS" github.com/tomnomnom/unfurl@latest

# --- crawling + JS analysis (cgo) -----------------------------------------
# katana (crawler; -jc/-jsl parse JS for endpoints) pulls in a jsluice fork and
# jsluice itself (URLs/paths/secrets out of JS via AST) — both link tree-sitter,
# so CGO is on for these two. -linkmode external -extldflags -static: force the
# system linker (Go otherwise links small cgo packages internally and silently
# ignores -extldflags) and make it static against musl, so the runtime image
# needs nothing beyond the binary.
RUN CGO_ENABLED=1 go install -v -ldflags="$GO_LDFLAGS -linkmode external -extldflags -static" \
        github.com/projectdiscovery/katana/cmd/katana@latest \
    && mv /out/bin/katana /out/bin/katana.bin
RUN CGO_ENABLED=1 go install -v -ldflags="$GO_LDFLAGS -linkmode external -extldflags -static" \
        github.com/BishopFox/jsluice/cmd/jsluice@latest

# --- payload rewriting + XSS ----------------------------------------------
# qsreplace: rewrite every query-string value in a URL list (feed one payload).
# gf: tomnomnom's grep wrapper, driven by baked pattern files (see runtime
# stage). dalfox: XSS scanner/validator, takes a URL list on stdin.
RUN go install -v -ldflags="$GO_LDFLAGS" github.com/tomnomnom/qsreplace@latest \
 && go install -v -ldflags="$GO_LDFLAGS" github.com/tomnomnom/gf@latest \
 && go install -v -ldflags="$GO_LDFLAGS" github.com/hahwul/dalfox/v2@latest

# --- detection scan (projectdiscovery) ------------------------------------
# nuclei: template-driven detection (run with the takeover/exposures/misconfig/
# cve tags; templates are baked in the runtime stage).
RUN go install -v -ldflags="$GO_LDFLAGS" github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# --- takeover + reflection ------------------------------------------------
# subzy: subdomain-takeover fingerprinting. Gxss/kxss: reflected-parameter
# detection — send a canary through params and look for it in the response
# (reflection only, no payloads).
RUN go install -v -ldflags="$GO_LDFLAGS" github.com/PentestPad/subzy@latest \
 && go install -v -ldflags="$GO_LDFLAGS" github.com/KathanP19/Gxss@latest \
 && go install -v -ldflags="$GO_LDFLAGS" github.com/Emoe/kxss@latest

# --- trufflehog (secret scan) ---------------------------------------------
# Secret detection over dumped source / fetched JS; always run with
# --no-verification so it detects but never validates a secret against a live
# service. trufflehog's go.mod carries replace directives, so `go install`
# refuses it — build from a shallow clone (replace is allowed for the main
# module), like nomore403, and keep only the binary.
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

# base-alpine already ships python3/py3-pip/curl/git. Add pipx (isolated venvs
# for the Python CLIs) and py3-requests (requests + urllib3 for batchql, from
# the system interpreter, so that one script needs no venv). curl is required at
# runtime by bypass-url-parser. bind-tools: dig/host for DNS + zone-transfer
# (AXFR) checks.
RUN apk add --no-cache pipx py3-requests bind-tools

# chromium for katana -headless/-hybrid (DOM-rendered SPAs). Alpine's package
# pulls in everything the browser links (nss, freetype, harfbuzz, mesa...);
# ttf-freefont gives it at least one font so text layout works. About 760MB on
# disk, always on: the image is meant to run on servers with no browser of
# their own. Verified right here (no network needed): fail the build if the
# browser cannot render a blank page headless.
RUN apk add --no-cache chromium ttf-freefont \
    && chromium --headless --no-sandbox --disable-gpu --disable-dev-shm-usage \
           --dump-dom about:blank 2>/dev/null | grep -q '<html' \
    || { echo "ERROR: headless chromium does not run" >&2; exit 1; } \
    && rm -rf /root/.config/chromium /tmp/org.chromium.*

# --- Go tools, from the builder --------------------------------------------
COPY --from=builder /out/bin/ /usr/local/bin/
COPY --from=builder /out/nomore403/ /opt/nomore403/

# nuclei templates, baked in (same rationale as skw/recon): scans should run
# offline with -disable-update-check, so the template set must be present at
# build time. Fail the build if it ends up empty, so a template-less nuclei can
# never ship. Rebuild the image to refresh templates.
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

# --- corsy (CORS misconfiguration: single script corsy.py). Give it its own
#     venv so its deps never collide with the system interpreter. Detects the
#     dangerous reflected-origin + credentials combination. -----------------
RUN git clone --depth 1 https://github.com/s0md3v/Corsy /opt/corsy \
    && rm -rf /opt/corsy/.git \
    && python3 -m venv /opt/corsy/.venv \
    && /opt/corsy/.venv/bin/pip install requests tld \
    && printf '%s\n' '#!/bin/sh' 'exec /opt/corsy/.venv/bin/python /opt/corsy/corsy.py "$@"' \
        > /usr/local/bin/corsy \
    && chmod +x /usr/local/bin/corsy \
    && rm -rf /root/.cache

# --- jwt_tool (DECODE/inspect JWTs and flag alg:none / weak signing; never
#     used to crack or forge against a live service). venv with its runtime
#     deps, wrapped like sqlmap. -----------------------------------------------
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool \
    && rm -rf /opt/jwt_tool/.git \
    && python3 -m venv /opt/jwt_tool/.venv \
    && /opt/jwt_tool/.venv/bin/pip install -r /opt/jwt_tool/requirements.txt \
    && printf '%s\n' '#!/bin/sh' 'exec /opt/jwt_tool/.venv/bin/python /opt/jwt_tool/jwt_tool.py "$@"' \
        > /usr/local/bin/jwt_tool \
    && chmod +x /usr/local/bin/jwt_tool \
    && /opt/jwt_tool/.venv/bin/python /opt/jwt_tool/jwt_tool.py -h >/dev/null \
    && rm -rf /root/.cache

# --- SSTImap (server-side template injection: detection + exploitation, the
#     maintained Python3 successor to tplmap). Own venv, wrapped like sqlmap so
#     it does not need a bare `python` on PATH. Detects/exploits Jinja2, Twig,
#     Freemarker, Velocity, Mako, Smarty and more; drives non-interactively
#     (-u URL, plus --os-cmd / --os-shell / --eval-shell once an engine is
#     confirmed). Python prepends the script's own dir to sys.path, so it finds
#     its core/ and plugins/ packages from any working directory; the -h smoke
#     test runs from /work to prove that before the image ships. --------------
RUN git clone --depth 1 https://github.com/vladko312/SSTImap /opt/sstimap \
    && rm -rf /opt/sstimap/.git \
    && python3 -m venv /opt/sstimap/.venv \
    && /opt/sstimap/.venv/bin/pip install -r /opt/sstimap/requirements.txt \
    && printf '%s\n' '#!/bin/sh' 'exec /opt/sstimap/.venv/bin/python /opt/sstimap/sstimap.py "$@"' \
        > /usr/local/bin/sstimap \
    && chmod +x /usr/local/bin/sstimap \
    && sstimap -h >/dev/null \
    && rm -rf /root/.cache

# --- pipx apps: each isolated in its own venv, entrypoints on PATH ---------
# bypass-url-parser (needs curl), arjun (param discovery), clairvoyance
# (GraphQL schema recovery when introspection is off — pairs with batchql).
RUN pipx install bypass-url-parser \
    && pipx install arjun \
    && pipx install clairvoyance \
    && rm -rf /root/.cache

# paramspider (hidden params mined from web archives) and git-dumper (rebuild an
# exposed .git over plain GET requests — source exposure is a top-priority lead).
RUN pipx install git+https://github.com/devanshbatham/paramspider.git \
    && pipx install git-dumper \
    && rm -rf /root/.cache

# URL / JS side: uro (declutters URL lists: gau | uro), jsbeautifier (the
# js-beautify CLI, to read minified sources), xnLinkFinder (endpoints, params
# and words out of JS/HTML, from a URL, a file or a Burp export) and waymore
# (gau's heavier sibling: more archive sources, can also fetch the archived
# responses). Both xnl tools are git-only, no PyPI release.
RUN pipx install uro \
    && pipx install jsbeautifier \
    && pipx install git+https://github.com/xnl-h4ck3r/waymore.git \
    && rm -rf /root/.cache

# xnLinkFinder declares playwright, which has no musl wheel (build fails on
# Alpine). It is only imported lazily by --heap (browser heap snapshots), so
# it gets a hand-made venv: the package without deps, then the rest of its
# setup.py list explicitly. (pipx cannot do this: with --no-deps it aborts on
# the missing dependency metadata.) --heap is therefore unsupported in this
# image; everything else works. Keep the list in sync with upstream setup.py.
RUN python3 -m venv /opt/xnlinkfinder \
    && /opt/xnlinkfinder/bin/pip install --no-deps git+https://github.com/xnl-h4ck3r/xnLinkFinder.git \
    && /opt/xnlinkfinder/bin/pip install requests psutil pyyaml termcolor urlparse3 \
           beautifulsoup4 lxml html5lib urllib3 tldextract 'inflect>=7.3.0' pypdf \
    && ln -s /opt/xnlinkfinder/bin/xnLinkFinder /usr/local/bin/xnLinkFinder \
    && xnLinkFinder -h >/dev/null \
    && rm -rf /root/.cache

# waymore writes results under DEFAULT_OUTPUT_DIR from its config (empty =>
# ~/.config/waymore/, i.e. lost with the container). The config is generated
# from code on first run, so run it once here and point the key at /work, so
# results/<domain>/ lands on the host. Fail the build if the key is missing.
RUN waymore -h >/dev/null \
    && sed -i 's#^DEFAULT_OUTPUT_DIR:.*#DEFAULT_OUTPUT_DIR: /work#' /root/.config/waymore/config.yml \
    && grep -q '^DEFAULT_OUTPUT_DIR: /work$' /root/.config/waymore/config.yml \
    && rm -f /root/.config/waymore/config.yml.NEW \
    || { echo "ERROR: waymore config.yml not generated/patched" >&2; exit 1; }

# gf reads its pattern files from ~/.gf (or ~/.config/gf). Bake a useful set:
# tomnomnom's examples plus 1ndianl33t/Gf-Patterns. Fail the build if the
# directory ends up empty, so a pattern-less gf can never ship.
RUN mkdir -p /root/.gf \
    && git clone --depth 1 https://github.com/tomnomnom/gf /tmp/gf \
    && git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gfp \
    && cp /tmp/gf/examples/*.json /root/.gf/ \
    && cp /tmp/gfp/*.json /root/.gf/ \
    && rm -rf /tmp/gf /tmp/gfp \
    && [ -n "$(find /root/.gf -name '*.json' -print -quit)" ] \
    || { echo "ERROR: gf patterns not installed" >&2; exit 1; }

# --- katana wrapper: headless always wired to the baked-in chromium ------
# katana ships as katana.bin (renamed in the builder) and runs behind a wrapper.
# Its headless engines only use a system browser when -system-chrome-path is
# given (the pure -headless engine ignores -system-chrome entirely); otherwise
# rod downloads a glibc chrome into ~/.cache/rod that cannot run on Alpine. So
# whenever a browser mode is requested (-headless/-hl, -hybrid/-hh,
# -system-chrome/-sc) the wrapper adds -system-chrome-path /usr/bin/chromium
# and -no-sandbox (we run as root). It stays out of the way when the caller
# already chose a browser (-system-chrome-path/-scp) or attaches to one
# running elsewhere (-chrome-ws-url/-cwu). rod itself already passes
# --disable-dev-shm-usage (docker's /dev/shm is 64MB) and katana --disable-gpu.
# Verified at build time: katana exits 0 even when it cannot start, so grep its
# log for an ERR line instead — a headless crawl of an unreachable URL must get
# past browser startup (the only ERR a refused connection produces is none).
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
