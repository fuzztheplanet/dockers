# skw/recon — a recon pipeline in a container: recon (orchestrator) chaining
# gimmesubs -> http-probe -> nuclei-auto, each also usable on its own.
# Stage 1 builds the Go tools + massdns; stage 2 is the slim runtime.
# Built from the repo root: make recon

FROM golang:1.26-bookworm AS builder

# GOTOOLCHAIN=auto: let Go fetch the toolchain a module asks for.
# -ldflags "-s -w" drops the symbol table and DWARF at link time — smaller
# binaries the safe way, rather than running strip over Go binaries afterwards.
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOBIN=/out/bin \
    GOFLAGS=-buildvcs=false \
    GOTOOLCHAIN=auto
ARG GO_LDFLAGS="-s -w"

RUN apt-get update && apt-get install -y --no-install-recommends \
        git build-essential ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /out/bin

# massdns (used by puredns); a C binary, so strip it directly.
RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns \
    && make -C /tmp/massdns -j"$(nproc)" \
    && cp /tmp/massdns/bin/massdns /out/bin/massdns \
    && strip /out/bin/massdns \
    && rm -rf /tmp/massdns

# One layer per pair so an upstream breakage does not invalidate everything.
RUN go install -v -ldflags="$GO_LDFLAGS" github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install -v -ldflags="$GO_LDFLAGS" github.com/projectdiscovery/dnsx/cmd/dnsx@latest

RUN go install -v -ldflags="$GO_LDFLAGS" github.com/projectdiscovery/alterx/cmd/alterx@latest \
 && go install -v -ldflags="$GO_LDFLAGS" github.com/projectdiscovery/tlsx/cmd/tlsx@latest \
 && go install -v -ldflags="$GO_LDFLAGS" github.com/projectdiscovery/httpx/cmd/httpx@latest

RUN go install -v -ldflags="$GO_LDFLAGS" github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

RUN go install -v -ldflags="$GO_LDFLAGS" github.com/tomnomnom/assetfinder@latest \
 && go install -v -ldflags="$GO_LDFLAGS" github.com/lc/gau/v2/cmd/gau@latest

RUN go install -v -ldflags="$GO_LDFLAGS" github.com/d3mondev/puredns/v2@latest

FROM skw/base-debian AS runtime

LABEL org.opencontainers.image.title="recon" \
      org.opencontainers.image.description="recon tools: gimmesubs (subdomain enumeration), http-probe (HTTP service discovery), nuclei-auto (nuclei scanning)"

# OUTPUT_DIR=/work: results go wherever /work is mounted.
ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/bin:${PATH}" \
    WORDLIST_DIR=/opt/wordlists \
    OUTPUT_DIR=/work \
    HOME=/root

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl jq bind9-dnsutils tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/bin/ /usr/local/bin/

# /opt/wordlists: resolver lists. /work: results, one directory per run.
RUN mkdir -p "$WORDLIST_DIR" /work

# --- baked data, all independent of the scripts, so editing a script leaves
#     these layers cached ----------------------------------------------------

# Public resolver list, fallback for when the per-run download fails.
RUN curl -fsSL --retry 3 --max-time 180 \
        https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
        -o "$WORDLIST_DIR/resolvers.txt" \
    || curl -fsSL --retry 3 --max-time 180 \
        https://raw.githubusercontent.com/proabiral/Fresh-Resolvers/master/resolvers.txt \
        -o "$WORDLIST_DIR/resolvers.txt" \
    || echo "WARN: no resolver list baked in — it will be fetched on first run"

# Trusted resolvers, used to verify hits.
RUN printf '%s\n' \
        1.1.1.1 1.0.0.1 \
        8.8.8.8 8.8.4.4 \
        9.9.9.9 149.112.112.112 \
        208.67.222.222 208.67.220.220 \
        64.6.64.6 77.88.8.8 \
    > "$WORDLIST_DIR/resolvers-trusted.txt"

# nuclei templates, baked in — a hard requirement, not an optimization: scans
# run with -disable-update-check, so templates are never fetched at runtime.
# Note: -disable-update-check must NOT be combined with -update-templates here —
# it suppresses the version check the install relies on, so nothing downloads.
# Fail the build if the install does not produce a non-empty template set, so a
# silently template-less image can never ship. Rebuild the image to refresh.
RUN nuclei -update-templates \
    && [ -d "$HOME/nuclei-templates" ] \
    && [ -n "$(find "$HOME/nuclei-templates" -name '*.yaml' -print -quit)" ] \
    || { echo "ERROR: nuclei templates failed to install" >&2; exit 1; }

# Bruteforce wordlists are not baked: they are user-provided. The launcher
# bind-mounts a wordlist directory (RECON_WORDLISTS, if set) read-only at /wordlists.

# --- scripts and config last: cheap, and the layer that changes most often ---
COPY recon/scripts/ /opt/recon/scripts/
COPY recon/config/  /opt/recon/config/
RUN chmod +x /opt/recon/scripts/*.sh \
    && ln -sf /opt/recon/scripts/recon.sh      /usr/local/bin/recon \
    && ln -sf /opt/recon/scripts/gimmesubs.sh  /usr/local/bin/gimmesubs.sh \
    && ln -sf /opt/recon/scripts/gimmesubs.sh  /usr/local/bin/gimmesubs \
    && ln -sf /opt/recon/scripts/http-probe.sh /usr/local/bin/http-probe.sh \
    && ln -sf /opt/recon/scripts/http-probe.sh /usr/local/bin/http-probe \
    && ln -sf /opt/recon/scripts/nuclei-auto.sh /usr/local/bin/nuclei-auto.sh \
    && ln -sf /opt/recon/scripts/nuclei-auto.sh /usr/local/bin/nuclei-auto

WORKDIR /work
ENTRYPOINT ["/opt/recon/scripts/recon.sh"]
CMD ["help"]
