# recon (orchestrator) chains gimmesubs -> http-probe -> nuclei-auto; each is
# also usable on its own. Built from the repo root: make recon

FROM golang:1.26-bookworm AS builder

# -ldflags "-s -w" drops symbols/DWARF at link time, which is the safe way to
# shrink a Go binary (do not run strip over one).
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

# massdns (for puredns); a C binary, so strip it directly.
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

# Slim base, not skw/base-debian: this is a headless tool runtime with its own
# deps below, so the interactive base would add ~150MB it never uses.
FROM debian:12-slim AS runtime

LABEL org.opencontainers.image.title="recon" \
      org.opencontainers.image.description="recon tools: gimmesubs (subdomain enumeration), http-probe (HTTP service discovery), nuclei-auto (nuclei scanning)"

# OUTPUT_DIR=/work: results go wherever /work is mounted.
ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/bin:${PATH}" \
    WORDLIST_DIR=/opt/wordlists \
    OUTPUT_DIR=/work \
    HOME=/root

# No bind9-dnsutils: gimmesubs does all DNS through dnsx, not dig, which keeps
# libxml2 -> libicu72 (~36MB) out of the image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl jq tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/bin/ /usr/local/bin/

RUN mkdir -p "$WORDLIST_DIR" /work

# Baked data first: independent of the scripts, so editing one leaves these
# layers cached.

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

# Templates must be baked in: scans run with -disable-update-check and never
# fetch at runtime. Do not add -disable-update-check to the line below — it
# suppresses the version check the install relies on and nothing downloads.
# The build fails on an empty template set so a template-less image can't ship.
RUN nuclei -update-templates \
    && [ -d "$HOME/nuclei-templates" ] \
    && [ -n "$(find "$HOME/nuclei-templates" -name '*.yaml' -print -quit)" ] \
    || { echo "ERROR: nuclei templates failed to install" >&2; exit 1; }

# Bruteforce wordlists are not baked; the launcher bind-mounts RECON_WORDLISTS
# read-only at /wordlists.

# Scripts last: cheap, and the layer that changes most often.
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
