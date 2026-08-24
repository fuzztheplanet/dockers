#!/usr/bin/env bash
# gimmesubs.sh — subdomain enumeration for one apex domain. See --help.
#
# Phases (0, 4-6 active only): 0 resolvers, 1 passive, 2 validate, 3 wildcard,
# 4 bruteforce, 5 permute, 6 recurse, 7 report. Only resolving names are reported.
set -euo pipefail
export LC_ALL=C

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

# Settings — sized for a home network (router conntrack table is the limit);
# --vps swaps in the larger profile.
OUTPUT_DIR="${OUTPUT_DIR:-.}"
WORDLIST_DIR="${WORDLIST_DIR:-/opt/wordlists}"
PASSIVE_TIMEOUT="${PASSIVE_TIMEOUT:-180}"   # per source; aggregators get a multiple

RESOLVERS_URL="https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
RESOLVERS_BAKED="$WORDLIST_DIR/resolvers.txt"
RESOLVERS_TRUSTED="$WORDLIST_DIR/resolvers-trusted.txt"
SUBFINDER_CONFIG="/opt/recon/config/subfinder-provider-config.yaml"

#--- DNS load -----------------------------------------------------------------
RESOLVER_RATE=250        # puredns --rate-limit, which it maps onto massdns -s
MASSDNS_CONCURRENCY=250  # in-flight lookups; massdns' own default of 10000 kills routers
MASSDNS_RETRIES=3        # massdns -c; its default of 50 costs minutes per miss
MAX_RESOLVERS=150        # distinct public resolvers — the conntrack dial
TRUSTED_RATE=50          # load on the trusted pool; these are shared public services
RESOLVERS_PROBE=600      # entries probed when building the pool; ~a third are dead
PROBE_PARALLEL=50

DNSX_THREADS=25
WILDCARD_THREADS=25          # puredns -t (wildcard filtering only)
WILDCARD_TESTS=10
WILDCARD_BATCH=500000
WILDCARD_PROBES=3            # random labels tested per zone

#--- TLS (one TCP conntrack entry per connection) -----------------------------
TLSX_CONCURRENCY=15

#--- Passive phase (HTTP APIs; unrelated to the DNS budget) -------------------
PASSIVE_PARALLEL=6

#--- Permutation --------------------------------------------------------------
PERMUTE_MAX_INPUT=2000
PERMUTE_MAX_CANDIDATES=1000000

#--- Recursion ----------------------------------------------------------------
RECURSION_DEPTH=1        # --depth
RECURSE_MAX_TARGETS=10   # zones expanded per level
RECURSE_MAX_KNOWN=50000  # past this, recursion costs a lot and adds little
RECURSE_REUSE_LABELS=true

#--- Ceilings on the long-running tools ---------------------------------------
RESOLVE_TIMEOUT=3600
BRUTE_TIMEOUT=43200      # 12h ceiling on the bruteforce phase (the long pole)
PERMUTE_GEN_TIMEOUT=900
TLS_TIMEOUT=900

#--- Behaviour ----------------------------------------------------------------
STOP_ON_WILDCARD=true    # --force flips this
TLS_SCRAPE=true

# --vps profile
apply_vps_profile() {
    RESOLVER_RATE=10000
    MASSDNS_CONCURRENCY=10000
    MAX_RESOLVERS=2000
    RESOLVERS_PROBE=8000
    TRUSTED_RATE=500
    WILDCARD_THREADS=100
    DNSX_THREADS=100
    TLSX_CONCURRENCY=50
    PASSIVE_PARALLEL=10
}

# Usage
usage() {
cat <<'USAGE_TEXT'
gimmesubs — subdomain enumeration for one apex domain

USAGE
    gimmesubs.sh -p <domain>
    gimmesubs.sh -a <domain> <wordlist>

MODE  (passive is the default if neither is given)
    -p, --passive        OSINT sources + DNS validation only (phases 1-3, 7).
    -a, --active         Passive, then bruteforce, permutations and recursion
                         against the zone (phases 0-7). Needs a wordlist.

ARGUMENTS
    <domain>             Apex domain, e.g. example.com
    <wordlist>           Bruteforce wordlist, positional or -w. Required with
                         --active: it decides most of what phase 4 finds and
                         swings runtime from minutes to hours, so nothing is
                         chosen for you.
                         A directory works too: every text file under it, at any
                         depth, is merged into one deduplicated list and phase 4
                         runs once over the union. Documentation, archives and
                         binary files are skipped.

OPTIONS
    -o, --output <dir>   Where the run directory goes    (default: current dir; /work in the container)
                         Each run writes <dir>/<domain>_<timestamp>/.
        --depth <n>      Recursion depth                 (default: 1, 0 = off)
        --vps            Raise the DNS limits for a machine with its own public
                         IP: 10000 lookups in flight over 2000 resolvers. The
                         defaults are sized to keep a home network usable —
                         roughly 400 router conntrack entries.
        --force          Bruteforce even a wildcard apex. Normally a wildcard
                         stops the active phases, because a zone that answers
                         everything returns endless meaningless hostnames.
    -v, --verbose        Per-source counts, resolver detail and timings. They
                         are in the run log either way.
    -h, --help           This help

EXAMPLES
    gimmesubs.sh -p example.com
    gimmesubs.sh -a example.com /wordlists/n0kovo-huge.txt
    gimmesubs.sh -a example.com /wordlists/            every list in a directory
    gimmesubs.sh -a example.com /wordlists/big.txt --depth 2 --vps
USAGE_TEXT
}

# Logging
_ts()  { date -u '+%H:%M:%S'; }
say()  { printf '%s %s\n' "$(_ts)" "$*" >&2; }
warn() { printf '%s warning: %s\n' "$(_ts)" "$*" >&2; }
err()  { printf '%s error: %s\n' "$(_ts)" "$*" >&2; }
die()  { err "$*"; exit 1; }
step() { say "[$1/7] $2"; }

# terminal only with -v; always logged
detail() {
    if [[ "${VERBOSE:-false}" == true ]]; then
        printf '%s   %s\n' "$(_ts)" "$*" >&2
    else
        printf '%s   %s\n' "$(_ts)" "$*" >> "${LOG_FILE:-/dev/null}"
    fi
}

declare -A _PHASE_START
timer_start() { _PHASE_START["$1"]=$SECONDS; }
timer_end()   { local d=$(( SECONDS - ${_PHASE_START[$1]:-$SECONDS} )); printf '%dm%02ds' $((d/60)) $((d%60)); }

# Helpers
have()  { command -v "$1" >/dev/null 2>&1; }
count() { [[ -s "${1:-/dev/null}" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }

require() {
    local missing=() t
    for t in "$@"; do have "$t" || missing+=("$t"); done
    (( ${#missing[@]} )) && die "missing required tool(s): ${missing[*]}"
    return 0
}

_timed_rc() {
    local label="$1" secs="$2" rc="$3"
    case $rc in
        0)       ;;
        124|137) warn "$label timed out after ${secs}s (partial results kept)" ;;
        *)       detail "$label exited rc=$rc" ;;
    esac
    return 0
}

# Run under a time limit; never fails the caller.
timed() {
    local secs="$1" label="$2"; shift 2
    local rc=0
    timeout --kill-after=10s "${secs}s" "$@" || rc=$?
    _timed_rc "$label" "$secs" "$rc"
}

# Same, with the command's stdout/stderr redirected. stdin is /dev/null:
# puredns reads its domain list from a piped stdin instead of the file argument.
timed_io() {
    local secs="$1" label="$2" outf="$3" errf="$4"; shift 4
    local rc=0
    timeout --kill-after=10s "${secs}s" "$@" >"$outf" 2>"$errf" </dev/null || rc=$?
    _timed_rc "$label" "$secs" "$rc"
}

# Show the tool's stderr when it returned nothing.
explain_empty() {
    local label="$1" result="$2" errfile="$3"
    (( $(count "$result") > 0 )) && return 0
    if [[ -s "$errfile" ]]; then
        warn "$label returned nothing; its stderr was:"
        tail -n 5 "$errfile" | sed 's/^/      /' >&2
    fi
    # puredns swallows massdns' stderr; the wrapper logs it
    if [[ -n "${MASSDNS_LOG:-}" && -s "$MASSDNS_LOG" ]]; then
        local failures; failures=$(grep -c 'exit=[1-9]' "$MASSDNS_LOG" 2>/dev/null) || failures=0
        if (( failures > 0 )); then
            warn "$label: massdns reported errors:"
            tail -n 8 "$MASSDNS_LOG" | sed 's/^/      /' >&2
        fi
    fi
    return 0
}

# Normalise to valid hostnames under $1. `|| true`: empty output is fine under pipefail.
clean_hosts() {
    local domain="${1:?domain required}" esc
    esc=$(printf '%s' "$domain" | sed 's/\./\\./g')
    tr -d '\r' \
        | tr '[:upper:]' '[:lower:]' \
        | sed -E 's#^[a-z0-9+.-]+://##; s#/.*$##; s#^\*\.##; s#^\.+##; s#\.+$##; s#:[0-9]+$##' \
        | sed -E 's#^[^@]*@##' \
        | grep -aE "^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*${esc}$" \
        | grep -avE '^\s*$' \
        | sort -u || true
    return 0
}

merge_into() {
    local out="$1"; shift
    { cat "$@" 2>/dev/null || true; } | sort -u > "$out.tmp"
    mv "$out.tmp" "$out"
}

rand_label() {
    local n="${1:-14}"
    LC_ALL=C tr -dc 'a-z0-9' < /dev/urandom 2>/dev/null | head -c "$n" || printf 'r%s%s' "$RANDOM" "$RANDOM"
}

# Bounded parallelism. Waits on explicit PIDs: a bare `wait` would hang on the log tee.
throttle() {
    local max="${1:-4}" name="$2"
    local -n _pids="$name"
    local p alive first
    while :; do
        alive=0; first=""
        for p in "${_pids[@]}"; do
            if kill -0 "$p" 2>/dev/null; then
                alive=$(( alive + 1 )); [[ -z "$first" ]] && first="$p"
            fi
        done
        (( alive < max )) && return 0
        [[ -z "$first" ]] && return 0
        wait "$first" 2>/dev/null || true
    done
}

reap() {
    local name="$1"; local -n _rp="$name"; local p
    for p in "${_rp[@]}"; do wait "$p" 2>/dev/null || true; done
}

# PHASE 0 — resolver pool: fetch, validate, sample down to MAX_RESOLVERS.
# Download the public resolver list into the run directory; fall back to the baked copy.
fetch_resolvers() {
    local dst="$TMP_DIR/resolvers-public.txt"
    detail "downloading public resolver list"
    if curl -fsSL --retry 2 --max-time 120 "$RESOLVERS_URL" -o "$dst.tmp" 2>/dev/null \
       && [[ -s "$dst.tmp" ]]; then
        grep -aE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$dst.tmp" | sort -u > "$dst"
        rm -f "$dst.tmp"
        detail "resolver list: $(count "$dst") public entries"
    else
        rm -f "$dst.tmp"
        warn "could not download the resolver list — using the copy shipped in the image"
        cp "$RESOLVERS_BAKED" "$dst" 2>/dev/null || : > "$dst"
    fi
    RESOLVERS_SRC="$dst"
    return 0
}

# Keep resolvers that answer a known name and NXDOMAIN a nonexistent one,
# ranked fastest first.
validate_resolvers() {
    local src="$1" out="$2" want="$3" probe="$4"

    export VALIDATE_POS="google.com"
    VALIDATE_NEG="$(rand_label 18).google.com"
    export VALIDATE_NEG

    shuf -n "$probe" "$src" 2>/dev/null \
        | xargs -P "$PROBE_PARALLEL" -I{} bash -c '
            ip="$1"; t0=$EPOCHREALTIME
            printf "%s\n" "$VALIDATE_POS" \
                | dnsx -r "$ip" -a -resp-only -silent -retry 1 -timeout 2 2>/dev/null \
                | grep -qE "^[0-9]+\." || exit 0
            t1=$EPOCHREALTIME
            printf "%s\n" "$VALIDATE_NEG" \
                | dnsx -r "$ip" -a -resp-only -silent -retry 1 -timeout 2 2>/dev/null \
                | grep -qE "^[0-9]+\." && exit 0
            awk -v a="$t0" -v b="$t1" -v ip="$ip" "BEGIN { printf \"%d %s\\n\", (b - a) * 1000, ip }"
          ' _ {} 2>/dev/null \
        | sort -n | cut -d" " -f2 | head -n "$want" > "$out" || true

    unset VALIDATE_POS VALIDATE_NEG
    return 0
}

prepare_resolvers() {
    RESOLVERS="$TMP_DIR/resolvers-active.txt"
    local n; n=$(count "$RESOLVERS_SRC")

    if (( n < 10 )); then
        warn "public resolver list has $n entries — using the trusted resolvers only"
        cp "$RESOLVERS_TRUSTED" "$RESOLVERS"
        (( RESOLVER_RATE > TRUSTED_RATE )) && RESOLVER_RATE="$TRUSTED_RATE"
        return 0
    fi

    detail "validating resolvers (probing $RESOLVERS_PROBE of $n public entries)"
    validate_resolvers "$RESOLVERS_SRC" "$TMP_DIR/resolvers-valid.txt" \
                       "$MAX_RESOLVERS" "$RESOLVERS_PROBE"
    local got; got=$(count "$TMP_DIR/resolvers-valid.txt")

    if (( got < 5 )); then
        warn "only $got resolvers validated — falling back to an unvalidated sample"
        shuf -n "$MAX_RESOLVERS" "$RESOLVERS_SRC" > "$RESOLVERS"
        return 0
    fi

    cp "$TMP_DIR/resolvers-valid.txt" "$RESOLVERS"
    say "resolvers: $(count "$RESOLVERS") public, $(count "$RESOLVERS_TRUSTED") trusted"
    return 0
}

# Use the zone's authoritative nameservers for verification (never for bruteforce).
prepare_auth_resolvers() {
    local domain="$1"
    local ns_ips="$TMP_DIR/auth-resolvers.txt"
    # NS names for the zone, then resolve each to an A record. dnsx handles both
    # the NS query and the A resolution (piped), using the trusted resolver pool.
    printf '%s\n' "$domain" \
        | dnsx -r "$RESOLVERS_TRUSTED" -ns -resp-only -silent 2>/dev/null | sed 's/\.$//' \
        | dnsx -r "$RESOLVERS_TRUSTED" -a -resp-only -silent 2>/dev/null \
        | grep -aE '^[0-9]+\.' | sort -u > "$ns_ips.all" || true

    : > "$ns_ips"
    while read -r ip; do
        [[ -n "$ip" ]] || continue
        # skip NS hosts that do not answer
        printf '%s\n' "$domain" \
            | dnsx -r "$ip" -a -resp-only -silent -retry 1 -timeout 3 2>/dev/null \
            | grep -qaE '^[0-9]+\.' || continue
        printf '%s\n' "$ip" >> "$ns_ips"
    done < "$ns_ips.all"
    rm -f "$ns_ips.all"

    local n; n=$(count "$ns_ips")
    if (( n >= 2 )); then
        # keep the trusted public ones as a fallback
        sort -u "$ns_ips" "$RESOLVERS_TRUSTED" > "$TMP_DIR/verify-resolvers.txt"
        RESOLVERS_TRUSTED="$TMP_DIR/verify-resolvers.txt"
        detail "verification pool: $n authoritative nameserver(s) for $domain + public trusted"
    else
        detail "authoritative nameservers unusable ($n reachable) — verifying against the public trusted pool"
    fi
    return 0
}

# massdns wrapper for `puredns --bin`: caps -s/-c (no puredns flag for them) and logs stderr.
make_massdns_wrapper() {
    MASSDNS_BIN="$TMP_DIR/massdns-limited"
    MASSDNS_LOG="$TMP_DIR/massdns.log"
    local real; real=$(command -v massdns || echo /usr/local/bin/massdns)
    cat > "$MASSDNS_BIN" <<WRAPPER
#!/usr/bin/env bash
# Generated by gimmesubs: bounds massdns concurrency and retries.
cap=$MASSDNS_CONCURRENCY
retries=$MASSDNS_RETRIES
log="$MASSDNS_LOG"
args=(); seen_s=0; seen_c=0
while (( \$# )); do
    case "\$1" in
        -s|--hashmap-size)
            v="\$2"
            [[ "\$v" =~ ^[0-9]+\$ ]] && (( v > cap )) && v=\$cap
            args+=(-s "\$v"); seen_s=1; shift 2 ;;
        -c|--resolve-count)
            args+=("\$1" "\$2"); seen_c=1; shift 2 ;;
        *)  args+=("\$1"); shift ;;
    esac
done
(( seen_s )) || args=(-s "\$cap" "\${args[@]}")
(( seen_c )) || args=(-c "\$retries" "\${args[@]}")

err=\$(mktemp)
"$real" "\${args[@]}" 2>"\$err"
rc=\$?
{
    printf '[%s] exit=%s args: %s\n' "\$(date -u +%H:%M:%S)" "\$rc" "\${args[*]}"
    [[ -s "\$err" ]] && sed 's/^/    /' "\$err"
} >> "\$log" 2>/dev/null
cat "\$err" >&2
rm -f "\$err"
exit "\$rc"
WRAPPER
    chmod +x "$MASSDNS_BIN"
    : > "$MASSDNS_LOG"
}

# Before trusting an empty result, check the pool still resolves a known name.
public_pool_healthy() {
    local probe="${1:-$ROOT_DOMAIN}" n
    n=$(printf '%s\n' "$probe" \
        | dnsx -r "$RESOLVERS" -silent -retry 3 -t 5 -rl 20 2>/dev/null | wc -l)
    (( n > 0 ))
}

warn_if_pool_dead() {
    local label="$1" result="$2"
    (( $(count "$result") > 0 )) && return 0
    [[ -n "${RESOLVERS:-}" && -s "${RESOLVERS:-/dev/null}" ]] || return 0
    if ! public_pool_healthy "$ROOT_DOMAIN"; then
        err "$label returned nothing AND the resolver pool failed a known-good probe"
        err "  -> this result is UNRELIABLE, not an empty zone. You are likely rate-limited."
        err "  -> retry later"
    fi
    return 0
}

report_dns_load() {
    local conntrack=$(( MAX_RESOLVERS + MASSDNS_CONCURRENCY ))
    detail "DNS ceiling: ${MASSDNS_CONCURRENCY} lookups in flight over ${MAX_RESOLVERS} resolvers (~${conntrack} router conntrack entries)"
    if (( conntrack > 4000 )); then
        warn "that is a lot for a consumer router (they often hold 2k-16k entries)"
        warn "drop --vps, or lower MAX_RESOLVERS / MASSDNS_CONCURRENCY, if the network suffers"
    fi
}

# PHASE 1 — passive sources. Each prints raw hostnames; run in parallel under a timeout.
_UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36'

_curl() {
    local url="$1"; shift
    local maxtime=$(( ${PASSIVE_TIMEOUT:-180} - 10 )); (( maxtime < 20 )) && maxtime=20
    curl -sSL --compressed \
         --connect-timeout 15 --max-time "$maxtime" \
         --retry 2 --retry-delay 2 --retry-connrefused \
         -H "User-Agent: $_UA" \
         "$@" "$url" 2>/dev/null
}

#--- certificate transparency -------------------------------------------------
src_crtsh() {
    # 502s often; retried. Wildcard query plus bare query.
    local q attempt body
    for q in "%25.$DOMAIN" "$DOMAIN"; do
        for attempt in 1 2 3; do
            body=$(_curl "https://crt.sh/?q=${q}&output=json" --retry 3 --retry-delay 5)
            if [[ "$body" == \[* ]]; then
                printf '%s' "$body" \
                    | jq -r '.[]? | (.name_value, .common_name) // empty' 2>/dev/null \
                    | tr ',' '\n'
                break
            fi
            sleep $(( attempt * 3 ))
        done
    done
}

src_certspotter() {
    _curl "https://api.certspotter.com/v1/issuances?domain=${DOMAIN}&include_subdomains=true&expand=dns_names" \
        | jq -r '.[]?.dns_names[]? // empty' 2>/dev/null
}

#--- passive DNS / aggregators ------------------------------------------------
src_alienvault() {
    local -a hdr=()
    [[ -n "${OTX_KEY:-}" ]] && hdr=(-H "X-OTX-API-KEY: $OTX_KEY")
    _curl "https://otx.alienvault.com/api/v1/indicators/domain/${DOMAIN}/passive_dns" "${hdr[@]}" \
        | jq -r '.passive_dns[]?.hostname // empty' 2>/dev/null
}

src_hackertarget() {
    _curl "https://api.hackertarget.com/hostsearch/?q=${DOMAIN}" \
        | grep -v 'API count exceeded' | cut -d',' -f1
}

src_rapiddns() {
    _curl "https://rapiddns.io/subdomain/${DOMAIN}?full=1#result" \
        | grep -oE '<td>[^<]*\.'"${DOMAIN//./\\.}"'</td>' | sed -E 's#</?td>##g'
}

src_subdomaincenter() {
    _curl "https://api.subdomain.center/?domain=${DOMAIN}" | jq -r '.[]? // empty' 2>/dev/null
}

src_leakix() {
    [[ -n "${LEAKIX_KEY:-}" ]] || return 0   # the endpoint is key-only
    _curl "https://leakix.net/api/subdomains/${DOMAIN}" \
        -H "api-key: $LEAKIX_KEY" -H "Accept: application/json" \
        | jq -r '.[]?.subdomain // empty' 2>/dev/null
}

src_dnsdumpster() {
    [[ -n "${DNSDUMPSTER_KEY:-}" ]] || return 0
    _curl "https://api.dnsdumpster.com/domain/${DOMAIN}" -H "X-API-Key: $DNSDUMPSTER_KEY" \
        | jq -r '[.a[]?, .cname[]?, .mx[]?, .ns[]?] | .[]? | (.host // .value // empty)' 2>/dev/null
}

src_fullhunt() {
    [[ -n "${FULLHUNT_KEY:-}" ]] || return 0
    _curl "https://fullhunt.io/api/v1/domain/${DOMAIN}/subdomains" -H "X-API-KEY: $FULLHUNT_KEY" \
        | jq -r '.hosts[]? // empty' 2>/dev/null
}

#--- URL archives -------------------------------------------------------------
src_urlscan() {
    _curl "https://urlscan.io/api/v1/search/?q=domain%3A${DOMAIN}&size=10000" \
        | jq -r '.results[]? | (.page.domain, .task.domain, .page.url) // empty' 2>/dev/null
}

src_wayback() {
    _curl "http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=text&fl=original&collapse=urlkey&limit=200000"
}

src_gau() {
    have gau || return 0
    printf '%s\n' "$DOMAIN" | gau --subs --threads 5 --timeout 30 --retries 2 2>/dev/null
}

#--- local tools --------------------------------------------------------------
src_subfinder() {
    have subfinder || return 0
    local args=(-d "$DOMAIN" -all -silent -recursive -timeout 30 -max-time 5)
    [[ -f "$SUBFINDER_CONFIG" ]] && args+=(-pc "$SUBFINDER_CONFIG")
    subfinder "${args[@]}" 2>/dev/null
}

src_assetfinder() { have assetfinder || return 0; assetfinder --subs-only "$DOMAIN" 2>/dev/null; }

# Key-gated sources are added only when their key is set.
PASSIVE_SOURCES=(
    subfinder assetfinder gau
    crtsh certspotter
    alienvault hackertarget rapiddns
    subdomaincenter urlscan wayback
)
[[ -n "${LEAKIX_KEY:-}" ]]      && PASSIVE_SOURCES+=(leakix)
[[ -n "${DNSDUMPSTER_KEY:-}" ]] && PASSIVE_SOURCES+=(dnsdumpster)
[[ -n "${FULLHUNT_KEY:-}" ]]    && PASSIVE_SOURCES+=(fullhunt)

# Aggregators get a longer timeout.
_source_timeout() {
    case "$1" in
        subfinder|gau) echo $(( PASSIVE_TIMEOUT * 3 )) ;;
        crtsh|wayback) echo $(( PASSIVE_TIMEOUT * 2 )) ;;
        *)             echo "$PASSIVE_TIMEOUT" ;;
    esac
}

run_passive() {
    local domain="$1" out="$2"
    mkdir -p "$PASSIVE_DIR"
    detail "querying ${#PASSIVE_SOURCES[@]} passive sources (parallel=$PASSIVE_PARALLEL)"

    # sources run as children via --internal-source
    export PASSIVE_TIMEOUT SUBFINDER_CONFIG VERBOSE
    export OTX_KEY="${OTX_KEY:-}" LEAKIX_KEY="${LEAKIX_KEY:-}" \
           DNSDUMPSTER_KEY="${DNSDUMPSTER_KEY:-}" FULLHUNT_KEY="${FULLHUNT_KEY:-}"

    local s; local -a pids=()
    for s in "${PASSIVE_SOURCES[@]}"; do
        throttle "$PASSIVE_PARALLEL" pids
        (
            raw="$PASSIVE_DIR/$s.raw"; clean="$PASSIVE_DIR/$s.txt"
            timed "$(_source_timeout "$s")" "$s" \
                "$SELF" --internal-source "$domain" "$s" > "$raw" 2>/dev/null
            clean_hosts "$domain" < "$raw" > "$clean"
            rm -f "$raw"
            n=$(count "$clean")
            detail "$(printf '%-16s %6d' "$s" "$n")"
        ) &
        pids+=($!)
    done
    reap pids

    merge_into "$out" "$PASSIVE_DIR"/*.txt
    local hit=0 f
    for f in "$PASSIVE_DIR"/*.txt; do [[ -s "$f" ]] && hit=$(( hit + 1 )); done
    say "passive: $(count "$out") names from $hit/${#PASSIVE_SOURCES[@]} sources"
}

# PHASES 2/3 — resolution, wildcard detection

# is_wildcard <domain> [ip-outfile]   0 = wildcard, 1 = not. Probes are retried.
is_wildcard() {
    local domain="$1" ipout="${2:-/dev/null}"
    local probes i answers
    probes=$(mktemp)

    for (( i = 0; i < WILDCARD_PROBES; i++ )); do
        printf '%s.%s\n' "$(rand_label 16)" "$domain"
    done > "$probes"
    printf '%s.%s.%s\n' "$(rand_label 10)" "$(rand_label 10)" "$domain" >> "$probes"

    answers=$(dnsx -l "$probes" -r "$RESOLVERS_TRUSTED" -a -cname -resp-only \
                   -silent -retry 3 -t 10 -rl "$TRUSTED_RATE" 2>/dev/null | sort -u)
    rm -f "$probes"

    [[ -n "$answers" ]] && { printf '%s\n' "$answers" > "$ipout"; return 0; }
    return 1
}

# Resolve candidates: puredns on the public pool, hits re-verified on the trusted pool. Small sets: dnsx.
resolve_hosts() {
    local in="$1" out="$2" wcout="${3:-$TMP_DIR/wildcards.txt}"
    local n; n=$(count "$in")
    : > "$out"
    (( n == 0 )) && { warn "nothing to resolve"; return 0; }

    if (( n <= 1000 )) || [[ "$MODE" == passive ]]; then
        # passive mode has no public pool: trusted resolvers only, slower
        if [[ "$MODE" == passive ]] && (( n > 5000 )); then
            say "validating $n names at ${TRUSTED_RATE}/s against the trusted resolvers (~$(( n / (TRUSTED_RATE > 0 ? TRUSTED_RATE : 1) / 60 ))m); --active spreads this over the public pool"
        fi
        detail "resolving $n host(s) with dnsx"
        dnsx -l "$in" -r "$RESOLVERS_TRUSTED" -silent -retry 2 \
             -t "$DNSX_THREADS" -rl "$TRUSTED_RATE" 2>/dev/null \
            | clean_hosts "$ROOT_DOMAIN" > "$out" || true
    else
        detail "resolving $n host(s) with puredns"
        local tmp; tmp=$(mktemp -d)
        timed_io "$RESOLVE_TIMEOUT" "puredns resolve" /dev/null "$tmp/err" \
            puredns resolve "$in" \
                --bin "$MASSDNS_BIN" \
                -r "$RESOLVERS" --resolvers-trusted "$RESOLVERS_TRUSTED" \
                --rate-limit "$RESOLVER_RATE" --rate-limit-trusted "$TRUSTED_RATE" \
                -t "$WILDCARD_THREADS" \
                --wildcard-tests "$WILDCARD_TESTS" --wildcard-batch "$WILDCARD_BATCH" \
                --write "$tmp/valid.txt" --write-wildcards "$tmp/wildcards.txt" -q
        [[ -s "$tmp/valid.txt" ]] && clean_hosts "$ROOT_DOMAIN" < "$tmp/valid.txt" > "$out"
        [[ -s "$tmp/wildcards.txt" ]] && cat "$tmp/wildcards.txt" >> "$wcout"
        explain_empty "puredns resolve" "$out" "$tmp/err"
        rm -rf "$tmp"
        warn_if_pool_dead "resolution of $n candidate(s)" "$out"
    fi
    detail "resolved $(count "$out")/$n"
}

dns_records() {
    local in="$1" jsonout="$2" txtout="$3"
    (( $(count "$in") == 0 )) && return 0
    detail "collecting A/AAAA/CNAME records"
    dnsx -l "$in" -r "$RESOLVERS_TRUSTED" -a -aaaa -cname -json -silent \
         -retry 2 -t "$DNSX_THREADS" -rl "$TRUSTED_RATE" 2>/dev/null > "$jsonout" || true
    if [[ -s "$jsonout" ]]; then
        jq -r 'select(.host) | [.host, ((.a // []) | join(",")), ((.cname // []) | join(","))] | @tsv' \
            "$jsonout" 2>/dev/null | sort -u > "$txtout" || true
        jq -r '(.a // [])[]' "$jsonout" 2>/dev/null | sort -u > "$RUN_DIR/ips.txt" || true
    fi
}

# TLS SANs off live hosts.
tls_scrape() {
    local in="$1" out="$2"
    [[ "$TLS_SCRAPE" == true ]] || return 0
    (( $(count "$in") == 0 )) && return 0
    : > "$out"
    detail "scraping TLS SANs from $(count "$in") host(s)"
    timed "$TLS_TIMEOUT" tlsx \
        tlsx -l "$in" -san -cn -resp-only -silent -c "$TLSX_CONCURRENCY" -timeout 5 2>/dev/null \
        | clean_hosts "$ROOT_DOMAIN" > "$out" || true
    detail "TLS SANs: $(count "$out") in-scope names"
}

# PHASE 4 — bruteforce. A wordlist directory is merged into one deduplicated list.
WORDLIST_IS_DIR=false    # set when <wordlist> is a directory...
WORDLIST_SRC=""          # ...and then where it came from, for the report
WORDLIST_FILE_COUNT=0

# Text files under the directory, minus hidden files, docs, archives and binaries.
collect_wordlist_files() {
    local dir="$1" f
    while IFS= read -r f; do
        [[ -s "$f" ]] || continue
        (( $(head -c 4096 -- "$f" 2>/dev/null | LC_ALL=C tr -dc '\000' | wc -c) > 0 )) && continue
        printf '%s\n' "$f"
    done < <(find -L "$dir" -type f \
                  ! -name '.*' \
                  ! -iname 'README*' ! -iname 'LICENSE*' ! -iname 'CHANGELOG*' \
                  ! -iname '*.md' ! -iname '*.json' ! -iname '*.yaml' ! -iname '*.yml' \
                  ! -iname '*.gz'  ! -iname '*.zip'  ! -iname '*.bz2'  ! -iname '*.xz' \
                  ! -iname '*.zst' ! -iname '*.7z'   ! -iname '*.tar' \
                  2>/dev/null | sort)
    return 0
}

# Lowercase, strip CRs/comments/blanks, sort -u.
build_wordlist_from_dir() {
    local dir="$1" out="$2"
    [[ "$dir" != / ]] && dir="${dir%/}"   # keeps the per-file log lines relative
    local -a files=()
    mapfile -t files < <(collect_wordlist_files "$dir")
    (( ${#files[@]} )) || die "no usable wordlist files in directory: $dir"

    local f n raw=0
    for f in "${files[@]}"; do
        n=$(count "$f")
        raw=$(( raw + n ))
        detail "$(printf '  %-48s %10d' "${f#"$dir"/}" "$n")"
    done

    cat -- "${files[@]}" 2>/dev/null \
        | tr -d '\r' | tr '[:upper:]' '[:lower:]' \
        | grep -avE '^[[:space:]]*(#|$)' \
        | sort -u -T "$(dirname -- "$out")" > "$out" || true
    [[ -s "$out" ]] || die "the wordlist files under $dir contain no usable words"

    WORDLIST_FILE_COUNT=${#files[@]}
    local uniq; uniq=$(count "$out")
    say "wordlist: ${#files[@]} file(s) under $dir, $raw word(s) -> $uniq unique"
    return 0
}

run_bruteforce() {
    local domain="$1" wordlist="$2" out="$3"
    : > "$out"
    [[ -s "$wordlist" ]] || { warn "wordlist '$wordlist' missing/empty — skipping bruteforce"; return 0; }

    local words eta
    words=$(count "$wordlist")
    # rough ETA
    eta=$(( words / (MASSDNS_CONCURRENCY > 0 ? MASSDNS_CONCURRENCY * 10 : 1) ))
    detail "bruteforcing $domain: $words words, ${MASSDNS_CONCURRENCY} in flight (~$((eta/60))m minimum)"

    local tmp; tmp=$(mktemp -d)
    timed_io "$BRUTE_TIMEOUT" "puredns bruteforce" /dev/null "$tmp/err" \
        puredns bruteforce "$wordlist" "$domain" \
            --bin "$MASSDNS_BIN" \
            -r "$RESOLVERS" --resolvers-trusted "$RESOLVERS_TRUSTED" \
            --rate-limit "$RESOLVER_RATE" --rate-limit-trusted "$TRUSTED_RATE" \
            -t "$WILDCARD_THREADS" \
            --wildcard-tests "$WILDCARD_TESTS" --wildcard-batch "$WILDCARD_BATCH" \
            --write "$tmp/valid.txt" --write-wildcards "$tmp/wildcards.txt" -q

    detail "puredns raw: valid=$(count "$tmp/valid.txt") wildcards=$(count "$tmp/wildcards.txt")"
    [[ -s "$tmp/valid.txt" ]] && clean_hosts "$ROOT_DOMAIN" < "$tmp/valid.txt" > "$out"
    [[ -s "$tmp/wildcards.txt" ]] && cat "$tmp/wildcards.txt" >> "$TMP_DIR/wildcards.txt"
    explain_empty "puredns bruteforce" "$out" "$tmp/err"
    rm -rf "$tmp"
    warn_if_pool_dead "bruteforce on $domain" "$out"
    detail "bruteforce on $domain: $(count "$out") hosts"
}

# PHASE 5 — permutations (alterx), capped on seeds and candidates.
run_permutations() {
    local in="$1" out="$2"
    : > "$out"
    local known; known=$(count "$in")
    (( known == 0 )) && { warn "no seed hosts for permutation"; return 0; }
    have alterx || { warn "alterx is not installed — skipping permutation"; return 0; }

    local work; work=$(mktemp -d)
    local seeds="$work/seeds.txt"

    # shallow names first
    awk -F'.' '{ print NF "\t" $0 }' "$in" \
        | sort -k1,1n -k2,2 | cut -f2- | head -n "$PERMUTE_MAX_INPUT" > "$seeds"

    # -enrich: vocabulary taken from the seeds
    detail "permuting $(count "$seeds") seed(s) with alterx"
    timed "$PERMUTE_GEN_TIMEOUT" alterx \
        alterx -l "$seeds" -enrich -silent 2>/dev/null > "$work/alterx.txt" || true
    detail "alterx generated $(count "$work/alterx.txt")"

    cat "$work/alterx.txt" 2>/dev/null \
        | clean_hosts "$ROOT_DOMAIN" | comm -23 - "$in" > "$work/candidates.all" || true

    local total; total=$(count "$work/candidates.all")
    if (( total > PERMUTE_MAX_CANDIDATES )); then
        warn "capping permutation candidates: $total -> $PERMUTE_MAX_CANDIDATES (raise PERMUTE_MAX_CANDIDATES to go deeper)"
        head -n "$PERMUTE_MAX_CANDIDATES" "$work/candidates.all" > "$work/candidates.txt"
    else
        mv "$work/candidates.all" "$work/candidates.txt"
    fi

    local cands; cands=$(count "$work/candidates.txt")
    if (( cands == 0 )); then
        rm -rf "$work"; detail "permutation produced no new candidates"; return 0
    fi
    detail "resolving $cands permutation candidate(s)"
    resolve_hosts "$work/candidates.txt" "$out"
    cp "$work/candidates.txt" "$TMP_DIR/permutation-candidates.txt" 2>/dev/null || true
    rm -rf "$work"
    detail "permutation: $(count "$out") host(s) found"
}

# PHASE 6 — recursion: expand the most populated non-wildcard zones.

# Zones at a given depth, ranked by known names under them; top few only.
select_targets() {
    local known="$1" level="$2" top="$3"
    awk -F'.' -v L="$level" '
        {
            if (NF == L) cand[$0] = 1
            if (NF > L) {
                p = $(NF - L + 1)
                for (i = NF - L + 2; i <= NF; i++) p = p "." $i
                kids[p]++
            }
        }
        END { for (c in cand) printf "%d\t%s\n", kids[c] + 0, c }
    ' "$known" | sort -k1,1nr -k2,2 | head -n "$top" | cut -f2
}

# Labels already seen, as an extra wordlist for the next level.
recursion_wordlist() {
    local base="$1" known="$2" out="$3"
    cp "$base" "$out"
    [[ "$RECURSE_REUSE_LABELS" == true ]] || return 0
    # apex may have more than two labels (example.co.uk)
    local apex_labels; apex_labels=$(awk -F'.' '{print NF}' <<< "$ROOT_DOMAIN")
    awk -F'.' -v A="$apex_labels" '{ for (i = 1; i <= NF - A; i++) print $i }' "$known" \
        | grep -aE '^[a-z0-9][a-z0-9_-]*$' >> "$out" || true
    sort -u "$out" -o "$out"
    return 0
}

run_recursion() {
    local known="$1" out="$2"
    : > "$out"
    (( RECURSION_DEPTH < 1 )) && { detail "recursion disabled"; return 0; }

    local total; total=$(count "$known")
    if (( total > RECURSE_MAX_KNOWN )); then
        warn "already found $total hosts (> RECURSE_MAX_KNOWN=$RECURSE_MAX_KNOWN) — skipping recursion"
        return 0
    fi

    local root_labels; root_labels=$(awk -F'.' '{print NF}' <<< "$ROOT_DOMAIN")
    local seen="$TMP_DIR/recursed-targets.txt"; : > "$seen"
    local pool; pool=$(mktemp); cp "$known" "$pool"
    local wl="$TMP_DIR/recurse-wordlist.txt"
    local depth level targets n t

    for (( depth = 1; depth <= RECURSION_DEPTH; depth++ )); do
        level=$(( root_labels + depth ))
        targets=$(mktemp)
        select_targets "$pool" "$level" "$RECURSE_MAX_TARGETS" \
            | clean_hosts "$ROOT_DOMAIN" \
            | grep -avxF "$ROOT_DOMAIN" \
            | grep -avxFf "$seen" > "$targets" 2>/dev/null || true

        n=$(count "$targets")
        if (( n == 0 )); then
            detail "recursion depth $depth: no new targets"; rm -f "$targets"; break
        fi

        say "recursion depth $depth: $n target zone(s)"
        while read -r line; do detail "$line"; done < "$targets"
        recursion_wordlist "$RECURSE_WORDLIST" "$pool" "$wl"
        detail "recursion wordlist: $(count "$wl") words ($(count "$RECURSE_WORDLIST") from the list, rest harvested from known names)"

        while read -r t; do
            [[ -z "$t" ]] && continue
            echo "$t" >> "$seen"

            if is_wildcard "$t" "$TMP_DIR/wc-probe.txt"; then
                warn "  $t is a wildcard zone — skipping (would return infinite hosts)"
                echo "$t" >> "$TMP_DIR/wildcard-domains.txt"
                rm -f "$TMP_DIR/wc-probe.txt"
                continue
            fi
            rm -f "$TMP_DIR/wc-probe.txt"

            detail "  recursing into $t"
            local rb="$TMP_DIR/recurse-brute.txt"
            run_bruteforce "$t" "$wl" "$rb"
            [[ -s "$rb" ]] && cat "$rb" >> "$out"
            rm -f "$rb"
        done < "$targets"
        rm -f "$targets"

        sort -u "$out" "$pool" -o "$pool"
    done

    sort -u "$out" -o "$out"
    detail "recursion: $(count "$out") host(s) found"
    rm -f "$pool"
}

# Warn when $OUTPUT_DIR is not a mount (results would die with the container).
# The host path is only printed when HOST_OUTPUT_DIR is given; mountinfo cannot be trusted for it.
check_output_mount() {
    HOST_OUTPUT=""
    [[ -f /.dockerenv || -n "${RECON_IN_CONTAINER:-}" ]] || return 0

    if ! awk -v p="$OUTPUT_DIR" '$5 == p { found = 1; exit } END { exit !found }' \
             /proc/self/mountinfo 2>/dev/null; then
        warn "$OUTPUT_DIR is not a mounted volume — the results will live inside the"
        warn "container only, and vanish with it (docker run --rm deletes them)."
        warn "  mount it:  docker run -v \"\$PWD/output:$OUTPUT_DIR\" ..."
        warn "  or use:    docker compose run --rm gimmesubs ..."
        return 0
    fi

    if [[ -n "${HOST_OUTPUT_DIR:-}" ]]; then
        HOST_OUTPUT="${HOST_OUTPUT_DIR%/}"
    else
        detail "$OUTPUT_DIR is a mounted volume — the results will be on the host after the run"
        detail "  (set HOST_OUTPUT_DIR to have the host-side path printed here)"
    fi
    return 0
}

# chown the run directory (only) to the mount point's owner; runs from a trap.
give_results_back() {
    [[ -n "${RUN_DIR:-}" && -d "$RUN_DIR" ]] || return 0
    local uid gid
    uid=$(stat -c %u "$OUTPUT_DIR" 2>/dev/null) || return 0
    gid=$(stat -c %g "$OUTPUT_DIR" 2>/dev/null) || return 0
    (( uid == 0 )) && return 0          # root-owned mount point; leave it
    chown -R "$uid:$gid" "$RUN_DIR" 2>/dev/null || true
}

# Main
main() {
    # child re-entry for one passive source
    if [[ "${1:-}" == "--internal-source" ]]; then
        DOMAIN="$2"; "src_$3"; exit 0
    fi

    local MODE_GIVEN="" OUT_ROOT="" WORDLIST="" ARGS=()
    local WORDLIST_GIVEN=false
    local DO_BRUTE=true DO_PERMUTE=true DO_RECURSE=true
    VERBOSE=false

    while (( $# )); do
        case "$1" in
            -p|--passive)  MODE_GIVEN="passive"; shift ;;
            -a|--active)   MODE_GIVEN="active"; shift ;;
            -w|--wordlist) WORDLIST="${2:-}"; WORDLIST_GIVEN=true; shift 2 ;;
            -o|--output)   OUT_ROOT="${2:-}"; shift 2 ;;
            --depth)       RECURSION_DEPTH="${2:-}"; shift 2 ;;
            --vps)         apply_vps_profile; shift ;;
            --force)       STOP_ON_WILDCARD=false; shift ;;
            -v|--verbose)  VERBOSE=true; shift ;;
            -h|--help)     usage; exit 0 ;;
            -*)            usage; die "unknown option: $1" ;;
            *)             ARGS+=("$1"); shift ;;
        esac
    done

    # <domain> [wordlist]; -w wins
    (( ${#ARGS[@]} )) || { usage; exit 1; }
    local DOMAIN_ARG="${ARGS[0]}"
    if (( ${#ARGS[@]} > 1 )) && [[ "$WORDLIST_GIVEN" != true ]]; then
        WORDLIST="${ARGS[1]}"; WORDLIST_GIVEN=true
    fi
    (( ${#ARGS[@]} > 2 )) && { usage; die "too many arguments: expected <domain> [wordlist]"; }

    MODE="${MODE_GIVEN:-passive}"
    if [[ "$MODE" == passive ]]; then
        DO_BRUTE=false; DO_PERMUTE=false; DO_RECURSE=false
        [[ -z "$MODE_GIVEN" ]] && detail "no mode given — running passive (-a/--active for the full run)"
    fi

    # accept URLs, *.domain, domain:port
    ROOT_DOMAIN=$(printf '%s' "$DOMAIN_ARG" | tr '[:upper:]' '[:lower:]' \
        | sed -E 's#^[a-z0-9+.-]+://##; s#/.*$##; s#^\*\.##; s#^\.+##; s#\.+$##; s#:[0-9]+$##')
    [[ "$ROOT_DOMAIN" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]] \
        || die "'$DOMAIN_ARG' does not look like a domain"

    [[ "$RECURSION_DEPTH" =~ ^[0-9]+$ ]] || die "--depth must be a non-negative integer"
    (( RECURSION_DEPTH == 0 )) && DO_RECURSE=false

    # wordlist is required for active; never defaulted
    if [[ "$DO_BRUTE" == true || "$DO_RECURSE" == true ]]; then
        [[ "$WORDLIST_GIVEN" == true ]] || {
            usage
            die "--active needs a wordlist: gimmesubs.sh -a $ROOT_DOMAIN /wordlists/<list>.txt"
        }
        if [[ -d "$WORDLIST" ]]; then
            # validate now, merge once tmp/ exists
            WORDLIST_IS_DIR=true
            (( $(collect_wordlist_files "$WORDLIST" | wc -l) )) \
                || die "no usable wordlist files in directory: $WORDLIST"
        else
            [[ -e "$WORDLIST" ]] || die "wordlist not found: $WORDLIST"
            [[ -f "$WORDLIST" ]] || die "wordlist is neither a file nor a directory: $WORDLIST"
            [[ -s "$WORDLIST" ]] || die "wordlist is empty: $WORDLIST"
        fi
    elif [[ "$WORDLIST_GIVEN" == true && "$MODE" == passive ]]; then
        warn "a wordlist was given but the mode is passive — it will not be used (-a to enable it)"
    fi

    RECURSE_WORDLIST="$WORDLIST"

    # one timestamped directory per run
    OUTPUT_DIR="${OUT_ROOT:-$OUTPUT_DIR}"
    local STAMP; STAMP=$(date -u '+%Y%m%d-%H%M%S')
    RUN_DIR="$OUTPUT_DIR/${ROOT_DOMAIN}_${STAMP}"
    TMP_DIR="$RUN_DIR/tmp"
    PASSIVE_DIR="$RUN_DIR/passive"
    local LOG_FILE="$RUN_DIR/gimmesubs.log"
    mkdir -p "$RUN_DIR" "$TMP_DIR" "$PASSIVE_DIR"
    check_output_mount

    trap give_results_back EXIT INT TERM

    local ALL="$TMP_DIR/all-candidates.txt"
    local RESOLVED="$RUN_DIR/subdomains.txt"
    touch "$ALL" "$RESOLVED" "$TMP_DIR/wildcards.txt" "$TMP_DIR/wildcard-domains.txt" \
          "$TMP_DIR/brute.txt" "$TMP_DIR/permuted.txt" "$TMP_DIR/permuted-recursive.txt" \
          "$TMP_DIR/recursed.txt"

    # When stdout is not a terminal, emit the discovered subdomains on it at the
    # end, so results pipe straight on: `gimmesubs ... | http-probe -`. All our
    # logging goes to stderr; fd 1 is logged but NOT forwarded onward, so the
    # pipe carries only the hostnames emitted below — nothing a stray tool writes
    # to stdout can pollute it. The real stdout is kept on a saved fd for that.
    local EMIT_SUBS=false; [[ -t 1 ]] || EMIT_SUBS=true
    local STDOUT_ORIG; exec {STDOUT_ORIG}>&1
    exec > >(tee -a "$LOG_FILE" >/dev/null) 2> >(tee -a "$LOG_FILE" >&2)

    # massdns needs one fd per in-flight query
    ulimit -n "$(ulimit -Hn)" 2>/dev/null || true

    require curl jq sort comm awk shuf dnsx tlsx
    [[ "$MODE" == active ]] && require massdns puredns

    if [[ "$WORDLIST_IS_DIR" == true ]]; then
        WORDLIST_SRC="$WORDLIST"
        WORDLIST="$TMP_DIR/wordlist-merged.txt"
        build_wordlist_from_dir "$WORDLIST_SRC" "$WORDLIST"
        RECURSE_WORDLIST="$WORDLIST"
    fi

    local WORDLIST_LABEL="none (passive)"
    if [[ "$DO_BRUTE" == true || "$DO_RECURSE" == true ]]; then
        if [[ "$WORDLIST_IS_DIR" == true ]]; then
            WORDLIST_LABEL="$WORDLIST_SRC ($WORDLIST_FILE_COUNT files, $(count "$WORDLIST") unique words)"
        else
            WORDLIST_LABEL="$WORDLIST ($(count "$WORDLIST") words)"
        fi
    fi

    local START_TS=$SECONDS
    local WILDCARD_APEX=false

    say "gimmesubs $ROOT_DOMAIN ($MODE) -> $(basename "$RUN_DIR")"
    detail "output   ${HOST_OUTPUT:-$RUN_DIR}"
    detail "wordlist $WORDLIST_LABEL"

    absorb()  { [[ -s "$1" ]] && cat "$1" >> "$ALL"; sort -u "$ALL" -o "$ALL"; }

    # merge a phase's hits; report only the new ones
    merge_results() {
        local f="$1" label="$2" before after
        before=$(count "$RESOLVED")
        if [[ -s "$f" ]]; then
            absorb "$f"
            sort -u "$RESOLVED" "$f" -o "$RESOLVED"
        fi
        after=$(count "$RESOLVED")
        say "$label: $(count "$f") hit(s), $(( after - before )) new, $after alive"
    }

    if [[ "$MODE" == active ]]; then
        step 0 "resolver pool"
        timer_start resolvers
        fetch_resolvers
        prepare_resolvers
        make_massdns_wrapper
        report_dns_load
        detail "phase 0 took $(timer_end resolvers)"
    fi
    prepare_auth_resolvers "$ROOT_DOMAIN"

    step 1 "passive enumeration"
    timer_start passive
    run_passive "$ROOT_DOMAIN" "$TMP_DIR/passive.txt"
    printf '%s\n' "$ROOT_DOMAIN" >> "$TMP_DIR/passive.txt"
    sort -u "$TMP_DIR/passive.txt" -o "$TMP_DIR/passive.txt"
    absorb "$TMP_DIR/passive.txt"
    detail "phase 1 took $(timer_end passive)"

    step 2 "resolution / validation"
    timer_start validate
    resolve_hosts "$ALL" "$TMP_DIR/resolved-passive.txt"
    absorb "$TMP_DIR/resolved-passive.txt"
    cp "$TMP_DIR/resolved-passive.txt" "$RESOLVED"

    if [[ "$TLS_SCRAPE" == true ]]; then
        tls_scrape "$RESOLVED" "$TMP_DIR/tls-sans.txt"
        if [[ -s "$TMP_DIR/tls-sans.txt" ]]; then
            comm -23 "$TMP_DIR/tls-sans.txt" "$RESOLVED" > "$TMP_DIR/tls-new.txt" || true
            if [[ -s "$TMP_DIR/tls-new.txt" ]]; then
                resolve_hosts "$TMP_DIR/tls-new.txt" "$TMP_DIR/tls-resolved.txt"
                sort -u "$RESOLVED" "$TMP_DIR/tls-resolved.txt" -o "$RESOLVED"
                absorb "$TMP_DIR/tls-resolved.txt"
            fi
        fi
    fi
    say "validated: $(count "$RESOLVED") alive"
    detail "phase 2 took $(timer_end validate)"

    step 3 "wildcard detection"
    if is_wildcard "$ROOT_DOMAIN" "$RUN_DIR/wildcard-ips.txt"; then
        WILDCARD_APEX=true
        echo "$ROOT_DOMAIN" >> "$TMP_DIR/wildcard-domains.txt"
        warn "$ROOT_DOMAIN is a WILDCARD domain — random labels resolve to:"
        sed 's/^/      /' "$RUN_DIR/wildcard-ips.txt" >&2
        if [[ "$MODE" == active && "$STOP_ON_WILDCARD" == true ]]; then
            err "active enumeration would return unlimited meaningless hosts — stopping after the passive results"
            err "override with --force if you want to bruteforce anyway (puredns filters wildcard branches)"
            DO_BRUTE=false; DO_PERMUTE=false; DO_RECURSE=false
        elif [[ "$MODE" == active ]]; then
            warn "--force set: continuing; puredns wildcard filtering will do the heavy lifting"
        fi
    else
        detail "$ROOT_DOMAIN is not a wildcard domain — active enumeration is meaningful"
        rm -f "$RUN_DIR/wildcard-ips.txt"
    fi

    if [[ "$DO_BRUTE" == true ]]; then
        step 4 "bruteforce ($(count "$WORDLIST") words)"
        timer_start brute
        run_bruteforce "$ROOT_DOMAIN" "$WORDLIST" "$TMP_DIR/brute.txt"
        merge_results "$TMP_DIR/brute.txt" "bruteforce"
        detail "phase 4 took $(timer_end brute)"
    fi

    if [[ "$DO_PERMUTE" == true ]]; then
        step 5 "permutations"
        timer_start permute
        run_permutations "$RESOLVED" "$TMP_DIR/permuted.txt"
        merge_results "$TMP_DIR/permuted.txt" "permutation"
        detail "phase 5 took $(timer_end permute)"
    fi

    if [[ "$DO_RECURSE" == true ]]; then
        step 6 "recursion (depth $RECURSION_DEPTH)"
        timer_start recurse
        local before_recursion; before_recursion=$(count "$RESOLVED")
        run_recursion "$RESOLVED" "$TMP_DIR/recursed.txt"
        merge_results "$TMP_DIR/recursed.txt" "recursion"

        # re-permute only if recursion added seeds
        if (( $(count "$RESOLVED") > before_recursion )) \
           && [[ "$DO_PERMUTE" == true ]]; then
            detail "permuting recursion findings"
            run_permutations "$RESOLVED" "$TMP_DIR/permuted-recursive.txt"
            merge_results "$TMP_DIR/permuted-recursive.txt" "post-recursion permutation"
        fi
        detail "phase 6 took $(timer_end recurse)"
    fi

    step 7 "enrichment and report"
    timer_start report

    # children of wildcard zones are kept: puredns already dropped the synthetic ones
    if [[ -s "$TMP_DIR/wildcards.txt" ]]; then
        sed -E 's/^\*\.//' "$TMP_DIR/wildcards.txt" | sort -u > "$RUN_DIR/wildcard-roots.txt"
        warn "$(count "$RUN_DIR/wildcard-roots.txt") wildcard branch(es) detected — see wildcard-roots.txt"
    fi
    sort -u "$RESOLVED" -o "$RESOLVED"

    dns_records "$RESOLVED" "$RUN_DIR/dns.json" "$RUN_DIR/dns.txt"

    local TOTAL_TIME=$(( SECONDS - START_TS ))
    {
        printf '# gimmesubs report\n'
        printf 'target        : %s\n' "$ROOT_DOMAIN"
        printf 'mode          : %s\n' "$MODE"
        printf 'finished      : %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'duration      : %dm%02ds\n' $((TOTAL_TIME/60)) $((TOTAL_TIME%60))
        printf 'wildcard apex : %s\n' "$WILDCARD_APEX"
        printf 'wordlist      : %s\n' "$WORDLIST_LABEL"
        if [[ "$MODE" == active ]]; then
            printf 'recursion     : depth %s, up to %s zone(s)/level\n' "$RECURSION_DEPTH" "$RECURSE_MAX_TARGETS"
            printf 'dns ceiling   : %s in flight, %s resolvers, %s retries/name\n' \
                "$MASSDNS_CONCURRENCY" "$(count "${RESOLVERS:-/dev/null}")" "$MASSDNS_RETRIES"
        fi
        printf 'verified with : %s resolver(s)\n' "$(count "$RESOLVERS_TRUSTED")"
        printf '\n## counts\n'
        printf 'passive candidates      : %s\n' "$(count "$TMP_DIR/passive.txt")"
        printf 'all candidates tried    : %s\n' "$(count "$ALL")"
        printf 'bruteforce hits         : %s\n' "$(count "$TMP_DIR/brute.txt")"
        printf 'permutation hits        : %s\n' "$(( $(count "$TMP_DIR/permuted.txt") + $(count "$TMP_DIR/permuted-recursive.txt") ))"
        printf 'recursion hits          : %s\n' "$(count "$TMP_DIR/recursed.txt")"
        printf 'ALIVE SUBDOMAINS        : %s\n' "$(count "$RESOLVED")"
        printf 'unique IPs              : %s\n' "$(count "$RUN_DIR/ips.txt")"
        printf 'wildcard zones skipped  : %s\n' "$(count "$TMP_DIR/wildcard-domains.txt")"
        printf '\n## per passive source\n'
        for f in "$PASSIVE_DIR"/*.txt; do
            [[ -e "$f" ]] || continue
            printf '%-24s %6s\n' "$(basename "$f" .txt)" "$(count "$f")"
        done | sort -k2,2nr
        printf '\n## files\n'
        printf 'subdomains.txt  alive subdomains (the answer)\n'
        printf 'dns.txt/.json   A / AAAA / CNAME records\n'
        printf 'ips.txt         unique resolved addresses\n'
        printf 'passive/        raw per-source output\n'
        printf 'tmp/            per-phase working files\n'
    } > "$RUN_DIR/report.txt"

    cp "$TMP_DIR/wildcard-domains.txt" "$RUN_DIR/wildcard-domains.txt" 2>/dev/null || true
    detail "phase 7 took $(timer_end report)"

    [[ "$VERBOSE" == true ]] && cat "$RUN_DIR/report.txt" >&2
    say "done in $((TOTAL_TIME/60))m$((TOTAL_TIME%60))s: $(count "$RESOLVED") alive, $(count "$RUN_DIR/ips.txt") IPs"
    say "results: ${HOST_OUTPUT:+$HOST_OUTPUT/}$(basename "$RUN_DIR")"
    detail "in the container: $RUN_DIR"

    [[ "$EMIT_SUBS" == true && -s "$RESOLVED" ]] && cat "$RESOLVED" >&"$STDOUT_ORIG"
}

main "$@"
