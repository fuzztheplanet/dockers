#!/usr/bin/env bash
# http-probe.sh — probe a list of hosts for live HTTP(S) services with httpx.
#
# Input: a file of IPs or FQDNs (positional or -, or piped on stdin).
# For each host x port it reports status code, response size, page title and
# detected technologies. Only responding services are listed.
set -euo pipefail
export LC_ALL=C

# Settings
OUTPUT_DIR="${OUTPUT_DIR:-.}"
PORTS_DEFAULT="80,443,444,8000,8001,8008,8009,8010,8080,8081,8082,8088,8089,8090,8091,8443,8444,8445,8880,8888,8889,8043"
THREADS="${HTTPX_THREADS:-50}"              # httpx -threads
HTTPX_TIMEOUT="${HTTPX_TIMEOUT:-10}"        # httpx -timeout, seconds per request
HTTPX_RUN_TIMEOUT="${HTTPX_RUN_TIMEOUT:-43200}" # wall-clock cap on the whole probe (12h)

# Logging
_ts()  { date -u '+%H:%M:%S'; }
say()  { printf '%s %s\n' "$(_ts)" "$*" >&2; }
warn() { printf '%s warning: %s\n' "$(_ts)" "$*" >&2; }
err()  { printf '%s error: %s\n' "$(_ts)" "$*" >&2; }
die()  { err "$*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
count() { [[ -s "${1:-/dev/null}" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }

usage() {
cat <<'USAGE_TEXT'
http-probe — probe a host list for live HTTP(S) services (httpx)

USAGE
    http-probe.sh <targets> [ports]
    http-probe.sh -  [ports]        targets on stdin
    cat targets.txt | http-probe.sh [ports]

ARGUMENTS
    <targets>            File of IPs or FQDNs, one per line. "-" or a pipe reads
                         from stdin. A line may already carry a scheme or port
                         (https://x, x:8443); those are honoured as given.
    [ports]              Comma-separated HTTP(S) ports to try on hosts that have
                         no port of their own. Positional or -p.
                         Default: 80,81,82,83,84,88,443,444,800,801,808,8000,8001,8002,8003,8004,8008,8009,8010,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8443,8444,8445,8446,8880,8888,8889,8043

OPTIONS
    -p, --ports <list>   Ports to probe                 (default: as above)
    -o, --output <dir>   Where the run directory goes    (default: current dir; /work in the container)
                         Each run writes <dir>/http-probe_<timestamp>/.
    -t, --threads <n>    Concurrent requests             (default: 50)
    -v, --verbose        Show httpx's own progress/errors on the terminal.
    -h, --help           This help

EXAMPLES
    http-probe.sh hosts.txt
    http-probe.sh hosts.txt 80,443,8443
    gimmesubs.sh -p example.com && http-probe.sh example.com_*/subdomains.txt
    cat subdomains.txt | http-probe.sh -p 80,443
USAGE_TEXT
}

# chown the run directory to the mount point's owner so results are not
# left root-owned on the host; runs from a trap so failures are covered too.
give_results_back() {
    [[ -n "${RUN_DIR:-}" && -d "$RUN_DIR" ]] || return 0
    local uid gid
    uid=$(stat -c %u "$OUTPUT_DIR" 2>/dev/null) || return 0
    gid=$(stat -c %g "$OUTPUT_DIR" 2>/dev/null) || return 0
    (( uid == 0 )) && return 0
    chown -R "$uid:$gid" "$RUN_DIR" 2>/dev/null || true
}

# Warn when $OUTPUT_DIR is not a mount: results would vanish with the container.
check_output_mount() {
    [[ -f /.dockerenv || -n "${RECON_IN_CONTAINER:-}" ]] || return 0
    awk -v p="$OUTPUT_DIR" '$5 == p { f = 1; exit } END { exit !f }' \
        /proc/self/mountinfo 2>/dev/null && return 0
    warn "$OUTPUT_DIR is not a mounted volume — results will vanish with the container."
    warn "  mount it:  docker run -v \"\$PWD:$OUTPUT_DIR\" ..."
    return 0
}

main() {
    local INPUT="" PORTS="" OUT_ROOT="" VERBOSE=false
    local -a POS=()

    while (( $# )); do
        case "$1" in
            -p|--ports)    PORTS="${2:-}"; shift 2 ;;
            -o|--output)   OUT_ROOT="${2:-}"; shift 2 ;;
            -t|--threads)  THREADS="${2:-}"; shift 2 ;;
            -v|--verbose)  VERBOSE=true; shift ;;
            -h|--help)     usage; exit 0 ;;
            --)            shift; POS+=("$@"); break ;;
            -)             POS+=("-"); shift ;;
            -*)            die "unknown option: $1 (see --help)" ;;
            *)             POS+=("$1"); shift ;;
        esac
    done

    require_tools

    # Positionals: <targets> [ports]. A lone positional that looks like a port
    # list (and is no existing file) is taken as ports when targets come from a
    # pipe, so `cat hosts | http-probe.sh 80,443` does the obvious thing.
    local stdin_piped=false; [[ ! -t 0 ]] && stdin_piped=true
    case ${#POS[@]} in
        0) [[ "$stdin_piped" == true ]] || { usage; exit 1; }; INPUT="-" ;;
        1) if [[ "${POS[0]}" == "-" ]]; then
               INPUT="-"
           elif [[ -f "${POS[0]}" ]]; then
               INPUT="${POS[0]}"
           elif [[ "$stdin_piped" == true && "${POS[0]}" =~ ^[0-9,]+$ ]]; then
               INPUT="-"; PORTS="${PORTS:-${POS[0]}}"
           else
               die "targets file not found: ${POS[0]}"
           fi ;;
        2) INPUT="${POS[0]}"; PORTS="${PORTS:-${POS[1]}}"
           [[ "$INPUT" == "-" || -f "$INPUT" ]] || die "targets file not found: $INPUT" ;;
        *) die "too many arguments (see --help)" ;;
    esac

    [[ "$INPUT" == "-" && "$stdin_piped" != true ]] && die "no targets on stdin"
    PORTS="${PORTS:-$PORTS_DEFAULT}"
    [[ "$PORTS" =~ ^[0-9]+(,[0-9]+)*$ ]] || die "invalid port list: $PORTS"

    OUTPUT_DIR="${OUT_ROOT:-$OUTPUT_DIR}"
    local STAMP; STAMP=$(date -u '+%Y%m%d-%H%M%S')
    RUN_DIR="$OUTPUT_DIR/http-probe_${STAMP}"
    local LOG_FILE="$RUN_DIR/http-probe.log"
    mkdir -p "$RUN_DIR"
    trap give_results_back EXIT INT TERM
    check_output_mount
    exec > >(tee -a "$LOG_FILE") 2> >(tee -a "$LOG_FILE" >&2)

    # Freeze the target list (from a file or stdin) so it can be counted first.
    local targets="$RUN_DIR/targets.txt"
    if [[ "$INPUT" == "-" ]]; then cat > "$targets"; else cat "$INPUT" > "$targets"; fi
    sed -i 's/\r$//; /^[[:space:]]*$/d' "$targets"
    local n; n=$(count "$targets")
    (( n > 0 )) || die "no targets to probe"

    say "probing $n host(s) on ports $PORTS"

    local -a hv=(-silent -no-color -json
                 -l "$targets" -ports "$PORTS"
                 -threads "$THREADS" -timeout "$HTTPX_TIMEOUT"
                 -status-code -content-length -title -tech-detect
                 -o "$RUN_DIR/http.json")
    [[ "$VERBOSE" == true ]] && hv+=(-stats)

    # Never fail the caller: a non-zero httpx exit (all hosts down, a timeout)
    # is not fatal — whatever it wrote to http.json is still processed below.
    local rc=0
    if [[ "$VERBOSE" == true ]]; then
        timeout --kill-after=10s "${HTTPX_RUN_TIMEOUT}s" httpx "${hv[@]}" || rc=$?
    else
        timeout --kill-after=10s "${HTTPX_RUN_TIMEOUT}s" httpx "${hv[@]}" 2>/dev/null || rc=$?
    fi
    case $rc in
        0)       ;;
        124|137) warn "httpx timed out after ${HTTPX_RUN_TIMEOUT}s (partial results kept)" ;;
        *)       warn "httpx exited rc=$rc (results may be incomplete)" ;;
    esac

    # Derive the readable views from the JSON httpx wrote.
    if [[ -s "$RUN_DIR/http.json" ]]; then
        jq -r '.url' "$RUN_DIR/http.json" | sort -u > "$RUN_DIR/live.txt"
        jq -r '"\(.url) [\(.status_code // "-")] [\(.content_length // 0)] [\(.title // "")] [\((.tech // [])|join(","))]"' \
            "$RUN_DIR/http.json" > "$RUN_DIR/http.txt"
    else
        : > "$RUN_DIR/live.txt"; : > "$RUN_DIR/http.txt"
    fi

    say "$(count "$RUN_DIR/live.txt") live service(s) -> $RUN_DIR/http.txt"
}

require_tools() {
    local miss=() t
    for t in httpx jq; do have "$t" || miss+=("$t"); done
    (( ${#miss[@]} )) && die "missing required tool(s): ${miss[*]}"
    return 0
}

main "$@"
