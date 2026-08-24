#!/usr/bin/env bash
# nuclei-auto.sh — scan a list of web servers with nuclei, tuned for real,
# actionable findings over noise.
#
# Selection strategy (signal over coverage-of-everything):
#   * severity medium/high/critical only — info and low are where the noise and
#     false positives live (tech/TLS/header/banner observations).
#   * exclude fuzz/dos/intrusive templates — the most false-positive-prone and
#     the ones that can damage the target.
#   * out-of-band (interactsh) left ON — it confirms blind SSRF/RCE/log4j etc.
#     out of band, which raises confidence rather than adding false positives.
# No tag whitelist by default: narrowing to a few tags would skip whole vuln
# classes (sqli, rce, ssrf, auth-bypass) that are not tagged cve/exposure.
# Non-matching templates simply do not fire, so breadth costs time, not FPs.
# Use --tags for a deliberately focused, faster run.
#
# Input: a file of URLs, one per line (positional or -, or piped on stdin) —
# e.g. live.txt from http-probe. Reports the findings, grouped by severity.
set -euo pipefail
export LC_ALL=C

# Settings
OUTPUT_DIR="${OUTPUT_DIR:-.}"
SEVERITY_DEFAULT="medium,high,critical"          # -severity; info and low dropped as noise
TAGS_DEFAULT=""                                  # -tags; empty = no whitelist (all matching)
EXCLUDE_TAGS="${NUCLEI_EXCLUDE_TAGS:-fuzz,dos,intrusive}"  # -exclude-tags
RATE_LIMIT="${NUCLEI_RATE_LIMIT:-150}"           # nuclei -rate-limit (requests/s)
CONCURRENCY="${NUCLEI_CONCURRENCY:-25}"          # nuclei -concurrency (parallel templates)
NUCLEI_RUN_TIMEOUT="${NUCLEI_RUN_TIMEOUT:-43200}" # wall-clock cap on the whole scan (12h)

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
nuclei-auto — scan web servers with nuclei, templates chosen per target (nuclei)

USAGE
    nuclei-auto.sh <targets>
    nuclei-auto.sh -                targets on stdin
    cat urls.txt | nuclei-auto.sh

ARGUMENTS
    <targets>            File of URLs, one per line (http-probe's live.txt is the
                         natural input). "-" or a pipe reads from stdin.

OPTIONS
    -s, --severity <l>   Comma-separated severities to keep
                         (default: medium,high,critical — info and low are noise)
    -t, --tags <list>    Restrict to these template tags for a focused, faster
                         run (default: none — run every matching template)
    -r, --rate-limit <n> Requests per second               (default: 150)
    -c, --concurrency <n> Templates run in parallel         (default: 25)
    -o, --output <dir>   Where the run directory goes    (default: current dir; /work in the container)
                         Each run writes <dir>/nuclei-auto_<timestamp>/.
    -v, --verbose        Show nuclei's own progress on the terminal.
    -h, --help           This help

    Extra nuclei flags may be passed after --, e.g.
        nuclei-auto.sh urls.txt -- -etags wordpress

    Tuned for real findings: medium+ severity only, fuzz/dos/intrusive templates
    excluded, out-of-band (interactsh) confirmation left on. Non-matching
    templates do not fire, so the broad default costs time, not false positives.
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
    local INPUT="" SEVERITY="$SEVERITY_DEFAULT" TAGS="$TAGS_DEFAULT" OUT_ROOT="" VERBOSE=false
    local -a POS=() EXTRA=()

    while (( $# )); do
        case "$1" in
            -s|--severity)     SEVERITY="${2:-}"; shift 2 ;;
            -t|--tags)         TAGS="${2:-}"; shift 2 ;;
            -r|--rate-limit)   RATE_LIMIT="${2:-}"; shift 2 ;;
            -c|--concurrency)  CONCURRENCY="${2:-}"; shift 2 ;;
            -o|--output)       OUT_ROOT="${2:-}"; shift 2 ;;
            -v|--verbose)      VERBOSE=true; shift ;;
            -h|--help)         usage; exit 0 ;;
            --)                shift; EXTRA+=("$@"); break ;;
            -)                 POS+=("-"); shift ;;
            -*)                die "unknown option: $1 (see --help)" ;;
            *)                 POS+=("$1"); shift ;;
        esac
    done

    require_tools

    local stdin_piped=false; [[ ! -t 0 ]] && stdin_piped=true
    case ${#POS[@]} in
        0) [[ "$stdin_piped" == true ]] || { usage; exit 1; }; INPUT="-" ;;
        1) if [[ "${POS[0]}" == "-" ]]; then INPUT="-"
           elif [[ -f "${POS[0]}" ]]; then INPUT="${POS[0]}"
           else die "targets file not found: ${POS[0]}"; fi ;;
        *) die "too many arguments (see --help)" ;;
    esac
    [[ "$INPUT" == "-" && "$stdin_piped" != true ]] && die "no targets on stdin"
    [[ "$SEVERITY" =~ ^[a-z]+(,[a-z]+)*$ ]] || die "invalid severity list: $SEVERITY"
    [[ -z "$TAGS" || "$TAGS" =~ ^[a-z0-9]+([,-][a-z0-9]+)*$ ]] || die "invalid tag list: $TAGS"

    OUTPUT_DIR="${OUT_ROOT:-$OUTPUT_DIR}"
    local STAMP; STAMP=$(date -u '+%Y%m%d-%H%M%S')
    RUN_DIR="$OUTPUT_DIR/nuclei-auto_${STAMP}"
    local LOG_FILE="$RUN_DIR/nuclei-auto.log"
    mkdir -p "$RUN_DIR"
    trap give_results_back EXIT INT TERM
    check_output_mount
    exec > >(tee -a "$LOG_FILE") 2> >(tee -a "$LOG_FILE" >&2)

    # Freeze the target list (from a file or stdin) so it can be counted first.
    local targets="$RUN_DIR/targets.txt"
    if [[ "$INPUT" == "-" ]]; then cat > "$targets"; else cat "$INPUT" > "$targets"; fi
    sed -i 's/\r$//; /^[[:space:]]*$/d' "$targets"
    local n; n=$(count "$targets")
    (( n > 0 )) || die "no targets to scan"

    say "scanning $n target(s) with nuclei (severity: $SEVERITY${TAGS:+, tags: $TAGS})"

    local jsonl="$RUN_DIR/nuclei.jsonl"
    local -a nv=(-disable-update-check -no-color
                 -list "$targets"
                 -severity "$SEVERITY" -exclude-tags "$EXCLUDE_TAGS"
                 -rate-limit "$RATE_LIMIT" -concurrency "$CONCURRENCY"
                 -jsonl -output "$jsonl")
    [[ -n "$TAGS" ]] && nv+=(-tags "$TAGS")
    if [[ "$VERBOSE" == true ]]; then nv+=(-stats); else nv+=(-silent); fi
    (( ${#EXTRA[@]} )) && nv+=("${EXTRA[@]}")

    # Never fail the caller: a non-zero nuclei exit (a timeout, a template error)
    # is not fatal — whatever it wrote to nuclei.jsonl is still processed below.
    local rc=0
    timeout --kill-after=15s "${NUCLEI_RUN_TIMEOUT}s" nuclei "${nv[@]}" || rc=$?
    case $rc in
        0)       ;;
        124|137) warn "nuclei timed out after ${NUCLEI_RUN_TIMEOUT}s (partial results kept)" ;;
        *)       warn "nuclei exited rc=$rc (results may be incomplete)" ;;
    esac

    # Derive the readable views from the JSONL nuclei wrote.
    if [[ -s "$jsonl" ]]; then
        jq -r '"[\(.info.severity)] \(.["template-id"])  \(.["matched-at"] // .host)  — \(.info.name)"' \
            "$jsonl" > "$RUN_DIR/findings.txt"
        {
            printf '# nuclei-auto findings by severity\n'
            jq -r '.info.severity' "$jsonl" | sort | uniq -c | sort -rn
        } > "$RUN_DIR/summary.txt"
    else
        : > "$RUN_DIR/findings.txt"; : > "$RUN_DIR/summary.txt"
    fi

    say "$(count "$RUN_DIR/findings.txt") finding(s) -> $RUN_DIR/findings.txt"
}

require_tools() {
    local miss=() t
    for t in nuclei jq; do have "$t" || miss+=("$t"); done
    (( ${#miss[@]} )) && die "missing required tool(s): ${miss[*]}"
    return 0
}

main "$@"
