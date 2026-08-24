#!/usr/bin/env bash
# recon.sh — run the recon pipeline against an apex domain:
#
#   gimmesubs (subdomain enum) -> http-probe (live web services) -> nuclei-auto
#
# Stages run in order and each feeds the next. --subdomains stops after the
# first stage, --http after the second, the default runs all three.
#
# As a convenience it also dispatches to a single tool when the first argument
# is its name (recon gimmesubs …, recon http-probe …, recon nuclei-auto …); this
# is how the per-tool launcher functions in aliases.sh reach the image.
set -euo pipefail
export LC_ALL=C
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OUTPUT_DIR="${OUTPUT_DIR:-.}"

_ts()  { date -u '+%H:%M:%S'; }
say()  { printf '%s %s\n' "$(_ts)" "$*" >&2; }
warn() { printf '%s warning: %s\n' "$(_ts)" "$*" >&2; }
err()  { printf '%s error: %s\n' "$(_ts)" "$*" >&2; }
die()  { err "$*"; exit 1; }
count() { [[ -s "${1:-/dev/null}" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }

usage() {
cat <<'USAGE_TEXT'
recon.sh

Performs subdomain enumeration, HTTP probing and nuclei scans

USAGE
    recon.sh [options] <apex-domain> <wordlist> [ports]

ARGUMENTS
    <apex-domain>        Domain to enumerate, e.g. example.com.
    <wordlist>           Wordlist for bruteforcing subdomains (a file or a directory).
    [ports]              HTTP(S) ports for http-probe (default: its own default set).
    --subdomains         Perform only subdomain enumeration.
    --http               Perform --subdomains + http-probe on the resolved subdomains.
    --full               Perform --subdomains --http and then nuclei-auto  (default).
    -o, --output <dir>   Set output directory (default: ./recon_<domain>_<timestamp>)
    -h, --help           This help

EXAMPLES
    recon.sh example.com ~/lists/dns.txt
    recon.sh --http example.com ~/lists/dns.txt 80,443,8443
    recon.sh --subdomains example.com ~/lists/dns.txt
USAGE_TEXT
}

# chown the run directory to the mount point's owner so results are not left
# root-owned on the host; runs from a trap so failures are covered too. The
# per-stage tools skip their own chown because their -o dir is root-owned, so
# this one pass fixes the whole tree.
give_results_back() {
    [[ -n "${RUN_DIR:-}" && -d "$RUN_DIR" ]] || return 0
    local uid gid
    uid=$(stat -c %u "$OUTPUT_DIR" 2>/dev/null) || return 0
    gid=$(stat -c %g "$OUTPUT_DIR" 2>/dev/null) || return 0
    (( uid == 0 )) && return 0
    chown -R "$uid:$gid" "$RUN_DIR" 2>/dev/null || true
}

# First output file matching <name> under <dir> (each stage runs into a fresh
# -o dir, so there is exactly one).
find_one() {
    find "$1" -maxdepth 2 -name "$2" -type f 2>/dev/null | head -1
}

main() {
    local STAGE=full OUT_ROOT=""
    local -a POS=()

    while (( $# )); do
        case "$1" in
            --subdomains|--subs)  STAGE=subdomains; shift ;;
            --http)               STAGE=http; shift ;;
            --full|--all|--nuclei) STAGE=full; shift ;;
            -o|--output)          OUT_ROOT="${2:-}"; shift 2 ;;
            -h|--help)            usage; exit 0 ;;
            --)                   shift; POS+=("$@"); break ;;
            -*)                   die "unknown option: $1 (see --help)" ;;
            *)                    POS+=("$1"); shift ;;
        esac
    done

    local DOMAIN="${POS[0]:-}" WORDLIST="${POS[1]:-}" PORTS="${POS[2]:-}"
    [[ -n "$DOMAIN" && -n "$WORDLIST" ]] || { usage; exit 1; }
    [[ -e "$WORDLIST" ]] || die "wordlist not found: $WORDLIST"
    [[ -z "$PORTS" || "$PORTS" =~ ^[0-9]+(,[0-9]+)*$ ]] || die "invalid port list: $PORTS"
    [[ "$STAGE" == subdomains && -n "$PORTS" ]] && warn "ports ignored with --subdomains"

    OUTPUT_DIR="${OUT_ROOT:-$OUTPUT_DIR}"
    local STAMP; STAMP=$(date -u '+%Y%m%d-%H%M%S')
    local safe; safe=$(printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9.-' '-')
    RUN_DIR="$OUTPUT_DIR/recon_${safe}_${STAMP}"
    local LOG_FILE="$RUN_DIR/recon.log"
    mkdir -p "$RUN_DIR"
    trap give_results_back EXIT INT TERM
    exec > >(tee -a "$LOG_FILE") 2> >(tee -a "$LOG_FILE" >&2)

    say "recon pipeline (stage: $STAGE) on $DOMAIN"

    # --- Stage 1: subdomains -------------------------------------------------
    say "[1/3] gimmesubs — subdomain enumeration"
    local rc=0
    gimmesubs.sh -a "$DOMAIN" "$WORDLIST" -o "$RUN_DIR/1-subdomains" >/dev/null || rc=$?
    (( rc == 0 )) || warn "gimmesubs exited rc=$rc"
    local subs; subs=$(find_one "$RUN_DIR/1-subdomains" subdomains.txt)
    [[ -n "$subs" ]] && cp -f "$subs" "$RUN_DIR/subdomains.txt" || : > "$RUN_DIR/subdomains.txt"
    local n_subs; n_subs=$(count "$RUN_DIR/subdomains.txt")
    say "    $n_subs subdomain(s) -> subdomains.txt"

    if [[ "$STAGE" == subdomains ]]; then finish "$n_subs"; return; fi
    (( n_subs > 0 )) || { warn "no subdomains resolved — stopping"; finish 0; return; }

    # --- Stage 2: http-probe -------------------------------------------------
    say "[2/3] http-probe — live HTTP(S) services"
    local -a pflag=(); [[ -n "$PORTS" ]] && pflag=(-p "$PORTS")
    rc=0
    http-probe.sh "$RUN_DIR/subdomains.txt" "${pflag[@]}" -o "$RUN_DIR/2-http" >/dev/null || rc=$?
    (( rc == 0 )) || warn "http-probe exited rc=$rc"
    local live; live=$(find_one "$RUN_DIR/2-http" live.txt)
    [[ -n "$live" ]] && cp -f "$live" "$RUN_DIR/live.txt" || : > "$RUN_DIR/live.txt"
    local n_live; n_live=$(count "$RUN_DIR/live.txt")
    say "    $n_live live web service(s) -> live.txt"

    if [[ "$STAGE" == http ]]; then finish "$n_subs" "$n_live"; return; fi
    (( n_live > 0 )) || { warn "no live web services — stopping"; finish "$n_subs" 0; return; }

    # --- Stage 3: nuclei-auto ------------------------------------------------
    say "[3/3] nuclei-auto — vulnerability scan"
    rc=0
    nuclei-auto.sh "$RUN_DIR/live.txt" -o "$RUN_DIR/3-nuclei" >/dev/null || rc=$?
    (( rc == 0 )) || warn "nuclei-auto exited rc=$rc"
    local findings; findings=$(find_one "$RUN_DIR/3-nuclei" findings.txt)
    [[ -n "$findings" ]] && cp -f "$findings" "$RUN_DIR/findings.txt" || : > "$RUN_DIR/findings.txt"
    local n_find; n_find=$(count "$RUN_DIR/findings.txt")
    say "    $n_find finding(s) -> findings.txt"

    finish "$n_subs" "$n_live" "$n_find"
}

finish() {
    say "done: ${1:-0} subdomains${2:+, $2 live}${3:+, $3 findings} -> $(basename "$RUN_DIR")"
}

# --- entry: dispatch to a single tool, otherwise run the pipeline ------------
case "${1:-}" in
    gimmesubs|subs)     shift; exec "$DIR/gimmesubs.sh"   "$@" ;;
    http-probe|http)    shift; exec "$DIR/http-probe.sh"  "$@" ;;
    nuclei-auto|nuclei) shift; exec "$DIR/nuclei-auto.sh" "$@" ;;
    shell|sh|bash)      shift; exec /bin/bash "$@" ;;
    ""|help)            usage; exit 0 ;;
esac
main "$@"
