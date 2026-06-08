#!/usr/bin/env bash

# For a given domain (eg. example.com), the script performs the following steps
# to enumerate subdomains:
#     0: Download and sort DNS resolvers by speed, keep the most perfomant.
#     1: Passive enumeration with amass, subfinder and gau.
#     2: Find authoritative nameservers for example.com.
#     3: Actually resolve example.com.
#     4: Resolve results from passive enumeration to start building a list of
#        active subdomains.
#     5: Until maximum recursion depth is reached, perform:
#     6:   - Check if *.item.example.com is wildcard, if yes, stop.
#     7:   - Bruteforce *.item.example.com with wordlist (add previously found
#            subdomains to it). Validate results with auth resolvers.


# Default values
ACTIVE=false
KEEP=false
LEVEL=2
OUTDIR="gimmesubs_$(date '+%Y%m%d-%H%M')"
RESOLVERS_URL="https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
RESOLVERS_WORKERS=42
RESOLVERS_NB_QUERY=400
RESOLVERS_NB_KEEP=200
WORDLIST="/etc/hostname"


usage() {
    >&2 cat <<EOF
Usage: $0 [options] [<domain.com>..]"

Options:
    -a, --active                 Perform active subdomain enumeration (default:
                                 false).
    -h, --help                   Display this help message.
    -k, --keep                   Keep temporary files (default: false).
    -l, --level <level>          Set maximum level for recursive active
                                 enumeration (default: 2).
    -o, --out <dir>              Set output directory (default:
                                 timestamp-based).
    --resolvers-url <url>        Set url to fetch resolvers from.
    --resolvers-workers <nb>     Set number of parallel lookup for resolvers.
    --resolvers-nb-query <nb>    Set how many resolvers should be queried.
    --resolvers-nb-keep <nb>     Set how many resolvers should be kept.
    -w, --wl <file>              Set wordlist for bruteforce (active).
EOF
}


# logmsg: echo all options passed to stdout and to $LOGFILE.
logmsg() { echo "$@" | tee -a "${LOGFILE}" ;}


# add_subdomains: add subdomains (subdomain,ip) from file $1 to subdomains.txt.
add_subdomains() {
    local additional="$1"
    cat active.txt "${additional}" 2>/dev/null | sort -u > active.txt_
    mv active.txt_ active.txt
}


# select_subdomains: print lines from subdomains.txt matching domain $1 and
# having items of level $2. For example with domain=example.com:
# level 0: example.com
# level 1: foo.example.com
# level 2: test-bar.foo.example.com
select_subdomains() {
    local domain="$1"
    local level="$2"
    cut -d ',' -f 1 active.txt | \
        grep -Eo "([a-z0-9\-]+\.){${level}}${domain}\$" | sort -u
}


# sanitize_subdomains: translate input from stdin to lowercase and keep lines
# containing exclusively lowercase chars, digits, hyphens and dots.
sanitize_subdomains() {
    tr 'A-Z' 'a-z' | grep -E '^[a-z0-9\-\.]+$'
}


# write_queries: write test dns queries for dnsperf to file $1.
write_queries() {
    cat <<EOF > $1
github.com A
google.com A
reddit.com A
skywhi.net A
facebook.com A
EOF
}


# download_resolvers: write list of resolvers to outfile $1. Test nb_test
# resolvers $4 for speed using nb_workers $2 and keep nb_keep $3 top results.
download_resolvers() {
    local outfile="$1"
    local nb_workers="${2:-42}"
    local nb_keep="${3:-30}"
    local nb_query="${4:-20000}"

    write_queries test-queries.txt

    curl -s ${RESOLVERS_URL} \
        | head -n "${nb_query}" \
        | xargs -I{} -P "${nb_workers}" bash -c '
  avg=$(dnsperf -s "{}" -d test-queries.txt -l 2 2>/dev/null | grep -Po "Average Latency \(s\):  \K[0-9\.]+")
  echo "$avg {}"' \
        | grep -v "0.000000" \
        | sort -n > tested.txt

    cat tested.txt | cut -d ' ' -f 2 | head -n "${nb_keep}" > "${outfile}"

    ! $KEEP && rm tested.txt test-queries.txt
}


# resolve_stdin: resolve domains from stdin with resolvers $1. Print
# subdomain,ip to stdout.
resolve_stdin() {
    local resolvers="$1"
    massdns -s 20000 -r "${resolvers}" -t A -o S 2>/dev/null \
        | awk '{ gsub(/\.$/, "", $1); print $1 "," $3 }' \
        | sort -u
}


# resolve_file: resolve domains from file $1 using resolvers $3 and store them
# in file $2 as smbdomain,ip. Some basic test show that processing massdns
# inputs from a file can be slightly faster than stdin.
resolve_file() {
    local infile="$1"
    local outfile="$2"
    local resolvers="$3"
    local tmpfile=$(mktemp)

    massdns -s 20000 --processes 8 -r "${resolvers}" \
            -t A -o S \
            -w "${tmpfile}" "${infile}" 2>/dev/null

    awk '{ gsub(/\.$/, "", $1); print $1 "," $3 }' "${tmpfile}"* \
        | sort -u > "${outfile}"
    rm "${tmpfile}"*
}


# is_wildcard: returns true (0) if domain $1 is a wildcard, ie: if
# <random string>.$1 resolves according to resolvers $2.
is_wildcard() {
    local domain="$1"
    local resolvers="$2"
    local random_sub=$(head /dev/urandom | tr -dc a-z0-9 | head -c 12)
    local result=$(echo "${random_sub}.${domain}" | resolve_stdin "${resolvers}")
    [[ -z "${result}" ]]
}


# make_wordlist: prepend each line of wordlist $2 to domain $1.
make_wordlist() {
    local domain="$1"
    local wordlist="$2"
    awk "{print \$1 \".${domain}\"}" "${wordlist}" \
        | sanitize_subdomains | sort -u
}


# enum_domain_passive: passive enumeration of domain $1.
enum_domain_passive() {
    local domain="$1"
    local amass_results="./tmp/amass.txt"
    local subfinder_results="./tmp/subfinder.txt"
    local gau_results="./tmp/gau.txt"

    logmsg "[*] Passive enumeration:"

    # Run amass, subfinder, gau
    logmsg -n "[*]   - Running amass"
    touch "${amass_results}"
    amass enum -d "${domain}" 2>/dev/null | tail -n +6 >> "${amass_results}"
    logmsg " (got $(wc -l ${amass_results} | cut -d ' ' -f 1) domains)"

    logmsg -n "[*]   - Running subfinder"
    touch "${subfinder_results}"
    subfinder -silent -timeout 60 -max-time 20 \
              -o "${subfinder_results}" -d "${domain}" 1>/dev/null
    logmsg " (got $(wc -l ${subfinder_results} | cut -d ' ' -f 1) domains)"

    logmsg -n "[*]   - Running gau"
    gau --subs "${domain}" 2>/dev/null \
        | unfurl -u domains | grep "${domain}" | sort -u > "${gau_results}"
    logmsg " (got $(wc -l ${gau_results} | cut -d ' ' -f 1) domains)"

    # Merge results
    cat "${amass_results}" "${subfinder_results}" "${gau_results}" 2>/dev/null \
        | sanitize_subdomains | sort -u > passive.txt

    logmsg "[*]   - Found $(wc -l passive.txt | cut -d ' ' -f 1) unique subdomains"

    ! $KEEP && rm "${amass_results}" "${subfinder_results}" "${gau_results}"
}


# enum_domain_active_level: active enumeration of domain $1, with resolvers $2
# and auth_resolvers $3 of level $4.
enum_domain_active_level() {
    local domain="$1"
    local resolvers="$2"
    local auth_resolvers="$3"
    local rec_level="$4"
    local targets=$(select_subdomains "${domain}" "${rec_level}")

    logmsg "[*]   - Running stage ${rec_level} ($(echo ${targets[@]} | wc -l | cut -d ' ' -f 1) targets)"

    if [[ -z "${targets}" ]]; then
        logmsg "[*]     - No targets found. Moving on."
        return
    fi

    while IFS= read -r target; do

        # If it's a wildcard domain, we stop here. For example if
        # "fjzrez473893.staging.example.com" resolves.
        if is_wildcard "$target" "${auth_resolvers}"; then
            logmsg "[*]     - Wildcard domain detected for *.${target}. Stopping."
            echo "${target}" >> wildcards.txt
            sort -u -o wildcards.txt wildcards.txt
            return
        fi

        # Add existing subdomains to a wordlist and try to resolve
        # <candidate>.${target}. Validate results against auth resolvers.
        logmsg -n "[*]     - Bruteforcing *.${target} "

        make_wordlist "${target}" "${WORDLIST}" > tmp/wl_${rec_level}.txt
        cat active.txt 2>/dev/null | cut -d ',' -f 1 \
            | sed -n "s/.${domain}\$//p" | sort -u \
            | xargs -I{} echo "{}.${target}" >> tmp/wl_${rec_level}.txt

        resolve_file tmp/wl_${rec_level}.txt tmp/brute_${rec_level}.txt "${resolvers}"
        resolve_file tmp/brute_${rec_level}.txt tmp/resolved_${rec_level}.txt "${auth_resolvers}"
        add_subdomains tmp/resolved_${rec_level}.txt
        logmsg "($(wc -l tmp/resolved_${rec_level}.txt | cut -d ' ' -f 1) domains)"

        ! $KEEP && rm tmp/brute_${rec_level.txt} tmp/resolved_${rec_level.txt} tmp/wl_${rec_level.txt}
    done <<< "${targets}"
}


# enum_domain_active: active enumeration of domain $1 with resolvers $2.
enum_domain_active() {
    local domain="$1"
    local resolvers="$2"
    local auth_resolvers=$(realpath auth-resolvers.txt)

    # The main results will be stored in active.txt as subdomain,ip
    logmsg "[*] Active enumeration:"
    touch active.txt

    # The authorative resolver will be used to validate findings
    #logmsg "[*]   - Setting auth resolver"
    #/root/tools/massdns/scripts/auth-addrs.sh "${domain}" | sort -Vu > "${auth_resolvers}"
    auth_resolvers="${resolvers}"

    # Can we even resolve the $domain?
    logmsg "[*]   - Resolving ${domain}"
    echo "${domain}" | resolve_stdin "${auth_resolvers}" > tmp/domain.txt
    add_subdomains tmp/domain.txt
    ! $KEEP && rm tmp/domain.txt

    # Resolve items from the passive enumeration to have a solid starting base
    logmsg -n "[*]   - Resolving domains from passive enumeration "
    cat passive.txt | resolve_stdin "${auth_resolvers}" > tmp/resolved.txt
    add_subdomains tmp/resolved.txt
    logmsg "(got $(wc -l tmp/resolved.txt | cut -d ' ' -f 1) active subdomains)"
    ! $KEEP && rm tmp/resolved.txt

    # Examine up to $LEVEL subdomains
    for i in $(seq 0 ${LEVEL}); do
        enum_domain_active_level "${domain}" "${resolvers}" "${auth_resolvers}" $i
    done

    # Log results of active enumeration
    cut -d ',' -f1 active.txt | sort -u > subdomains.txt
    cut -d ',' -f2 active.txt | sort -u > ips.txt
    logmsg "[*]   Found $(wc -l subdomains.txt | cut -d ' ' -f 1) unique subdomains"

    cd - &>/dev/null
}


# Parse command line arguments
PARSED=$(getopt -o ahko:w:l: \
                --long active,help,keep,out:,wl:,level: \
                --name "$0" -- "$@")

if [[ $? -ne 0 ]]; then
    usage
    exit 1
fi

eval set -- "$PARSED"

while true; do
    case "$1" in
        -a|--active)
            ACTIVE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -k|--keep)
            KEEP=true
            shift
            ;;
        -l|--level)
            LEVEL="$2"
            shift 2
            ;;
        -o|--out)
            OUT="$2"
            shift 2
            ;;
        --resolvers-url)
            RESOLVERS_URL="$2"
            shift 2
            ;;
        --resolvers-nb-keep)
            RESOLVERS_NB_KEEP="$2"
            shift 2
            ;;
        --resolvers-nb-query)
            RESOLVERS_NB_QUERY="$2"
            shift 2
            ;;
        --resolvers-workers)
            RESOLVERS_WORKERS="$2"
            shift 2
            ;;
        -w|--wl)
            WORDLIST="$2"
            shift 2
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Parsing error"
            exit 1
            ;;
    esac
done

DOMAINS=("$@")

# Set realpath to $WORDLIST
WORDLIST=$(realpath "${WORDLIST}")

# Create output directory and log file
mkdir -p "$OUTDIR"
cd "$OUTDIR"
LOGFILE=$(realpath log.txt)

# Write initial log message
logmsg "[*] Using options:"
logmsg "[*]   active   : ${ACTIVE}"
logmsg "[*]   keep     : ${KEEP}"
logmsg "[*]   levels   : ${LEVEL}"
logmsg "[*]   outdir   : ${OUTDIR}"
logmsg "[*]   wordlist : ${WORDLIST}"
logmsg "[*]   domains  : ${DOMAINS[*]}"

# Download and sort resolvers as they will be used for all domains
if $ACTIVE; then
    logmsg "[*] Downloading and testing resolvers"
    RESOLVERS=$(realpath resolvers.txt)
    download_resolvers "${RESOLVERS}" "${RESOLVERS_WORKERS}" "${RESOLVERS_NB_QUERY}" "${RESOLVERS_NB_KEEP}"
fi

# Enumerate each domain
for domain in "${DOMAINS[@]}"; do

    logmsg "[*] ### Starting subdomain enumeration of ${domain} ###"

    mkdir -p "${domain}/tmp"
    cd "${domain}"

    enum_domain_passive "${domain}"
    $ACTIVE && enum_domain_active "${domain}" "${RESOLVERS}"

    ! $KEEP && rm -rf "${domain}/tmp"
done

# Leave output directory
cd - &>/dev/null
