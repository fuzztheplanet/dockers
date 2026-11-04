if [ -z "${BASH_VERSION:-}" ]; then
    echo "aliases.sh needs bash (it uses BASH_SOURCE); source it from bash." >&2
    return 1 2>/dev/null || exit 1
fi

# Docker invocation building blocks
drun() { docker run --rm "$@"; }
drunhere() { drun -v "$(pwd):/work" -w /work "$@"; }
drunit() { drun -it "$@"; }
drunithere() { drunit -v "$(pwd):/work" -w /work "$@"; }
dshell() { drunit --entrypoint=/bin/bash "$@"; }
dshellhere() { drunithere --entrypoint=/bin/bash "$@"; }

# Shortcut for calling Makefile rules from anywhere
mdm() {
    cd $(dirname -- ${BASH_SOURCE[0]}) &>/dev/null
    make "$@"
    cd - &>/dev/null
}

# With shell completion
if [ -x "$(command -v fzf)" ]; then

    _fzf_complete_mdm() {
        _fzf_complete \
            --multi --ansi \
            --preview "bat --color=always $(dirname -- ${BASH_SOURCE[0]})/{}/Dockerfile 2>/dev/null" \
            --bind 'ctrl-j:preview-down,ctrl-k:preview-up' \
            -- "@" < <(
            { mdm list; echo clean all ;} | tr ' ' '\n'
        )
    }
    complete -F _fzf_complete_mdm -o default -o bashdefault mdm
fi


# skw/ad
ad-run() { drunhere --network=host skw/ad "$@"; }
ad-runit() { drunithere --network=host skw/ad "$@"; }
ad-shell() { dshellhere --network=host skw/ad "$@"; }
ad-miner() { ad-runit AD-miner "$@"; }
bloodhound-ce-python() { ad-runit bloodhound-ce-python "$@"; }
bloodhound-python() { ad-runit bloodhound-python "$@"; }
certipy() { ad-runit certipy "$@"; }
coercer() { ad-runit coercer "$@"; }
donpapi() {
    drunithere -v "$(pwd)/.docker-ad-donpapi:/root/.donpapi" --network=host skw/ad donpapi "$@"
}
krbrelayx() { ad-runit krbrelayx "$@"; }
ldeep() { ad-runit ldeep "$@"; }
nxc() { drunithere -v "$(pwd)/.docker-ad-nxc:/root/.nxc" --network=host skw/ad nxc "$@"; }
petitpotam() { ad-runit petitpotam "$@"; }
smbclient() { ad-runit smbclient "$@"; }
smbserver() { ad-run smbserver.py -smb2support "$@"; }


# skw/bloodhound
bloodhound-run() {
    #   cd ~/projectA && bloodhound-run
    #   cd ~/projectB && bloodhound-run projectb 8712 7475 7688

    CONTAINER_NAME="$(basename "$(pwd)" | tr -dc '0-9a-z')"
    unset BLOODHOUND_PORT
    unset NEO4J_WEB_PORT
    unset NEO4J_DB_PORT

    [[ $# -gt 0 ]] && { CONTAINER_NAME="$1"; shift; }
    [[ $# -gt 0 ]] && { export BLOODHOUND_PORT="$1"; shift; }
    [[ $# -gt 0 ]] && { export NEO4J_WEB_PORT="$1"; shift; }
    [[ $# -gt 0 ]] && { export NEO4J_DB_PORT="$1"; shift; }

    export POSTGRES_DATA_MOUNT="$(pwd)/.docker-bh-postgres"
    export NEO4J_DATA_MOUNT="$(pwd)/.docker-bh-neo4j"
    docker compose -p "${CONTAINER_NAME}" -f "$(dirname -- ${BASH_SOURCE[0]})/bloodhound/docker-compose.yml" up

    unset BLOODHOUND_PORT
    unset NEO4J_WEB_PORT
    unset NEO4J_DB_PORT
    unset POSTGRES_DATA_MOUNT
    unset NEO4J_DATA_MOUNT
}

# skw/forensic
forensic-run() { drunhere skw/forensic "$@"; }
forensic-runit() { drunithere skw/forensic "$@"; }
forensic-shell() { dshellhere skw/forensic "$@"; }
volatility() { forensic-run vol -s /symbols "$@"; }

# skw/http-server
http-server() { drunithere --network=host skw/http-server "$@"; }
https-server() { http-server --server-certificate /etc/ssl/private/server.pem "$@"; }

# skw/java-env
jdeserialize() { drunhere skw/java-env jdeserialize "$@"; }
marshalsec() { drunhere skw/java-env marshalsec "$@"; }
ysoserial() { drunhere skw/java-env ysoserial "$@"; }

# skw/jazzer
jazzer() { drunithere skw/jazzer jazzer "$@"; }
jazzer-shell() { dshellhere skw/jazzer "$@"; }

# skw/pwn
pwn-run() { drunhere --network=host skw/pwn "$@"; }
pwn-runit() { drunithere --network=host skw/pwn "$@"; }
pwn-shell() { dshellhere --network=host skw/pwn "$@"; }

# skw/recon
recon-run() {
    drunithere --ulimit nofile=65535:65535 \
        --sysctl "net.ipv4.ip_local_port_range=10000 65535" \
        -e HOST_OUTPUT_DIR="$PWD" skw/recon "$@"
}
recon-shell() { dshellhere skw/recon "$@"; }

recon() {
    # recon() runs gimmesubs | http-probe | nuclei-auto.
    # recon example.com ~/lists/dns.txt              full pipeline
    # recon --http example.com ~/lists/dns.txt 80,443  stop after http-probe
    # recon --subdomains example.com big              only gimmesubs (bare-name list)

    local dir wldir orig p v prev=""
    local -a opts=() args=() tty=() run=()

    dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/recon
    wldir="${RECON_WORDLISTS:-$dir/wordlists}"

    opts=(-v "$PWD:/work")
    [[ -d "$wldir" ]]      && opts+=(-v "$wldir:/wordlists:ro")
    [[ -d "$dir/config" ]] && opts+=(-v "$dir/config:/opt/recon/config:ro")
    [[ -f "$dir/.env" ]]   && opts+=(--env-file "$dir/.env")
    for v in OTX_KEY LEAKIX_KEY DNSDUMPSTER_KEY FULLHUNT_KEY PASSIVE_TIMEOUT \
             HTTPX_THREADS HTTPX_TIMEOUT HTTPX_RUN_TIMEOUT \
             NUCLEI_RATE_LIMIT NUCLEI_CONCURRENCY NUCLEI_RUN_TIMEOUT NUCLEI_EXCLUDE_TAGS; do
        [[ -n "${!v:-}" ]] && opts+=(-e "$v=${!v}")
    done

    for orig in "$@"; do
        p="$orig"
        if [[ "$prev" == -o || "$prev" == --output ]]; then
            mkdir -p -- "$orig" 2>/dev/null
            if v=$(realpath -- "$orig" 2>/dev/null); then p="$v"; opts+=(-v "$v:$v"); fi
        elif [[ "$orig" != */* && -d "$wldir" && -f "$wldir/${orig%.txt}.txt" ]]; then
            p="/wordlists/${orig%.txt}.txt"
        elif [[ "$orig" != */* && -d "$wldir/$orig" ]]; then
            p="/wordlists/$orig"
        elif [[ "$orig" == */* && -e "$orig" ]]; then
            v=$(realpath -- "$orig"); p="$v"; opts+=(-v "$v:$v:ro")
        fi
        args+=("$p"); prev="$orig"
    done

    [[ -t 0 && -t 1 ]] && tty=(-it)

    run=(--rm "${tty[@]}"
         --ulimit nofile=65535:65535
         --sysctl "net.ipv4.ip_local_port_range=10000 65535"
         "${opts[@]}" -w /work -e "HOST_OUTPUT_DIR=$PWD"
         skw/recon "${args[@]}")

    docker run "${run[@]}"
}

gimmesubs() {
    # gimmesubs -p example.com                   passive enumeration
    # gimmesubs -a example.com ~/lists/big.txt   active with specific wordlist
    # gimmesubs -a example.com ~/lists/          active every list in dir

    local dir wldir orig p v prev=""
    local -a opts=() args=() tty=() run=()

    dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/recon
    wldir="${RECON_WORDLISTS:-$dir/wordlists}"

    opts=(-v "$PWD:/work")
    [[ -d "$wldir" ]]      && opts+=(-v "$wldir:/wordlists:ro")
    [[ -d "$dir/config" ]] && opts+=(-v "$dir/config:/opt/recon/config:ro")
    [[ -f "$dir/.env" ]]   && opts+=(--env-file "$dir/.env")
    for v in OTX_KEY LEAKIX_KEY DNSDUMPSTER_KEY FULLHUNT_KEY PASSIVE_TIMEOUT; do
        [[ -n "${!v:-}" ]] && opts+=(-e "$v=${!v}")
    done

    for orig in "$@"; do
        p="$orig"
        if [[ "$prev" == -o || "$prev" == --output ]]; then
            # The one argument written to rather than read: create it first so
            # the mount lands on something that exists, and mount it rw.
            mkdir -p -- "$orig" 2>/dev/null
            if v=$(realpath -- "$orig" 2>/dev/null); then p="$v"; opts+=(-v "$v:$v"); fi
        elif [[ "$orig" != */* && -d "$wldir" && -f "$wldir/${orig%.txt}.txt" ]]; then
            p="/wordlists/${orig%.txt}.txt"
        elif [[ "$orig" != */* && -d "$wldir/$orig" ]]; then
            # A bare name can also be a directory of lists under $wldir;
            # gimmesubs.sh merges everything under it.
            p="/wordlists/$orig"
        elif [[ "$orig" == */* && -e "$orig" ]]; then
            # Same path inside as outside, file or directory alike. realpath
            # first, so a relative path reaching above the current directory
            # still resolves.
            v=$(realpath -- "$orig"); p="$v"; opts+=(-v "$v:$v:ro")
        fi
        args+=("$p"); prev="$orig"
    done

    [[ -t 0 && -t 1 ]] && tty=(-it)

    run=(--rm "${tty[@]}"
         --ulimit nofile=65535:65535
         --sysctl "net.ipv4.ip_local_port_range=10000 65535"
         "${opts[@]}" -w /work -e "HOST_OUTPUT_DIR=$PWD"
         skw/recon gimmesubs "${args[@]}")

    docker run "${run[@]}"
}

http-probe() {
    # http-probe hosts.txt                 default ports
    # http-probe hosts.txt 80,443,8443     explicit ports
    # cat hosts.txt | http-probe -p 8080   targets on stdin
    local orig p v prev=""
    local -a opts=(-v "$PWD:/work") args=() tty=() run=()

    for v in HTTPX_THREADS HTTPX_TIMEOUT HTTPX_RUN_TIMEOUT; do
        [[ -n "${!v:-}" ]] && opts+=(-e "$v=${!v}")
    done

    for orig in "$@"; do
        p="$orig"
        if [[ "$prev" == -o || "$prev" == --output ]]; then
            mkdir -p -- "$orig" 2>/dev/null
            if v=$(realpath -- "$orig" 2>/dev/null); then p="$v"; opts+=(-v "$v:$v"); fi
        elif [[ "$orig" == */* && -e "$orig" ]]; then
            v=$(realpath -- "$orig"); p="$v"; opts+=(-v "$v:$v:ro")
        fi
        args+=("$p"); prev="$orig"
    done

    if [[ -t 0 && -t 1 ]]; then tty=(-it); elif [[ ! -t 0 ]]; then tty=(-i); fi

    run=(--rm "${tty[@]}" "${opts[@]}" -w /work
         -e "HOST_OUTPUT_DIR=$PWD"
         skw/recon http-probe "${args[@]}")

    docker run "${run[@]}"
}

nuclei-auto() {
    # nuclei-auto http-probe_*/live.txt        scan http-probe's live URLs
    # nuclei-auto urls.txt -s high,critical    only high/critical templates
    # cat urls.txt | nuclei-auto -             URL list on stdin
    local orig p v prev=""
    local -a opts=(-v "$PWD:/work") args=() tty=() run=()

    for v in NUCLEI_RATE_LIMIT NUCLEI_CONCURRENCY NUCLEI_RUN_TIMEOUT; do
        [[ -n "${!v:-}" ]] && opts+=(-e "$v=${!v}")
    done

    for orig in "$@"; do
        p="$orig"
        if [[ "$prev" == -o || "$prev" == --output ]]; then
            mkdir -p -- "$orig" 2>/dev/null
            if v=$(realpath -- "$orig" 2>/dev/null); then p="$v"; opts+=(-v "$v:$v"); fi
        elif [[ "$orig" == */* && -e "$orig" ]]; then
            v=$(realpath -- "$orig"); p="$v"; opts+=(-v "$v:$v:ro")
        fi
        args+=("$p"); prev="$orig"
    done

    if [[ -t 0 && -t 1 ]]; then tty=(-it); elif [[ ! -t 0 ]]; then tty=(-i); fi

    run=(--rm "${tty[@]}" "${opts[@]}" -w /work
         -e "HOST_OUTPUT_DIR=$PWD"
         skw/recon nuclei-auto "${args[@]}")

    docker run "${run[@]}"
}

subs2web() {
    # subs2web -p example.com                      passive, then probe default ports
    # subs2web -a example.com ~/lists/dns.txt      active enum, then probe
    # subs2web -p example.com -- 80,443,8443       http-probe options after --
    local -a g=() h=()
    while (( $# )); do
        [[ "$1" == -- ]] && { shift; h=("$@"); break; }
        g+=("$1"); shift
    done
    gimmesubs "${g[@]}" | http-probe - "${h[@]}"
}

# skw/semgrep — the pro-scan flags live here and nowhere else (semgrep's image
# has no entrypoint script duplicating them).
semgrep() { drunithere --entrypoint semgrep skw/semgrep "$@"; }
semgrep-pro-scan() {
    semgrep scan --pro --dataflow-traces --max-lines-per-finding=0 \
        --max-target-bytes=5000000 --time "$@"
}
semgrep-shell() { drunithere --entrypoint /bin/bash skw/semgrep "$@"; }

# skw/vsftpd (dir, user, password)
vsftpd() {
    docker run --rm --network=host -v "${1}:/home/ftpuser" -e FTP_USER="$2" -e FTP_PASS="${3}" skw/vsftpd
}

# skw/web
# Host networking is opt-in: only localhost/127.0.0.1 targets need it, and it
# hands the container the host's whole network stack. Set WEB_NETWORK_HOST=1
# (e.g. to reach a service running on the host) to add --network=host back.
_web_net() { [[ -n "${WEB_NETWORK_HOST:-}" ]] && printf -- '--network=host'; }

web-run() { drunhere $(_web_net) skw/web "$@"; }
web-runit() { drunithere $(_web_net) skw/web "$@"; }
web-shell() { dshellhere $(_web_net) skw/web "$@"; }

# Tool wrappers go through web-pipe: -i always, so stdin reaches the tool, but
# -t only when stdin AND stdout are terminals. With -t, a piped stdin makes
# docker refuse to start ("input device is not a TTY") and a redirected stdout
# gets CRLF line endings — so `cat urls | uro | anew all.txt` and `gau x > f`
# need it off, while interactive use (sqlmap prompts, colors) keeps it on.
web-pipe() {
    local t=-i
    [[ -t 0 && -t 1 ]] && t=-it
    drun "$t" -v "$(pwd):/work" -w /work $(_web_net) skw/web "$@"
}

# content discovery, bypass, injection, params
ffuf() { web-pipe ffuf "$@"; }
nomore403() { web-pipe nomore403 "$@"; }
sqlmap() { web-pipe sqlmap "$@"; }
sstimap() { web-pipe sstimap "$@"; }   # SSTI detect/exploit: sstimap -u URL
batchql() { web-pipe batchql "$@"; }
clairvoyance() { web-pipe clairvoyance "$@"; }
bypass-url-parser() { web-pipe bypass-url-parser "$@"; }
arjun() { web-pipe arjun "$@"; }
paramspider() { web-pipe paramspider "$@"; }   # archive-mined params: paramspider -d acme.com

# URL / endpoint discovery, JS analysis
#   echo acme.com | gau | uro | anew urls.txt      known URLs, deduped, appended
#   katana -u https://acme.com -jc -jsl -o k.txt   crawl, parse JS for endpoints
#   katana -u https://acme.com -headless -jc     crawl with the baked-in chromium (SPAs)
#   cat urls.txt | subjs | anew js.txt             JS files out of a URL list
#   jsluice urls app.js ; jsluice secrets app.js   endpoints / secrets from a JS file
#   cat js.txt | xnLinkFinder -sf acme.com          endpoints + params from JS (output.txt)
#   sourcemapper -url https://acme.com/app.js.map -output src/
#   waymore -i acme.com -mode U                    archives, URLs only -> results/acme.com/
gau() { web-pipe gau "$@"; }
waymore() { web-pipe waymore "$@"; }
katana() { web-pipe katana "$@"; }
uro() { web-pipe uro "$@"; }
anew() { web-pipe anew "$@"; }
unfurl() { web-pipe unfurl "$@"; }
subjs() { web-pipe subjs "$@"; }
jsluice() { web-pipe jsluice "$@"; }
# xnLinkFinder reads stdin whenever stdin is not a terminal, even with -i, and
# docker -i hands the container a pipe. So the TTY follows stdin here: results
# go to -o/-op files anyway (a redirected stdout only gets its banner, CRLF).
xnLinkFinder() {
    local t=-i
    [[ -t 0 ]] && t=-it
    drun "$t" -v "$(pwd):/work" -w /work $(_web_net) skw/web xnLinkFinder "$@"
}
sourcemapper() { web-pipe sourcemapper "$@"; }
js-beautify() { web-pipe js-beautify "$@"; }

# payload rewriting, pattern grep, reflection, XSS
#   cat urls.txt | gf xss | qsreplace FUZZ | anew xss-candidates.txt
#   cat urls.txt | Gxss -c 50 | anew reflected.txt   params whose value is reflected
#   cat urls.txt | kxss                              reflected + which special chars survive
#   cat urls.txt | dalfox pipe                       scan a URL list for XSS
#   gf -list                                         show the baked gf patterns
qsreplace() { web-pipe qsreplace "$@"; }
gf() { web-pipe gf "$@"; }
Gxss() { web-pipe Gxss "$@"; }
kxss() { web-pipe kxss "$@"; }
dalfox() { web-pipe dalfox "$@"; }

# takeover, CORS, secret & source exposure, JWT
#   subzy run --targets subs.txt                     subdomain-takeover fingerprinting
#   corsy -i urls.txt                                CORS misconfig: reflected origin + creds
#   git-dumper http://acme.com/.git/ dump/           rebuild an exposed .git over plain GETs
#   trufflehog filesystem dump/ --no-verification    secrets, detect-only (never validated)
#   jwt_tool <token>                                 decode/inspect a JWT (alg:none, weak sig)
subzy() { web-pipe subzy "$@"; }
corsy() { web-pipe corsy "$@"; }
git-dumper() { web-pipe git-dumper "$@"; }
trufflehog() { web-pipe trufflehog "$@"; }
jwt_tool() { web-pipe jwt_tool "$@"; }

# Misc software / scripts
evil-winrm() { drunit -v "$(pwd):/data" --network=host oscarakaelvis/evil-winrm "$@"; }
mobsf() { drun -p 127.0.0.1:7011:8000 opensecurity/mobile-security-framework-mobsf:latest "$@"; }
sonarqube() { drun -p 7022:9000 sonarqube:latest "$@"; }
unblob() {
    drunhere -v "$(pwd):/data" -w /data -u "$(id -u):$(id -g)" ghcr.io/onekey-sec/unblob:latest "$@"
}


intigriti_wildcards() {
    if [ $# -ne 1 ] || [ -z "$1" ]; then
        printf 'usage: intigriti_wildcards <intigriti-token>\n' >&2
        return 2
    fi
    docker run --rm --pull=always ghcr.io/sw33tlie/bbscope:latest \
        poll it -t "$1" -p --category wildcard -o t \
    | LC_ALL=C sed -n 's#^[[:space:]]*\*\.\([0-9a-zA-Z.-]*\)[[:space:]]*$#\1#p' \
    | sort -u
}
