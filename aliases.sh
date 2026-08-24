# Aliases for common docker commands
alias drun='docker run --rm '
alias drunhere='drun -v `pwd`:/work -w /work '
alias drunit='drun -it '
alias drunithere='drunit -v `pwd`:/work -w /work '
alias dshell='drunit --entrypoint=/bin/bash '
alias dshellhere='drunithere --entrypoint=/bin/bash '

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
alias ad-run='drunhere --network=host skw/ad '
alias ad-runit='drunithere --network=host skw/ad '
alias ad-shell='dshellhere --network=host skw/ad '
alias bloodhound-ce-python='ad-runit bloodhound-ce-python '
alias bloodhound-python='ad-runit bloodhound-python '
alias certipy='ad-runit certipy '
alias coercer='ad-runit coercer '
alias nxc='drunithere -v `pwd`/.docker-ad-nxc:/root/.nxc --network=host skw/ad nxc '
alias responder='drunithere -v `pwd`/.docker-ad-responder:/root/tools/responder/logs skw/ad Responder.py '
alias smbclient='ad-runit smbclient '
alias smbserver='ad-run smbserver.py -smb2support '

petitpotam() {
    ad-shell -c ". /root/.local/share/pipx/venvs/impacket/bin/activate; PetitPotam.py $@"
}


# skw/bloodhound
bloodhound-run() {
    #   cd ~/projectA && bloodhound-run
    #   cd ~/projectB && bloodhound-run projectb 8712 7475 7688

    CONTAINER_NAME="$(basename $(pwd) | tr -dc '0-9a-z')"
    unset BLOODHOUND_PORT
    unset NEO4J_WEB_PORT
    unset NEO4J_DB_PORT

    [[ $# -gt 0 ]] && { CONTAINER_NAME="$1"; shift; }
    [[ $# -gt 0 ]] && { export BLOODHOUND_PORT="$1"; shift; }
    [[ $# -gt 0 ]] && { export NEO4J_WEB_PORT="$1"; shift; }
    [[ $# -gt 0 ]] && { export NEO4J_DB_PORT="$1"; shift; }

    export POSTGRES_DATA_MOUNT="$(pwd)/.docker-bh-postgres"
    export NEO4J_DATA_MOUNT="$(pwd)/.docker-bh-neo4j"
    docker-compose -p "${CONTAINER_NAME}" -f "$(dirname -- ${BASH_SOURCE[0]})/bloodhound/docker-compose.yml" up

    unset BLOODHOUND_PORT
    unset NEO4J_WEB_PORT
    unset NEO4J_DB_PORT
    unset POSTGRES_DATA_MOUNT
    unset NEO4J_DATA_MOUNT
}

# skw/forensic
alias forensic-run='drunhere skw/forensic '
alias forensic-runit='drunithere skw/forensic '
alias forensic-shell='dshellhere skw/forensic '
alias volatility='forensic-run vol -s /symbols '

# skw/http-server
alias http-server='drunithere --network=host skw/http-server '
alias https-server='http-server --server-certificate /etc/ssl/private/server.pem '

# skw/java-env
alias jdeserialize='drunhere skw/java-env jdeserialize '
alias marshalsec='drunhere skw/java-env marshalsec '
alias ysoserial='drunhere skw/java-env ysoserial '

# skw/pwn
alias pwn-run='drunhere --network=host skw/pwn '
alias pwn-runit='drunithere --network=host skw/pwn '
alias pwn-shell='dshellhere --network=host skw/pwn '

# skw/recon
alias recon-run='drunithere --ulimit nofile=65535:65535 --sysctl "net.ipv4.ip_local_port_range=10000 65535" -e HOST_OUTPUT_DIR="$PWD" skw/recon '
alias recon-shell='dshellhere skw/recon '

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

# skw/semgrep
alias semgrep='drunithere --entrypoint semgrep skw/semgrep '
alias semgrep-pro-scan='semgrep scan --pro --dataflow-traces --max-lines-per-finding=0 --max-target-bytes=5000000 --time '
alias semgrep-shell='drunithere --entrypoint /bin/bash skw/semgrep '

# skw/vsftpd (dir, user, password)
vsftpd() {
    docker run --rm --network=host -v "${1}:/home/ftpuser" -e FTP_USER="$2" -e FTP_PASS="${3}" skw/vsftpd
}

# Misc software / scripts
alias evil-winrm='drunit -v `pwd`:/data --network=host oscarakaelvis/evil-winrm'
alias mobsf='drun -p 127.0.0.1:7011:8000 opensecurity/mobile-security-framework-mobsf:latest '
alias sonarqube='drun -p 7022:9000 sonarqube:latest '
alias unblob='drunhere -v `pwd`:/data -w /data -u $UID:$GID ghcr.io/onekey-sec/unblob:latest '
