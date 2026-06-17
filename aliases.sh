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
alias recon-shell='drunithere skw/recon '

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
