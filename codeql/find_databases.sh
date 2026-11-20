#!/usr/bin/env bash
# Print every real CodeQL database under the given roots, one path per line.
#
#   find_databases.sh [root ...]      # defaults to "$OUTPUT_DIR" then "."
#
# skw/codeql copy of the skw-codeql skill's scripts/find_databases.sh, baked into
# the image so it runs next to a real codeql binary: on the host, codeql is only a
# shell function from aliases.sh, which a child script does not inherit. Call it
# through the codeql-find-databases alias. The one change is to_host() below: the
# alias mounts the caller's directory at /work and passes its host path in
# HOST_PWD, and paths under it are printed as host paths, not /work/... ones.
#
# Callers build their own array from this output, in their own block: an array does not
# survive into a later Bash call, and an empty one reads as "no database".
#
# Read it with command substitution, not `done < <(...)`: a process substitution discards
# the exit status, and exit 2 below (no codeql on this shell's PATH) then looks exactly
# like an empty result — the one confusion this script exists to prevent.
#
# `codeql resolve database` is the filter that matters. The codeql-database.yml marker is
# written before the build finishes, so a failed build leaves one a bare `find` would take.
set -uo pipefail

# Without codeql the filter below rejects everything, and the script exits 0 having printed
# nothing — indistinguishable from a project with no databases. SKILL.md's auto-detection
# routes that to "build the whole pipeline", so a machine with three good databases and no
# codeql on this shell's PATH rebuilds instead of being told what is actually wrong.
if ! command -v codeql >/dev/null 2>&1; then
  echo "ERROR: codeql not found on PATH — cannot tell a database from the marker a failed build leaves." >&2
  exit 2
fi

if [ "$#" -eq 0 ]; then
  set -- "${OUTPUT_DIR:-.}" "."
fi

# The container's working directory is the caller's, mounted. With HOST_PWD set,
# rewrite paths under it to the host spelling; anything else (a root the alias
# mounted at its own path) is already the same on both sides.
here=$(pwd -P)
to_host() {
  if [ -n "${HOST_PWD:-}" ]; then
    case "$1" in
      "$here") printf '%s\n' "$HOST_PWD"; return ;;
      "$here"/*) printf '%s\n' "$HOST_PWD${1#"$here"}"; return ;;
    esac
  fi
  printf '%s\n' "$1"
}

seen=""
for root in "$@"; do
  [ -d "$root" ] || continue
  # Absolute physical path first: $OUTPUT_DIR is usually inside ".", so searched as written
  # one database surfaces twice under two spellings and defeats the dedup below.
  root=$(cd "$root" 2>/dev/null && pwd -P) || continue
  # Dotted directories are pruned by name rather than excluded with `-not -path '*/.*'`.
  # `find` matches -path against the whole path, and the root above is absolute, so that
  # pattern also matched dotted *ancestors*: a project anywhere under ~/.cache, ~/.local or
  # a dotted checkout reported no databases at all, and the caller rebuilt from scratch.
  # -mindepth 1 keeps the prune off the root itself, which may legitimately be dotted.
  while IFS= read -r marker; do
    db=$(dirname "$marker")
    case "$seen" in
      *"|$db|"*) continue ;;
    esac
    if codeql resolve database -- "$db" >/dev/null 2>&1; then
      seen="$seen|$db|"
      to_host "$db"
    fi
  done < <(find "$root" -mindepth 1 -maxdepth 3 \
    \( -type d -name '.*' -prune \) -o \
    \( -type f -name codeql-database.yml -print \) 2>/dev/null)
done
