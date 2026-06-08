#!/bin/sh
set -eu

semgrep scan --pro --dataflow-traces --max-lines-per-finding=0 --max-target-bytes=5000000 --time  "$@"
