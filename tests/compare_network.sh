#!/bin/sh
set -eu

# Linux traceroute options: https://man7.org/linux/man-pages/man8/traceroute.8.html
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

check_environment() {
    if [ "$(uname -s)" != Linux ]; then
        printf 'Esta prueba requiere Linux y permisos para RAW sockets.\n' >&2
        exit 1
    fi
    for command_name in make traceroute diff mktemp; do
        command -v "$command_name" >/dev/null 2>&1 || {
            printf 'Falta el comando: %s\n' "$command_name" >&2
            exit 1
        }
    done
}

run_logged() {
    log_prefix=$1
    shift
    status=0
    "$@" >"$log_prefix.log" 2>"$log_prefix.err" || status=$?
    if [ "$status" -ne 0 ]; then
        cat "$log_prefix.err" >&2
        printf 'Prueba fallida; resultados: %s.*\n' "$log_prefix" >&2
    fi
    return "$status"
}

compare_destination() {
    destination=$1
    prefix="$output_dir/$2"
    printf 'Comparando destino: %s\n' "$destination"
    run_logged "$prefix.own" "$project_dir/my_traceroute" \
        -f 1 -m 64 -q 3 -w 3 -z 100 -- "$destination"
    run_logged "$prefix.system" traceroute \
        -4 -F -f 1 -m 64 -q 3 -w 3 -z 100 -N 1 -- "$destination" 52
    difference=0
    diff -u "$prefix.system.log" "$prefix.own.log" >"$prefix.diff" || difference=$?
    [ "$difference" -le 1 ] || return "$difference"
    printf 'Logs y diferencias: %s.*\n' "$prefix"
}

run_comparisons() {
    index=0
    for destination do
        index=$((index + 1))
        compare_destination "$destination" "$index"
    done
}

check_environment
cd "$project_dir"
make all test
output_dir=$(mktemp -d "$project_dir/.build/network.XXXXXX")
if [ "$#" -eq 0 ]; then set -- 127.0.0.1 1.1.1.1; fi
run_comparisons "$@"
