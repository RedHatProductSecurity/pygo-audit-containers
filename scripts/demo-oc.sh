#!/usr/bin/env bash

set -Eeuo pipefail

readonly default_image="quay.io/prometheus/prometheus:latest"
readonly default_platform="linux/amd64"

usage() {
    printf 'Usage: %s [IMAGE [OS/ARCH]]\n' "$(basename "$0")"
    printf '\n'
    printf 'Extract IMAGE into sandbox/ with oc, then run pygo-audit.\n'
    printf 'Default IMAGE: %s\n' "$default_image"
    printf 'Default OS/ARCH: %s\n' "$default_platform"
}

case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
esac

if (( $# > 2 )); then
    usage >&2
    exit 2
fi

readonly image="${1:-$default_image}"
readonly platform="${2:-$default_platform}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd -- "$script_dir/.." && pwd)"
readonly repository_root
readonly sandbox_dir="$repository_root/sandbox"
readonly sandbox_gitignore="$sandbox_dir/.gitignore"
readonly expected_sandbox_gitignore="# This tracked file keeps sandbox/ present in fresh clones."
readonly auditor="$repository_root/pygo-audit"

for required_command in oc go; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
        printf 'error: required command not found: %s\n' "$required_command" >&2
        exit 1
    fi
done

if [[ ! -x "$auditor" ]]; then
    printf 'error: pygo-audit is not executable: %s\n' "$auditor" >&2
    exit 1
fi

mkdir -p -- "$sandbox_dir"

if [[ ! -e "$sandbox_gitignore" ]]; then
    printf 'warning: %s is missing; continuing without it.\n' \
        "$sandbox_gitignore" >&2
elif [[ ! -f "$sandbox_gitignore" || ! -r "$sandbox_gitignore" ]]; then
    printf 'warning: %s is not the expected readable file; keeping it in the audit scope.\n' \
        "$sandbox_gitignore" >&2
elif [[ "$(<"$sandbox_gitignore")" != "$expected_sandbox_gitignore" ]]; then
    printf 'warning: %s differs from the expected content; keeping it in the audit scope.\n' \
        "$sandbox_gitignore" >&2
fi

existing_path="$({
    find "$sandbox_dir" -mindepth 1 \
        ! -path "$sandbox_dir/.gitignore" -print -quit
} 2>/dev/null)"
if [[ -n "$existing_path" ]]; then
    printf 'error: sandbox already contains extracted files: %s\n' \
        "$existing_path" >&2
    printf 'Move or remove the existing root filesystem, then rerun this demo.\n' >&2
    exit 1
fi

printf 'Inspecting image: %s (%s)\n' "$image" "$platform"
oc image info --filter-by-os="$platform" "$image"

printf '\nExtracting image into: %s\n' "$sandbox_dir"
oc image extract "$image" \
    --filter-by-os="$platform" \
    --path="/:$sandbox_dir" \
    --confirm \
    --only-files

printf '\nAuditing extracted Go binaries...\n'
"$auditor" "$sandbox_dir"
