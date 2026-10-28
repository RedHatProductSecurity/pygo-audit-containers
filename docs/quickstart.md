# Quickstart

The host needs Linux with `/proc`, Python 3.14+, a Go toolchain supporting
`go version -m -json`, and `govulncheck`. The package has no third-party Python
runtime dependencies. See [requirements](../README.md#requirements-and-safety).

## One prepared container

An audit directory contains `rootfs/`, optional `layers/layer-000/`,
`layers/layer-001/`, etc., and optional metadata sidecars beside those subjects.
Use any extractor, or the supplied helper:

```console
./scripts/extract-image-layers IMAGE service --platform linux/amd64
./pygo-audit scan service --timeout 180
./pygo-audit report service --view overview
./pygo-audit report service --view binary-findings -vv
./pygo-audit check service --id CVE-2026-0001
```

The scanner runs binary-mode govulncheck on each distinct Go binary and always
saves `audit.json` plus five text views under `service/reports/`. It includes layers
when present; use `--no-layers` to skip them. It never runs image-owned programs.
Repeat `scan` to refresh vulnerability findings. Previous JSON findings are
preserved as `history/audit-<ID>-<date>.json`.

## Several containers

```console
./scripts/gather-openshift-targets 4.20.21 --output targets.txt
./scripts/prepare-audits targets.txt run --dry-run
./scripts/prepare-audits targets.txt run --workers 4
./pygo-audit audit run --workers 4 --jobs 2 --timeout 180
```

Preparation consumes NAME IMAGE rows. Auditing consumes prepared child directories;
`--targets FILE` optionally selects directory names, one per line. Batch targets
share `run/cache/` and `run/work/`. Both workspace arguments default to cwd.

## Local CSAF comparison

```console
./scripts/fetch-redhat-csaf run run/csaf
./pygo-audit csaf run
./pygo-audit aggregate run --csaf run/csaf
```

Each container receives `reports/comparison.json` and `reports/comparison.txt`;
`reports/aggregate.txt` and `reports/aggregate.json` are written in `run/`.
Missing documents and uncertain
matches must be reviewed.
A saved audit reflects the vulnerability knowledge at scan time; comparing newer
advisories does not rescan binaries.

Optional `pygo-audit.json` files configure locations and settings, with explicit
CLI options taking precedence. Read the [CLI reference](cli-reference.md) for
layout, cache validity, settings, history, and exits, and the
[scripts reference](scripts-reference.md) for preparation and registry access.
