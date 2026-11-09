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
saves `audit.json` plus five human-readable views and the plain `cves.txt`,
`modules.txt`, and `packages.txt` lists under `service/reports/`. It includes layers
when present; use `--no-layers` to skip them. It never runs image-owned programs.
Repeat `scan` to refresh vulnerability findings. Previous JSON findings are
preserved as `history/audit-<ID>-<date>.json`.

## Several containers

```console
./scripts/gather-openshift-targets 4.20.21 --output targets.txt
./scripts/prepare-audits targets.txt run --dry-run
./scripts/prepare-audits targets.txt run --workers 4
./pygo-audit audit run --workers 4 --jobs 2 --timeout 180 --output-dir upload
```

Preparation consumes NAME IMAGE rows. Auditing consumes prepared child directories;
`--targets FILE` optionally selects directory names, one per line. Batch targets
share `run/cache/` and `run/work/`. `audit --output-dir upload` mirrors each
container's audit JSON and report files into `upload/<container>/`, leaving the
canonical audits and scan work in `run/`.

## Local CSAF comparison

```console
./pygo-audit report service --view cves |
  ./scripts/fetch-redhat-csaf --input-format cves - service/csaf
./pygo-audit csaf service

# Or use the saved lists from a completed batch.
cat run/*/reports/cves.txt |
  ./scripts/fetch-redhat-csaf --input-format cves - run/csaf
./pygo-audit csaf run --output-dir upload
./pygo-audit aggregate run --csaf run/csaf --output-dir upload
```

`upload/<container>/` contains each mirrored audit and scan report plus its
`comparison.json` and `comparison.txt`. Aggregation also writes `aggregate.txt`
for overall statistics, `cve-aggregates.txt` for each CVE across containers,
`container-aggregates.txt` for per-container results, `aggregate.json`, and
`pygo-audit-triage.csv` at the root of `upload/`. Open the CSV for one row per
container/CVE pair, sorted by descending highest CVSS score, then container,
agreement priority, and CVE. Both batch commands use the
single-container comparison, scoped to each
container's own recorded CVEs;
standalone `csaf service` checks every supplied document. Uncertain matches retain
their qualifications.
With `aggregate --output-dir RESULTS`, the aggregate files go to `RESULTS/` and
each container's comparison pair is also collected under `RESULTS/<container>/`.
The original child `reports/` outputs are refreshed as usual.
A saved audit reflects the vulnerability knowledge at scan time; comparing newer
advisories does not rescan binaries.

Optional `pygo-audit.json` files configure locations and settings, with explicit
CLI options taking precedence. Read the [CLI reference](cli-reference.md) for
layout, cache validity, settings, history, and exits, and the
[scripts reference](scripts-reference.md) for preparation and registry access.
