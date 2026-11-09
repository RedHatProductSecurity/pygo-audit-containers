# pygo-audit-containers

`pygo-audit` identifies Go binaries in prepared filesystems, reads embedded build
metadata, and runs `govulncheck` in binary mode for each distinct binary. It saves
current findings, preserves previous audits, and compares evidence with local
CSAF/VEX documents. It never executes subject binaries or invokes image extraction.

The library works with filesystems supplied by any extraction tool. Scripts own
registry inventory, image extraction, directory preparation, and provider URL
presets. `fetch-redhat-csaf` uses the shared `pygo_audit.cve_data` library for
download and cache operations.

## Documentation

- [CLI reference](docs/cli-reference.md) — package commands, input contracts,
  sidecar fields, saved evidence, local CSAF comparison, and output layouts.
- [Scripts reference](docs/scripts-reference.md) — product target discovery,
  image extraction, metadata preparation, and vendor CSAF retrieval.
- [Quickstart](docs/quickstart.md) — scan a rootfs, extract an image, run a
  batch, and compare findings with CSAF/VEX.
- [Architecture](docs/architecture.md) — boundaries, report hierarchy,
  layer composition, cache locality, and the fallibility principle.
- [Developer guide](docs/dev-guide.md) — inputs, dataclasses, processing,
  strict typing, trust boundaries, and tests.
- [Findings guide](docs/findings-guide.md) — interpret pygo/VEX agreements,
  mismatches, resolution differences, CGO limits, and follow-up work.
- [Tutorial](docs/tutorial.md) — a longer analyst/developer walkthrough.
- [Author's note](docs/authors-note.md) and [poetry shelf](docs/poems.md) —
  optional human commentary from the maintainer-shaped machine.

## Requirements and safety

- Linux with `/proc` mounted for safe file inspection;
- Python 3.14 or newer;
- a Go toolchain supporting `go version -m -json`;
- `govulncheck` on `PATH` for vulnerability analysis; and
- an unpacked filesystem, or an image tool that can produce one.

The Python runtime has no third-party dependencies. Install the Go vulnerability
tool if necessary:

```
go install golang.org/x/vuln/cmd/govulncheck@latest
```

By default, `govulncheck` consults `https://vuln.go.dev`. Use
`--no-vulncheck` when only build metadata is wanted.

Treat image archives, extracted files, metadata, and external tool output as
untrusted black-box data. Work as a non-root user in a disposable directory,
verify image digests and platforms, never execute files from the subject tree,
and keep network access explicit. Files examined SHOULD have the minimum
permissions needed by the scan account (PoLP). The supplied extractor makes
completed subject files `0400` and directories `0700`, without following image
symlinks. For stronger isolation, use a read-only mount. `pygo-audit scan`
does not alter subject permissions or execute subject binaries.

## One container

```console
./scripts/extract-image-layers IMAGE service --platform linux/amd64
./pygo-audit scan service --jobs 4 --timeout 180
./pygo-audit report service --view overview
./pygo-audit report service --view binary-findings -vv
```

Repeat `-v` up to three times for expanded, detailed, and forensic text;
`--wide` independently removes entry limits and hash abbreviations.

The extractor prepares `service/rootfs`, optional historical directories under
`service/layers/`, and metadata sidecars. Scanning always saves
`service/audit.json` and exhaustive text views under `service/reports/`, including
plain `cves.txt`, `modules.txt`, and `packages.txt` identifier lists.
Previous findings go to `service/history/audit-<ID>-<date>.json` on replacement.

`scan` defaults to the current audit directory, inspecting its `rootfs/` and
optional `layers/`. Use `--no-layers` for runtime-filesystem evidence only.
The final rootfs determines filesystem presence; layer discovery alone does not
establish chronology or deployed-process reachability.

## A prepared batch

```console
./scripts/gather-openshift-targets 4.20.21 --output targets.txt
./scripts/prepare-audits targets.txt run --dry-run
./scripts/prepare-audits targets.txt run
./pygo-audit audit run --workers 4 --jobs 2 --output-dir upload
```

`audit` scans immediate prepared child directories. An optional `--targets FILE`
selects existing directory names. Repeating the command refreshes scans without
extracting anything. The batch shares a visible `cache/` and `work/` under its root.
`--output-dir upload` also bundles each container's audit JSON and report views
under `upload/<container>/`; canonical audit data and scan work stay under `run/`.
Both `AUDIT_ROOT` and `BATCH_AUDIT_ROOT` default to the current working directory.

Optional `pygo-audit.json` settings use CLI option names. Explicit CLI values win
over container settings, batch settings, and defaults. Relative sidecar paths
are relative to their file. Caches never default to a home directory.

One binary cache retains static build facts and run-scoped vulnerability results.
Every new scan/batch refreshes vulnerability knowledge; paths and runtime/layer
observations are rebuilt for each container. Saved reports remain independent
of disposable caches.

## Local advisory comparison

```console
./pygo-audit report service --view cves |
  ./scripts/fetch-redhat-csaf --input-format cves - service/csaf
./pygo-audit csaf service

# Combine the saved CVE lists from a completed batch.
cat run/*/reports/cves.txt |
  ./scripts/fetch-redhat-csaf --input-format cves - run/csaf
./pygo-audit csaf run --output-dir upload
./pygo-audit aggregate run --csaf run/csaf --output-dir upload
```

The `cves`, `modules`, and `packages` report views emit sorted, unique identifiers,
one per line without headers or truncation. Modules and packages use `path@version`
(`@unknown` when unavailable); packages use their containing module's version.
Modules include recorded replacements. Packages include only paths recorded in
the audit, not a complete package inventory.

The CSAF check writes `comparison.json` and `comparison.txt` under each audit's
`reports/` directory. For one container it checks every supplied document and reports
component PURL/product CPE matches, unconfirmed candidates, and linked platform
evidence. Each CVE also links to recorded binary artifacts and their locations.
The summary shows the independent local scan result (Affected, Not Affected, or
Undetermined), match confidence, agreement with vendor qualifications, and the
discovered CSAF product ID candidates for each CVE.
Local findings list unique binaries, runtime availability, and evidence kinds by
default. Reachability, locations, and modules expand inside that section at `-v`,
packages and CGO at `-vv`, and exact symbols at `-vvv`. Exact matches discard weaker
candidates. Individual candidates report
Yes, Qualified yes, No, Qualified no, or Undetermined; the overall CVE result can
also report Mixed when accepted candidates reach opposing conclusions.
Batch `csaf` and `aggregate` use the same matching, conclusions, and detail layout,
limited to each container's recorded CVEs. Aggregation refreshes those per-container
reports and writes `aggregate.txt`, `cve-aggregates.txt`, `container-aggregates.txt`,
`aggregate.json`, and `pygo-audit-triage.csv` under the batch `reports/` directory.
The spreadsheet has one row per container/CVE pair,
sorted by descending highest CVSS score, then container, agreement priority, and
CVE, with canonical advisory URLs and recorded image references. Neither command
downloads advisories or rescans binaries.

## Installation and checks

```console
python3 -m pip install .
PYTHONPATH=src python3 -B -m unittest discover -s tests
ruff check scripts src tests
python3 -m compileall -q scripts src tests
git diff --check
```

The tests use the standard library. Scanner integration tests build a local Go
fixture and fake the vulnerability tool; they need no network access. Go binary
analysis does not provide complete CGO/native-library coverage. See the
[findings guide](docs/findings-guide.md) for evidence and interpretation limits.
