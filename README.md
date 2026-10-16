# pygo-audit-containers

`pygo-audit` scans an unpacked Linux container filesystem and reports the Go
modules and known vulnerabilities found in each Go binary.

Project guides:

- [Proof-of-concept scope](docs/proof-of-concept-scope.md)
- [First demonstration outline](docs/first-demonstration.md)
- [Demonstration cheatsheet](docs/demonstration-cheatsheet.md)
- [AI persona audit experiment (`persona-exercise` branch)](https://github.com/RedHatProductSecurity/pygo-audit-containers/tree/persona-exercise/persona-exercise)

The scanner targets Python 3.14 and has no third-party runtime dependencies. It
does not execute anything from the container. Build metadata is read by the
host's `go version -m -json` command, and vulnerability information is produced
by the host's `govulncheck` command.

## Requirements

- Linux with `/proc` mounted (host only, for safe file inspection)
- Python 3.14 or newer
- A Go toolchain that supports `go version -m -json`
- `govulncheck` on `PATH`
- An unpacked container root filesystem

Install `govulncheck` with the Go toolchain if it is not already available:

```console
go install golang.org/x/vuln/cmd/govulncheck@latest
```

By default, `govulncheck` queries `https://vuln.go.dev`. Use
`--no-vulncheck` when only an offline build-information report is wanted.

The current development environment uses Python 3.14.7 and Go 1.26.8.

## Analyst quick start

Clone the repository and enter it:

```console
git clone <repository-url>
cd pygo-audit-containers
```

The workflow has two steps:

1. Use your preferred container tool to unpack one container root filesystem
   directly into `sandbox/`. The result should look like a Linux filesystem—for
   example, `sandbox/bin/` and `sandbox/etc/`—not an image archive or a directory
   of image layers.
2. Run the repository-local utility against `sandbox/` without installing it:

```console
./pygo-audit scan sandbox
```

The `sandbox/` directory is the default scan root, is retained in Git, and
ignores all extracted contents. Use a clean `sandbox/` for each image so files
from different containers are not mixed.

To retain a portable audit bundle from the scan:

```console
./pygo-audit scan sandbox --output-dir audit-artifacts/demo
```

Render its complete machine-readable snapshot without rescanning:

```console
./pygo-audit report json audit-artifacts/demo/audit.json
```

An explicit root directory still works:

```console
./pygo-audit scan /path/to/another/rootfs
```

## Demonstration script

The demonstration script performs both workflow steps: it extracts the
`linux/amd64` variant of a commonly available Prometheus image into `sandbox/`,
then runs `pygo-audit` against that directory. Pass another image reference and
optional `OS/ARCH` to override the defaults:

```console
./scripts/demo-oc.sh
./scripts/demo-oc.sh quay.io/example/project:tag
./scripts/demo-oc.sh quay.io/example/project:tag linux/arm64
```

For safety, the script refuses to mix an image with files already present in
`sandbox/`. Move or remove the previous extracted root filesystem before
running it again.

For a structured presentation that preserves one scan and demonstrates every
report without rerunning `govulncheck`, follow the
[first demonstration outline](docs/first-demonstration.md).

## Manual extraction with `oc`

From the repository root, choose an image and platform, unpack its root
filesystem into `sandbox/`, and run the audit:

```console
IMAGE=quay.io/prometheus/prometheus:latest
PLATFORM=linux/amd64

oc image info --filter-by-os="$PLATFORM" "$IMAGE"
oc image extract "$IMAGE" \
    --filter-by-os="$PLATFORM" \
    --path='/:sandbox' \
    --confirm \
    --only-files

./pygo-audit scan sandbox
```

The scanner does not invoke `oc`; it only analyzes the filesystem placed in
`sandbox/`.

## Manual extraction with Podman

Given an existing container, unpack its root filesystem into `sandbox/` and run
the audit:

```console
CONTAINER=my-container

podman export "$CONTAINER" | tar -C sandbox -xf -

./pygo-audit scan sandbox
```

## Manual extraction with Docker

Given an existing container, unpack its root filesystem into `sandbox/` and run
the audit:

```console
CONTAINER=my-container

docker export "$CONTAINER" | tar -C sandbox -xf -

./pygo-audit scan sandbox
```

## Image extraction scope

The workflow above audits the final merged filesystem: files deleted or
superseded by later image layers are not present in `sandbox/`. Historical
layer contents are still distributed in the referenced image blobs, but
examining them is a separate, tool-dependent forensic workflow. Preserve layer
history with `docker image save`, `podman save`, an OCI layout produced by
Skopeo, or `oc image extract` layer selectors; `docker export` and
`podman export` produce a flattened container filesystem instead.

### Extract every layer separately

The standalone helper discovers the layer count, resolves the image to an
immutable digest, and extracts each layer into its own directory:

```console
./scripts/extract-image-layers IMAGE NEW_DIRECTORY --platform linux/amd64
```

It requires `oc` and Python 3, with no additional Python packages. The output
contains `image-info.json` and directories named `layer-000`, `layer-001`, and
so on, in the metadata's layer order. Existing destinations are refused. A
failure stops extraction and retains partial output for inspection.

To make it available as a command in your active virtual environment:

```console
install -m 755 scripts/extract-image-layers "${VIRTUAL_ENV:?Activate your virtual environment first}/bin/extract-image-layers"
extract-image-layers IMAGE NEW_DIRECTORY
```

Each directory contains one layer's changes, including files later replaced
or deleted by another layer. Scan layer directories separately and identify
findings as layer findings; they do not establish that a binary survives in
the final filesystem. `oc` applies deletion markers while extracting, so
retain an image archive separately if the original archives and markers are
needed. The scanner itself remains independent of image extraction.

## Installation

Installation is optional. It provides a system or virtual-environment command
that can scan any unpacked root:

```console
python3 -m pip install .
pygo-audit scan /path/to/rootfs
```

The primary subcommands are:

```text
scan ROOT                    Scan an unpacked rootfs and print its overview
report overview SNAPSHOT     Show result, coverage, packages, and vulnerabilities
report findings SNAPSHOT     Show container findings and supporting evidence
report binaries SNAPSHOT     Show per-binary findings and dependencies
report diagnostics SNAPSHOT  Show scan issues and reconciliation details
report json SNAPSHOT         Show the complete machine-readable snapshot
check SNAPSHOT ID [ID ...]   Show only the requested vulnerability results
```

Useful scan options:

```text
--go PATH             Go command to use (default: go on PATH)
--govulncheck PATH    govulncheck command to use (default: govulncheck on PATH)
--no-vulncheck        Skip vulnerability checks
--jobs COUNT          Maximum concurrent inspections (default: 4)
--timeout SECONDS     Per-command inspection timeout (default: 30)
--strict              Exit nonzero if an actionable scan issue occurs
--snapshot-dir PATH   Content-addressed store for immutable scan snapshots
--output-dir PATH     Write audit.json and all current rendered reports
--image-metadata PATH JSON sidecar containing explicit image identity
--image-ref REFERENCE Original image reference
--image-digest DIGEST Resolved OCI manifest digest
--platform OS/ARCH    Selected image platform
--extractor TOOL      Tool used to produce the unpacked root
```

## How scanning works

The discovery path has three inexpensive filters:

1. Walk the root with `os.scandir`, without following symlinks.
2. Keep every regular file, regardless of its permissions, name, or extension.
3. Read four bytes and keep files beginning with the ELF magic `\x7fELF`.

Each ELF candidate is then passed to `go version -m -json`. Successful results
are Go binaries and are included in the report; other ELF files are ignored.
Confirmed Go binaries are passed to `govulncheck -mode binary -format json`.
The resulting OSV advisories and findings are correlated so advisories without
findings are not incorrectly reported as vulnerabilities.

The file descriptor checked during discovery is reopened without following
symlinks and passed to Go through `/proc/self/fd`. This guards against a path
being replaced by a symlink between discovery and inspection. Hardlinks are
inspected once and all observed container paths are retained.

## Output

Human-readable output uses narrow, labeled sections rather than wide tables so
long container paths and module names remain readable in a terminal. Values
that must be shortened keep their useful end and begin with `...`; JSON always
retains the full value.

The binary report includes CGO status, vulnerability findings, and the declared
dependency path, version, checksum, and replacement data preserved from
`go version -m`:

```console
./pygo-audit report binaries audit-artifacts/demo/audit.json
```

The findings report aggregates affected packages across all Go binaries:

```console
./pygo-audit report findings audit-artifacts/demo/audit.json
```

Operational scan issues, unverifiable components, and informational differences
between `go version -m` and `govulncheck` are kept in a dedicated diagnostics
view:

```console
./pygo-audit report diagnostics audit-artifacts/demo/audit.json
```

Primary reports show concise diagnostic counts only when issues or differences
exist. Coverage warnings remain prominent because incomplete binary scans can
hide vulnerability findings.

The overview prints complete deduplicated lists of packages and preferred
vulnerability identifiers. Use `--group-by` with the findings view for a
different evidence organization:

```console
./pygo-audit report overview audit-artifacts/demo/audit.json
./pygo-audit report findings audit-artifacts/demo/audit.json --group-by package
```

The check subcommand prints only the requested vulnerability results. Each
identifier is its result header, followed by status, coverage, affected
packages, and binary paths; compact snapshot and database provenance follows
under `SCAN CONTEXT`:

```console
./pygo-audit check audit-artifacts/demo/audit.json \
  CVE-2026-46595 CVE-2025-68121
```

A missing targeted finding is reported as `NOT DETECTED IN THIS SNAPSHOT` only
when every recognized Go binary completed vulnerability scanning. Otherwise
its result is `INDETERMINATE`.

The human-readable formats omit symbol names, references, fixed versions, and
affected version ranges. The canonical JSON retains scanner/database
provenance, the minimal `govulncheck` SBOM, dependencies,
full affected-version and package information, fixed versions, evidence levels,
references, scan timestamps, per-binary SHA-256 digests, scan statistics, and
non-fatal issues. It also reconciles the effective `go version -m` module
inventory—including replacements and the standard library—with govulncheck's
SBOM and each vulnerability finding. Matches are classified as `exact`,
`replacement`, `stdlib`, or `unverifiable`; disagreements are retained as
`mismatch` results and scan issues rather than silently discarded. All
differences between `go version -m` and `govulncheck`—including equivalent
standard-library representations such as `go1.24.6` and `v1.24.6`—are surfaced
as informational reconciliation differences. They do not make coverage
incomplete, raise an error, or trigger `--strict`. Advisory summaries are
deliberately omitted. Incomplete-scan warnings remain visible so a partial
audit is not presented as clean.

Reconciliation also reports unverifiable components, such as local module
replacements recorded with a `(devel)` version. These make reconciliation
partial without making vulnerability coverage incomplete. Diagnostics groups
each unique limitation across its affected binaries.

### Snapshots and generated artifacts

Write an immutable, content-addressed development snapshot while scanning:

```console
./pygo-audit scan sandbox --snapshot-dir audit-snapshots
```

Snapshots are named by a SHA-256 digest of their JSON content. The content
includes scan timestamps, binary hashes, the `pygo-audit`, Go, and
`govulncheck` versions, plus every vulnerability database URL and last-modified
time observed during the scan. Consequently, a new scan or changed provenance
produces a distinct snapshot; the snapshot digest is not a database digest.
When a snapshot filename is a SHA-256 content address, every read automatically
recomputes and validates that address. Portable `audit.json` files retain a
recomputed snapshot identity but have no digest-bearing filename to compare.

Generate the current portable artifact bundle from the same in-memory scan:

```console
./pygo-audit scan sandbox \
  --snapshot-dir audit-snapshots \
  --output-dir audit-artifacts/demo
```

The scan output directory contains:

```text
audit.json       Complete scan snapshot
overview.txt     Result, coverage, package list, and vulnerability list
findings.txt     Container-level findings organized by affected package
binaries.txt     Per-binary findings and declared dependency inventory
diagnostics.txt  Operational issues, reconciliation limitations, and differences
```

Running `check --output-dir` adds `checks/ID.txt` for each requested identifier;
it does not regenerate the five base artifacts.

The JSON file is the complete snapshot IR; every text file is a derived view.
Existing identical artifacts are reused, which permits adding saved checks to
an existing bundle. Differing generated content is never overwritten. No
renderer reruns `go` or `govulncheck`.

Rerender a stored snapshot or portable `audit.json` without rescanning:

```console
./pygo-audit report overview audit-snapshots/DIGEST.json
./pygo-audit report findings audit-snapshots/DIGEST.json --group-by package
./pygo-audit report binaries audit-artifacts/demo/audit.json
./pygo-audit report diagnostics audit-artifacts/demo/audit.json
```

Persist focused checks without regenerating the base reports:

```console
./pygo-audit check audit-artifacts/demo/audit.json \
  CVE-2026-46595 CVE-2025-68121 \
  --output-dir audit-artifacts/demo
```

A snapshot directory may be supplied directly when it contains exactly one
JSON snapshot. When it contains multiple snapshots, select the desired file.
Snapshot reads never refresh findings against the current vulnerability
database. Snapshot JSON uses the current canonical report structure.

### Image identity

An extracted root filesystem has no standardized record of its originating OCI
manifest. Supply identity explicitly when it is known:

```console
./pygo-audit scan sandbox \
  --image-ref registry.example.test/team/app:v1 \
  --image-digest sha256:MANIFEST_DIGEST \
  --platform linux/amd64 \
  --extractor "oc image extract"
```

The same values can be placed in `sandbox/.pygo-audit-image.json`; command-line
values override sidecar values:

```json
{
  "reference": "registry.example.test/team/app:v1",
  "digest": "sha256:MANIFEST_DIGEST",
  "platform": "linux/amd64",
  "extractor": "oc image extract"
}
```

`pygo-audit` retains this metadata in snapshots and rendered reports but never
infers a digest from extracted files.

Go build information contains modules that contributed packages to a binary.
It does not enumerate standard-library packages or unused requirements from the
source module's `go.mod`. Binaries without recognizable Go build metadata,
packed binaries, and binaries produced by unsupported toolchains cannot be
reported.

Binary-mode vulnerability evidence means that a vulnerable module, package, or
symbol was identified in the compiled binary. It does not prove that a symbol
is reachable or exploitable because compiled binaries do not contain the call
graph needed for source-level analysis. If symbol information is unavailable,
`govulncheck` can fall back to broader module-level findings. A failed or timed
out vulnerability check is reported as incomplete, never as a clean result.

## AI-assisted evaluation

The repository includes a reusable, evidence-constrained experiment for
evaluating how security, Go engineering, and assurance personas interpret the
same pygo-audit snapshots. The complete framework and first experiment's
generated snapshots, messages, analyses, targeted checks, and tutorials are on
the separate `persona-exercise` branch. See the
[experiment guide](https://github.com/RedHatProductSecurity/pygo-audit-containers/tree/persona-exercise/persona-exercise)
for its evidence boundaries and layout.

## Tests

The test suite uses only the Python standard library. Integration tests compile
a small local Go module and do not access the network.

```console
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Attribution

This project was created by [Codex](https://developers.openai.com/codex/),
OpenAI's AI coding agent, using the
[GPT-5.6 Sol](https://developers.openai.com/api/docs/models/gpt-5.6-sol)
model snapshot (`gpt-5.6-sol`), with direction from Daniel Ojalvo.

## ROBOT POEM

```text
In sandbox roots where quiet layers lie,
Four magic bytes wake under an ELF sky.
Go leaves its modules etched in binary light,
While oc unfolds each image into sight.

No borrowed package steers the Python way;
We scan each file and hear what builds can say.
Daniel gives direction; Codex charts the view—
“Engage,” and hidden dependencies shine through.
```
