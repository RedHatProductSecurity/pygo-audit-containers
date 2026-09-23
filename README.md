# pygo-audit-containers

`pygo-audit` scans an unpacked Linux container filesystem and reports the Go
modules and known vulnerabilities found in each Go binary.

See the [proof-of-concept scope](docs/proof-of-concept-scope.md) for the planned
analyst interface, report cache, and additional output formats.

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
./pygo-audit sandbox
```

The `sandbox/` directory is the default scan root, is retained in Git, and
ignores all extracted contents. Use a clean `sandbox/` for each image so files
from different containers are not mixed.

For machine-readable output:

```console
./pygo-audit sandbox --format json
```

An explicit root directory still works:

```console
./pygo-audit /path/to/another/rootfs
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

./pygo-audit sandbox
```

The scanner does not invoke `oc`; it only analyzes the filesystem placed in
`sandbox/`.

## Manual extraction with Podman

Given an existing container, unpack its root filesystem into `sandbox/` and run
the audit:

```console
CONTAINER=my-container

podman export "$CONTAINER" | tar -C sandbox -xf -

./pygo-audit sandbox
```

## Manual extraction with Docker

Given an existing container, unpack its root filesystem into `sandbox/` and run
the audit:

```console
CONTAINER=my-container

docker export "$CONTAINER" | tar -C sandbox -xf -

./pygo-audit sandbox
```

## Image extraction scope

The workflow above audits the final merged filesystem: files deleted or
superseded by later image layers are not present in `sandbox/`. Historical
layer contents are still distributed in the referenced image blobs, but
examining them is a separate, tool-dependent forensic workflow. Preserve layer
history with `docker image save`, `podman save`, an OCI layout produced by
Skopeo, or `oc image extract` layer selectors; `docker export` and
`podman export` produce a flattened container filesystem instead.

## Installation

Installation is optional. It provides a system or virtual-environment command
that can scan any unpacked root:

```console
python3 -m pip install .
pygo-audit /path/to/rootfs
```

Useful options:

```text
--format FORMAT       text, container, summary, or json (default: text)
--group-by GROUP      container, binary, package, or vulnerability
--check ID            Report a targeted CVE, GHSA, or GO ID (repeatable)
--go PATH             Go command to use (default: go on PATH)
--govulncheck PATH    govulncheck command to use (default: govulncheck on PATH)
--no-vulncheck        Skip vulnerability checks
--jobs COUNT          Maximum concurrent inspections (default: 4)
--timeout SECONDS     Per-command inspection timeout (default: 30)
--strict              Exit nonzero if an actionable scan issue occurs
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

Text output prints a compact package/version/vulnerability table for each Go
binary. Container output uses the same table but aggregates duplicate findings
across all Go binaries in the unpacked root. Both retain scan coverage, CGO,
and database provenance.

Each table prints one row for every package and vulnerability pair, along with
the current module version:

```console
./pygo-audit sandbox --format container
```

Summary output prints only the complete deduplicated lists of packages with
vulnerability findings and preferred vulnerability identifiers, except for
warnings when scan coverage is incomplete:

```console
./pygo-audit sandbox --format summary
```

Use `--group-by` for an evidence-rich view that retains binary paths and symbol
evidence, or repeat `--check` for an explicit result for each requested ID:

```console
./pygo-audit sandbox --group-by package
./pygo-audit sandbox --check CVE-2026-46595 --check CVE-2025-68121
```

A missing targeted finding is reported as such only when every recognized Go
binary completed vulnerability scanning. Otherwise its result is
`INDETERMINATE`. JSON accepts the same options and adds a machine-readable
`query` object while retaining the complete canonical audit.

The default compact human-readable formats omit dependencies, symbols,
references, and affected version ranges. JSON schema version 3 retains
scanner/database provenance, the minimal `govulncheck` SBOM, dependencies,
full affected-version and package information, fixed versions, evidence levels,
references, scan statistics, and non-fatal issues. It also reconciles the
effective `go version -m` module
inventory—including replacements and the standard library—with govulncheck's
SBOM and each vulnerability finding. Matches are classified as `exact`,
`replacement`, `stdlib`, or `unverifiable`; disagreements are retained as
`mismatch` results and scan issues rather than silently discarded. Equivalent
standard-library representations such as `go1.24.6` and `v1.24.6` are reported
as informational reconciliation differences and do not make coverage
incomplete or trigger `--strict`. Advisory summaries are deliberately omitted.
Incomplete-scan warnings remain visible so a partial audit is not presented as
clean.

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
