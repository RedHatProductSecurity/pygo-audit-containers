# pygo-audit-containers

`pygo-audit` scans an unpacked Linux container filesystem and reports the Go
modules embedded in each Go binary.

The scanner targets Python 3.14 and has no third-party runtime dependencies. It
does not execute anything from the container. Build metadata is read by the
host's `go version -m -json` command.

## Requirements

- Linux with `/proc` mounted (host only, for safe file inspection)
- Python 3.14 or newer
- A Go toolchain that supports `go version -m -json`
- An unpacked container root filesystem

The current development environment uses Python 3.14.7 and Go 1.26.8.

## Analyst quick start

Clone the repository and enter it:

```console
git clone <repository-url>
cd pygo-audit-containers
```

Use your preferred container tool to export or unpack one container root
filesystem into `sandbox/`. The directory must contain the unpacked filesystem
tree, not the image archive itself.

Then run the repository-local utility without installing anything:

```console
./pygo-audit
```

The `sandbox/` directory is the default scan root, is retained in Git, and
ignores all extracted contents. Use a clean `sandbox/` for each image so files
from different containers are not mixed.

For machine-readable output:

```console
./pygo-audit --format json
```

An explicit root directory still works:

```console
./pygo-audit /path/to/another/rootfs
```

### Example: OpenShift CLI (`oc`)

The demonstration script extracts the `linux/amd64` variant of a commonly
available Prometheus image into `sandbox/` and runs the audit. Pass another
image reference and optional `OS/ARCH` to override the defaults:

```console
./scripts/demo-oc.sh
./scripts/demo-oc.sh quay.io/example/project:tag
./scripts/demo-oc.sh quay.io/example/project:tag linux/arm64
```

For safety, the script refuses to mix an image with files already present in
`sandbox/`. Move or remove the previous extracted root filesystem before
running it again.

### Example: Podman

```console
container_id="$(podman create IMAGE)"
podman export "$container_id" | tar -C sandbox -xf -
podman rm "$container_id"
./pygo-audit
```

### Example: Docker

```console
container_id="$(docker create IMAGE)"
docker export "$container_id" | tar -C sandbox -xf -
docker rm "$container_id"
./pygo-audit
```

These are examples only; the scanner does not require or invoke either
container engine.

## Installation

Installation is optional. It provides a system or virtual-environment command
that can scan any unpacked root:

```console
python3 -m pip install .
pygo-audit /path/to/rootfs
```

Useful options:

```text
--go PATH           Go command to use (default: go on PATH)
--jobs COUNT        Maximum concurrent Go inspections (default: 4)
--timeout SECONDS   Per-binary Go inspection timeout (default: 30)
--strict            Exit nonzero if a non-fatal scan issue occurs
```

## How scanning works

The discovery path has three inexpensive filters:

1. Walk the root with `os.scandir`, without following symlinks.
2. Keep every regular file, regardless of its permissions, name, or extension.
3. Read four bytes and keep files beginning with the ELF magic `\x7fELF`.

Each ELF candidate is then passed to `go version -m -json`. Successful results
are Go binaries and are included in the report; other ELF files are ignored.

The file descriptor checked during discovery is reopened without following
symlinks and passed to Go through `/proc/self/fd`. This guards against a path
being replaced by a symlink between discovery and inspection. Hardlinks are
inspected once and all observed container paths are retained.

## Output

Text output shows the main package/module and dependency modules for each Go
binary, followed by a deduplicated dependency summary. JSON output uses schema
version 1 and includes build settings, module replacements, scan statistics,
and non-fatal issues.

Go build information contains modules that contributed packages to a binary.
It does not enumerate standard-library packages or unused requirements from the
source module's `go.mod`. Binaries without recognizable Go build metadata,
packed binaries, and binaries produced by unsupported toolchains cannot be
reported.

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
