# Scripts reference

The tools in `scripts/` prepare product inputs for `pygo-audit`: image
inventories, extracted filesystems, metadata, and local CSAF documents.

Business in the `scripts/`, party in the `src/`: Container identity, unpacking,
CSAF assembly, and retrieval tools in the scripts/ directory use a mix of oc
and skopeo. The CSAF analysis tool provided gathers Red Hat CSAF 2.0 formatted VEX
files, but, by design, pygo-audit only requires python, go, and govulncheck.

Use the [CLI reference](cli-reference.md) for scanning, batch auditing,
reporting, comparison, and aggregation.

## Tools and requirements

Run these helpers from a source checkout with Python 3.14 or newer. They use
Python's standard library and the local `pygo_audit` package.
`extract-image-layers` requires Linux with `/proc` mounted for its
descriptor-based permission changes, matching the scanner's host requirements.

| Helper | Purpose | Additional requirements |
| --- | --- | --- |
| `gather-openshift-targets` | Generate an image inventory from an OpenShift release payload | `oc` |
| `prepare-audits` | Prepare child audit directories from a NAME IMAGE inventory | The extraction helper below |
| `extract-image-layers` | Prepare a rootfs, ordered layers, and product metadata | Skopeo, `oc`, `tar`; optional host `rpm` for package facts |
| `fetch-redhat-csaf` | Retrieve Red Hat VEX documents for observed CVEs | HTTPS access, unless checking existing files with `--offline` |

Each helper supports `--help`. Paths are relative to the working directory
unless absolute paths are supplied. None of these helpers scans a deployed
cluster's running processes.

## Gather an OpenShift target list

`gather-openshift-targets` reads an OpenShift release payload and emits logical
container names with registry image references. It uses
`oc adm release info` to inspect the payload.

For example, prepare an OpenShift inventory:

```console
./scripts/gather-openshift-targets 4.20.21 --output openshift-targets.txt
```

The positional argument accepts a release version or release image reference.
Without `--output`, the inventory is printed to stdout. Each logical name
includes the version reported by the payload. Names are padded to the longest
name so every image reference begins in the same column:

```text
component-4.20.21    registry.example/product/component@sha256:...
```

The digest above is abbreviated for illustration. Release payloads generally
supply complete digest references. Other inventories may use tags or untagged
repository references; `pygo-audit` records the resolved digest during
extraction. The preparation script accepts two whitespace-separated columns,
blank lines, and `#` comment lines, with any filename or extension.

## Prepare a batch workspace

```console
./scripts/prepare-audits openshift-targets.txt run --dry-run
./scripts/prepare-audits openshift-targets.txt run --workers 4
./pygo-audit audit run --workers 4 --jobs 2
```

`prepare-audits TARGETS [BATCH_AUDIT_ROOT]` owns image extraction and directory
preparation. The root defaults to the current directory. Inventory rows contain
exactly two whitespace-separated fields, NAME and IMAGE; blank lines and `#`
comments are allowed. Names start with an ASCII letter/digit and contain only
letters, digits, dots, underscores, or hyphens. Names and image references must
be unique. Other inventory providers can write this same format.

Each logical name becomes an immediate child audit directory. No numbering is
required. `--dry-run` validates the inventory and lists destinations without
writes or registry access. Existing destinations are rejected before extraction;
use a fresh workspace when extracting new image contents. `--platform` defaults
to `linux/amd64`; `--workers` controls concurrent extractions. Failed extraction
output remains available for inspection.

After preparation, `pygo-audit audit` finds these child directories automatically.
Its optional `--targets` file is a different input: one existing child directory
name per line, selecting a subset to scan. It contains no registry references.
See the [CLI reference](cli-reference.md#batch-workspaces).

## Extract an image

```console
./scripts/extract-image-layers registry.example/team/service:1.2.3 service \
  --platform linux/amd64
```

The positional arguments are the image reference and a new destination
directory. Its parent must already exist. Existing destinations are rejected
before registry access. The optional `--platform` selects
`OS/ARCH[/VARIANT]` and defaults to `linux/amd64`. The destination basename is
the logical image name recorded in the generated sidecar.

The helper resolves the selected image once, then uses its resolved digest for
layer transport and rootfs extraction. The original reference and resolved
digest are recorded separately. If resolution fails, extraction stops before
creating the destination.

```text
service/
├── .pygo-audit-image.json
├── .pygo-audit-container.json
├── layers/
│   ├── layer-000/
│   └── layer-001/
└── rootfs/
    └── ...final filesystem files...
```

Skopeo transports the image, `oc` produces the merged rootfs and image
metadata, and `tar` unpacks historical layers. Layer archives are checked
for traversal and unsupported special files before unpacking. Ordinary
container symlinks are retained without executing their targets.

Completed regular files have owner-only read permission (`0400`); subject
directories have owner-only read/search permission (`0500`). File execute
bits, write access, and setuid/setgid bits are removed. Image symlinks are
preserved without following them or changing their targets' permissions.
Generated sidecars and reports remain writable outside these trees. These
permissions are not an immutable boundary: the owner can change them again,
so a read-only mount remains preferable for stronger isolation.

Registry authentication belongs to those host tools. Configure their registry
credentials before invoking the helper; private-registry examples in this
project use `REGISTRY_AUTH_FILE`. Do not place credentials in the subject
filesystem or generated audit reports.

Extraction staging is private, lives inside the destination, and is removed
when its context ends. A failed extraction retains partial output for review.
Choose a new destination after inspecting an interrupted or failed run.

`prepare-audits` invokes the sibling `extract-image-layers` helper. The package
CLI never invokes extraction. Other tools can prepare `rootfs/`, optional
`layers/`, and sidecars in the same directory contract without changing the scanner.

### Product metadata

Both generated sidecars live in the audit directory, outside `rootfs/`
and historical layers. Image-owned files with those names are retained as
subject data; they are not overwritten or loaded as default metadata.

`.pygo-audit-image.json` contains the original reference, resolved digest,
platform, logical name, component, product version, product component, source
repository, and available CPE evidence. It uses the fields documented under
[image identity inputs](cli-reference.md#optional-image-identity-sidecar).

The adapter translates provider metadata into those generic field names.
For example, an OpenShift image may supply `BUILD_VERSION`,
`OPENSHIFT_VERSION`, `io.openshift.build.source-location`, or
`io.openshift.maintainer.component`. These upstream names remain literal;
the generated fields are `product-version`, `source-git-url`, and
`product-component`.

`.pygo-audit-container.json` holds facts read from the extracted filesystem:
OS release values, RPM database locations, and package coordinates. The host
`rpm` command queries a private working copy of the database's regular files
in a temporary `rpm-query-*` directory beside `rootfs/`. Query-created locks
and journals never touch the extracted database. The working copy is removed
after success, failure, or timeout; RPM queries have a 30-second timeout.
No image-owned commands are executed. Missing, unusable, or timed-out RPM
tooling is recorded as a limitation rather than making extraction fail.

Metadata reads require regular files contained inside the subject, with
directory components pinned against symlink replacement. Contained OS-release
links are accepted; escaping links, special files, and OS-release files larger
than 64 KiB are skipped. RPM database files themselves must not be symlinks.
These filesystem facts remain separate from registry identity and are not yet
incorporated into the main report model.

### Layer directories and temporary manifests

Skopeo writes `manifest.json` only in the private transport staging directory.
The extractor reads its ordered layer descriptors to locate the downloaded
blobs, then unpacks them into `layers/layer-000/`, `layers/layer-001/`, and so
on. Staging, including the manifest, is removed when extraction ends. No
registry manifest or layer-list file is retained in the completed audit directory.

The numbered names are this helper's choice, not a scanner requirement.
Other extractors may use arbitrary directory names under `layers/`. Both `scan` and batch `audit` include an existing `layers/` directory automatically
and scan its children in lexicographic order by default;
`--layer-sort numeric` compares embedded numbers as integers. Sorting does
not establish image chronology: these scans record layer presence and final
rootfs availability, without inferring deletion or replacement.

When the actual image order is known, repeated `scan --layer-dir PATH`
arguments preserve that explicit oldest-to-newest order and enable historical
inference. `scan --layers-dir PATH` accepts any layer parent for discovery.
See the [CLI reference](cli-reference.md#layers-and-context).

## Retrieve Red Hat CSAF documents

Retrieval is optional and separate from comparison. To prepare documents for
one audit or every completed target in a numbered batch:

```console
./scripts/fetch-redhat-csaf run/service-1.2.3 run/csaf
./scripts/fetch-redhat-csaf run run/csaf --jobs 8
```

The helper downloads only CVEs observed in the supplied evidence. It owns
Red Hat's VEX URL layout and writes `run/csaf/CVE-YYYY-NNNN.json` files. Those
files are both the reusable download cache and the explicit inputs to the
comparison command. No cache defaults to a home directory.

Existing documents are reused. `--refresh` fetches current documents, retaining
an earlier file if fetching fails. `--offline` checks existing files without
network access or cache writes. Per-document locks prevent duplicate downloads
when processes share a destination; atomic publication keeps partial JSON out
of the document collection. A failed or missing download is reported and gives
a nonzero exit status.

Another provider's download tool can prepare ordinary CSAF files in the same
directory structure. The checker does not need the provider's URL convention.

## Hand inputs to the CLI

```console
./pygo-audit scan service
./pygo-audit audit run
./scripts/fetch-redhat-csaf run run/csaf
./pygo-audit csaf run
./pygo-audit aggregate run --csaf run/csaf
```

Scanning writes reports directly in each container audit directory. Batch scanning
shares `BATCH_AUDIT_ROOT/cache/` and `work/`; preparation never needs to configure
those defaults individually. Optional `pygo-audit.json` sidecars describe custom
locations and settings. Explicit CLI options win over sidecars. See the
[CLI reference](cli-reference.md) for precedence, history, and cache lifetimes.
