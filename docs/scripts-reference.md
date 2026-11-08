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
| `fetch-cve-data` | Download JSON for a CVE list; defaults to internal OSIDB | Access to the chosen source; the default requires Red Hat internal network/VPN access |

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
to `linux/amd64`; `--workers` controls concurrent extractions and defaults to the
logical CPUs available to the process, falling back to one if unknown. An explicit
`--workers N` overrides CPU detection. Failed extraction
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
directories have owner-only read/write/search permission (`0700`), allowing
the owner to remove an extracted workspace. File execute and write bits, and
setuid/setgid bits are removed. Image symlinks are
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

The generated image identity sidecar lives in the audit directory, outside
`rootfs/` and historical layers. An image-owned file with the same name is retained
as subject data; it is not overwritten or loaded as default metadata.

`.pygo-audit-image.json` contains the original reference, resolved digest,
platform, logical name, vendor image name, build release, component, product version, product component, source
repository, and available CPE evidence. It uses the fields documented under
[image identity inputs](cli-reference.md#optional-image-identity-sidecar).

The adapter translates provider metadata into those generic field names.
For example, an OpenShift image may supply `BUILD_VERSION`,
`OPENSHIFT_VERSION`, `io.openshift.build.source-location`, or
`io.openshift.maintainer.component`. These upstream names remain literal;
the generated image fields are `product_version`, `source_git_url`, and
`product_component`.
The `name` and `release` labels from `oc image info` are recorded separately as
`vendor_image_name` and `image_build_release`; they do not replace the inventory's
logical `name`.

The prettified JSON separates final `image` coordinates, observed layer `products`, and
user-supplied `csaf.product_ids` pins. Each product can carry multiple CPEs and
PURLs. Known buildinfo label files are read from every layer and the final rootfs;
duplicate observations retain all origins. Label observations matching the final
image's coordinates are attached to `image.sources`, avoiding a duplicate product
entry. Other contexts stay under `products`. The helper supplies literal CPEs;
PURL and product-ID lists start empty. The core may generate PURL lookup candidates
from the supplied names and labels those candidates in comparison output.

Vendor-specific label discovery stays in `scripts/container_metadata.py`.
The core consumes normalized identity records without opening these label files.
The helper skips unreadable, malformed, escaping, or over-1-MiB label files and
never executes container-owned commands.

The helper reads only `VERSION_ID`, `OPENSHIFT_VERSION`, and `CPE_NAME` from
`os-release` as fallbacks for missing component version, product version, and CPE.

Metadata reads require regular files contained inside the subject, with
directory components pinned against symlink replacement. Contained OS-release
links are accepted; escaping links, special files, and OS-release files larger
than 64 KiB are skipped.

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

Retrieval is optional and separate from comparison. Export the CVEs from one
audit and pipe them to the helper:

```console
set -o pipefail
./pygo-audit report run/service-1.2.3 --view cves |
  ./scripts/fetch-redhat-csaf --input-format cves - run/csaf
```

The input is a UTF-8 text file, or `-` for stdin, with one CVE per line.
`--input-format cves` is the default and the only supported format. Audit JSON
and audit directories are no longer inputs to this script. Blank lines and
surrounding whitespace are ignored; identifiers are uppercased, deduplicated,
and sorted. Invalid lines fail with a line number before any downloads or cache
writes. An empty list succeeds without creating a cache directory. `pipefail`
keeps an export failure visible in the pipeline's exit status.

Scans save the same list as `reports/cves.txt`. Use that file directly, or combine
lists from a completed batch; the helper deduplicates CVEs across containers:

```console
./scripts/fetch-redhat-csaf run/service-1.2.3/reports/cves.txt run/csaf
cat run/*/reports/cves.txt |
  ./scripts/fetch-redhat-csaf --input-format cves - run/csaf --jobs 8
```

For an existing audit without the saved list, use `report --view cves` to export
it without rescanning. The helper downloads only the supplied CVEs. It owns
Red Hat's VEX URL layout and writes `run/csaf/CVE-YYYY-NNNN.json` files. Those
files are both the reusable download cache and the explicit inputs to the
comparison command. No cache defaults to a home directory.

Existing documents are reused. `--refresh` fetches current documents, retaining
an earlier file if fetching fails. `--offline` checks existing files without
network access or cache writes. Per-document locks prevent duplicate downloads
when processes share a destination; atomic publication keeps partial JSON out
of the document collection. A failed or missing download is reported and gives
a nonzero exit status.

An HTTP 404 creates a `CVE-YYYY-NNNN.missing` cache marker containing the requested
URL, HTTP status, and UTC `checked_at` timestamp. Markers have no expiry: normal
runs report `cached missing (404; checked ...)` without another request.
`--refresh` checks again, updates the timestamp on another 404, and removes the
marker after a successful download. Other failures do not create missing markers.
`--offline` reads markers without changing them. Missing results still produce a
nonzero exit status and do not resolve the vulnerability. Markers are separate
from the `*.json` VEX documents used by the comparison command. If a refresh
returns 404 for a previously cached document, that document is retained, but the
downloader reports the newer missing observation until a successful refresh.

The helper uses eight concurrent workers by default; `--jobs N` changes that
limit. Results are printed and flushed as each CVE finishes, so a slow request
does not hide other completed downloads. Output order follows completion order.
Cache, lock, and write errors are reported for their CVE while the remaining
requests finish; the final exit status is nonzero if any CVE failed.

Network failures and HTTP 408, 429, 500, 502, 503, and 504 responses receive up to
four attempts, with 1-, 2-, and 4-second backoff. Each attempt retains the
60-second network timeout. `Retry-After` supports both seconds and HTTP dates;
the wait is at least the server's requested delay. A requested wait longer than
60 seconds reports a failure rather than retrying early. Invalid JSON, documents
without the requested CVE, other HTTP errors (including 404), and local file
errors are not retried. A failed refresh preserves the previous cached document.

Another provider's download tool can prepare ordinary CSAF files in the same
directory structure. The checker does not need the provider's URL convention.

## Download CVE data from a URL template

`fetch-cve-data` requires only a newline-separated CVE list. The destination
defaults to `cve-data/` in the working directory. Use `-` for standard input:

```console
./scripts/fetch-cve-data cves.txt
cat run/*/reports/cves.txt | ./scripts/fetch-cve-data - run/osidb
```

The default source is Red Hat's internal OSIDB flaw endpoint. Run it where that
service is accessible, such as through the appropriate VPN. Requests are ordinary
HTTP GETs. There are no format or authentication options; a failed request is
reported without switching sources or authentication methods.

For another JSON source, supply its URL template explicitly:

```console
./scripts/fetch-cve-data cves.txt run/vendor-data \
  --url-template 'https://advisories.example/flaws/{cve}'
```

Templates support `{cve}` (uppercase), `{cve_lower}`, and `{year}`. Downloaded
JSON is saved with two-space indentation as `CVE-YYYY-NNNN.json`. The helper
deduplicates the input and uses the same concurrency, cache, retry, `--refresh`,
`--offline`, and persistent 404 handling as `fetch-redhat-csaf` above. Each cache
records its URL template in `source.url`; a different template requires a
different destination. Offline checks create no files or locks.

The shared downloader lives in `pygo_audit.cve_data`; the scripts supply source
presets. `fetch-redhat-csaf` retains its CSAF/CVE validation and defaults its
destination to `csaf/`. Generic CVE data is stored as received and is not
converted into CSAF. Keep OSIDB records separate from CSAF inputs to `csaf`.

## Hand inputs to the CLI

```console
./pygo-audit scan service
./pygo-audit audit run
cat run/*/reports/cves.txt |
  ./scripts/fetch-redhat-csaf --input-format cves - run/csaf
./pygo-audit csaf run
./pygo-audit aggregate run --csaf run/csaf
```

Scanning writes reports directly in each container audit directory. Batch scanning
shares `BATCH_AUDIT_ROOT/cache/` and `work/`; preparation never needs to configure
those defaults individually. Optional `pygo-audit.json` sidecars describe custom
locations and settings. Aggregation refreshes each container's comparison and adds
`run/reports/aggregate.csv` for spreadsheet triage, alongside text and JSON.
Explicit CLI options win over sidecars. See the
[CLI reference](cli-reference.md) for precedence, history, and cache lifetimes.
