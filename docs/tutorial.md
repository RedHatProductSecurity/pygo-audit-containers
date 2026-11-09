# Tutorial: from image bytes to an analyst-ready audit

This is the longer tour for two people who are often the same person: the
analyst who needs a defensible answer and the developer who needs to know
where that answer came from. The [CLI reference](cli-reference.md) covers
package commands; the [scripts reference](scripts-reference.md) covers product
input preparation and vendor retrieval.

## Chapter 1: choose the subject

An image reference is not yet a filesystem. First pin the platform and record
the image identity:

```console
IMAGE=quay.io/example/component:latest
PLATFORM=linux/amd64

oc image info "$IMAGE" --filter-by-os="$PLATFORM"
```

Do not scan a directory called `rootfs` merely because it has a charming name.
Know who created it, which platform it represents, and whether it is the
merged final filesystem or one historical layer.

## Chapter 2: use the extractor adapter

The default helper accepts a tag or digest reference, resolves the selected image once, and
uses the resolved digest throughout extraction. The sidecar records both the
original reference and the resolved digest.

```console
./scripts/extract-image-layers "$IMAGE" sandbox/example \
  --platform "$PLATFORM"
```

Its output is:

```text
sandbox/example/
├── .pygo-audit-image.json
├── layers/
│   ├── layer-000/
│   └── layer-001/
└── rootfs/
```

The sidecar is flat and mirrors scan options: image reference, digest,
platform, extractor, component identity, source Git URL, product version,
component version, product component, and CPE. It is provenance, not an
attestation. A sidecar can tell us what the extractor was told; it cannot make
an untrusted registry honest by force of JSON.

If your environment uses another tool, supply its unpacked filesystem directly
to `pygo-audit scan`, with optional image metadata beside the rootfs or selected
through `--image-metadata`. Batch auditing scans prepared child directories;
it never invokes extraction. Scripts prepare the workspace beforehand.

## Chapter 3: scan the final image

Start with the merged rootfs:

```console
./pygo-audit scan sandbox/example \
  --jobs 16 \
  --timeout 180
```

The scanner walks regular files, identifies ELF candidates, asks Go for build
metadata, and asks `govulncheck` for binary findings. It never runs the files
it discovers. It also streams each candidate once for its full SHA-256. Finding
evidence comes from govulncheck; when the Go tools do not specify reachability,
the report says `unspecified` rather than guessing from ELF bytes.

Read the reports in this order:

```console
./pygo-audit report sandbox/example/audit.json --view overview
./pygo-audit report sandbox/example/audit.json --view vulnerability-findings
./pygo-audit report sandbox/example/audit.json --view binary-findings
./pygo-audit report sandbox/example/audit.json --view module-reconciliation
./pygo-audit report sandbox/example/audit.json --view diagnostics

# Full per-binary dependencies, build settings, and finding details
./pygo-audit report sandbox/example/audit.json --view module-reconciliation -vv
```

Overview answers “how much did we scan?” The findings reports answer “what was
found?” from binary and vulnerability perspectives. Module reconciliation
compares scanner evidence with embedded build metadata. Use `-v` for expanded
identity, `-vv` for detailed evidence, and
`-vvv --wide` for exhaustive output. Diagnostics
answers “what should make me cautious?”

## Chapter 4: add layer history when the question needs it

Layer mode is useful when the question is not merely “what runs now?” but also
“what vulnerable Go binaries passed through this image?”:

```console
./pygo-audit scan sandbox/example \
  --layers-dir sandbox/example/layers \
  --output-dir sandbox/example/audit-with-history \
  --jobs 16
```

The final rootfs determines availability. A byte-identical layer copy and
rootfs copy share one binary result. Discovery sorts directory names
lexicographically; add `--layer-sort numeric` for embedded-number sorting.
Neither sort proves chronology, so discovered layer-only binaries remain
`unaccounted` rather than being called deleted or replaced.

If the actual oldest-to-newest image order is known, use repeated
`--layer-dir PATH` arguments instead. Their supplied order is preserved and
enables the fuller set of historical dispositions:

```text
runtime       final rootfs contains the binary
deleted       a whiteout explains its removal
replaced      another binary later occupies its path
unaccounted   it vanished from the supplied view without an explanation
unknown       the evidence was insufficient
```

The fourth state is not automatically a security bug. It means that final
rootfs absence is known, but its cause is not established by the supplied evidence.

## Chapter 5: scale to prepared directories

```console
./scripts/prepare-audits sandbox/product-audit-targets.txt sandbox/product-audit --dry-run
./scripts/prepare-audits sandbox/product-audit-targets.txt sandbox/product-audit
./pygo-audit audit sandbox/product-audit --workers 4 --jobs 2 --timeout 180
```

Preparation consumes NAME IMAGE inventory rows. The audit command scans existing
immediate child directories. `--workers` controls containers; `--jobs` controls
binary inspections inside each container. Targets share a visible cache and work
directory under the batch root. One run ID allows reuse of vulnerability analysis
across the batch, while each container's paths and runtime observations are rebuilt.

Repeat the audit command to refresh findings. Build information can be reused across
runs; vulnerability results are refreshed. Previous reports are retained in each
container's flat `history/` directory. No extraction or registry access occurs during
an audit; govulncheck may access its vulnerability database.

## Chapter 6: compare with CSAF VEX

Prepare local Red Hat documents using the vendor helper, then compare them
with the saved audit:

```console
./pygo-audit report sandbox/example --view cves |
  ./scripts/fetch-redhat-csaf --input-format cves - sandbox/csaf
./pygo-audit csaf sandbox/example --csaf sandbox/csaf
```

For an entire completed batch:

```console
cat sandbox/product-audit/*/reports/cves.txt |
  ./scripts/fetch-redhat-csaf --input-format cves - sandbox/csaf
./pygo-audit aggregate sandbox/product-audit --csaf sandbox/csaf --jobs 4
```

Retrieval and caching belong to the script. The single-image check examines
every supplied document for the image and compares applicable vendor statements
with saved local findings, keeping tentative and conflicting conclusions explicit.
Batch `csaf` and `aggregate` use that same comparison, scoped to each container's
own recorded CVEs. Aggregation refreshes child comparisons and writes separate
aggregate statistics, CVE summaries, container summaries, JSON, and
`reports/pygo-audit-triage.csv` for spreadsheet triage. These comparisons read local
files and work without network access. See the
[command reference](cli-reference.md) for file formats and directory contracts.

## Chapter 7: investigate without overclaiming

Use the [findings guide](findings-guide.md) as the decision tree. Start with
`pygo-audit-triage.csv`: the highest CVSS scores appear first, with qualified labels preserved.
Undetermined identifies missing documents or evidence that cannot support a
comparison; it does not mean agreement. Follow the detail report for the candidate's
identity, raw statements, qualifications, and the local binary evidence.

For example, vulnerable code plus a vendor declaration that it is unreachable can
be Qualified yes. A vendor fix claim plus an old embedded version can be Qualified
no because the version alone cannot disprove a backport. Mixed means accepted
candidates reach opposing conclusions. A binary from an earlier layer remains a
finding with its runtime availability recorded; an unaccounted disposition needs
review of the extraction evidence. The single-container and batch views apply
these same rules.
