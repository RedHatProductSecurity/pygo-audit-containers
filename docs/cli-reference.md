# pygo-audit CLI reference

`pygo-audit` examines prepared container filesystems, always saves scan evidence,
and checks image identities against local CSAF documents. Image extraction,
inventory discovery, directory preparation, and provider URL presets belong to
[scripts](scripts-reference.md). The scanner never invokes an extractor.

> [!WARNING]
> **BLACK-BOX INPUT:** Extractors feeding `pygo-audit` SHOULD make all extracted
> content read-only by default and grant only the audit process's minimum
> file-read and directory read/search permissions. Do not analyze untrusted
> containers unless you know what you are doing.

## Commands

| Command | Input and default | Result |
| --- | --- | --- |
| `scan [AUDIT_ROOT]` | One prepared container directory; defaults to cwd | Current audit, text views, previous audit history |
| `report [AUDIT_ROOT] [--view VIEW]` | Current workspace or an explicit audit JSON | A view of saved evidence |
| `audit [BATCH_AUDIT_ROOT]` | Parent of prepared container directories; defaults to cwd | Per-container audits, optional report bundle, progress and summary |
| `aggregate [BATCH_AUDIT_ROOT] [--view VIEW]` | Parent of container audits; defaults to cwd | Shared comparisons and triage CSV, or a deduplicated identifier list |
| `check [AUDIT_ROOT] --id ID...` | CVE, GHSA, or GO identifiers; defaults to cwd | Targeted findings |
| `csaf [AUDIT_ROOT]` | A container or batch workspace; defaults to cwd | Saved JSON/text comparisons with local documents |

`report` views are `overview`, `binary-findings`, `vulnerability-findings`,
`module-reconciliation`, `diagnostics`, `cves`, `modules`, `packages`, and `json`.
The default view is `overview`.

| CLI | Detail level | Binary content |
| --- | --- | --- |
| default | Summary | Name, MB, scan counts, top packages and vulnerabilities |
| `-v` | Expanded | Locations, aliases, runtime state, and scan errors |
| `-vv` | Detailed | Module/package findings, build settings, and reconciliation exceptions |
| `-vvv` | Forensic | Detailed evidence plus layer, dependency, and normal reconciliation inventories |
| `--wide` | Cardinality modifier | Removes ten-entry limits and hash abbreviations from visible sections |

`-vvv --wide` is exhaustive. Text verbosity changes terminal output only;
saved human-readable views under `reports/` always use forensic-wide rendering.
JSON and the three identifier lists are already complete and reject text
verbosity options (`-v` and `--wide`).

Use `COMMAND --help` for all options. Paths supplied on the command line are
relative to the invocation directory unless absolute.

`scan` uses one container workspace; `audit` and `aggregate` use the immediate
container workspaces beneath a batch root. Each defaults to the current directory
in that role. `report`, `check`, and `csaf` accept either a workspace or an audit
JSON file. A positional file and `--audit-file FILE` use the same resolution:
the file's directory supplies `pygo-audit.json` and workspace defaults. Files in
the standard `history/` directory use its parent workspace. An explicit workspace
argument takes precedence over that inference, and `--audit-file` takes precedence
over a positional file. For a custom history location, supply its workspace
explicitly. With no file or workspace supplied, the workspace is cwd.

## One container workspace

Scripts or the operator prepare the audit directory and its subject files:

```text
AUDIT_ROOT/
├── pygo-audit.json               optional workspace settings
├── .pygo-audit-image.json         optional image identity
├── rootfs/                       final filesystem
├── layers/                       optional historical filesystems
│   ├── layer-000/
│   ├── layer-001/
│   └── ...
├── audit.json                    current canonical findings
├── reports/                      generated views and comparisons
│   ├── overview.txt
│   ├── binary-findings.txt
│   ├── vulnerability-findings.txt
│   ├── module-reconciliation.txt
│   ├── diagnostics.txt
│   ├── cves.txt
│   ├── modules.txt
│   └── packages.txt
├── history/
│   └── audit-<ID>-<date>.json      previous findings
├── csaf/                         supplied advisory documents
├── cache/                        reusable binary records
└── work/                         temporary and failed-run evidence
```

`scan` defaults to `rootfs/` and includes `layers/` if present. It does not
scan the entire workspace. Layer names above are the supplied extractor's
convention; arbitrary names remain supported. Missing optional layers are fine;
unreadable, empty, or malformed layer directories are reported as errors.
Explicitly supplied layer directories must exist; missing paths are errors.

```console
./pygo-audit scan service --jobs 4 --timeout 180
./pygo-audit scan service --no-layers
# From inside a prepared container audit directory:
pygo-audit scan
```

Linux with `/proc`, Python 3.14+, Go supporting `go version -m -json`, and
`govulncheck` are required for a full scan. There are no third-party Python
runtime dependencies. The host tools read files; subject programs are never run.

For each distinct Go binary, pygo-audit reads embedded build information with
`go version -m -json` and performs a binary vulnerability check with
`govulncheck -mode binary -format json`. Identical contents share work.
`govulncheck` may access its vulnerability database. `--no-vulncheck` gathers
build information only. `--go` and `--govulncheck` select host executables;
`--timeout` limits each invocation and `--jobs` bounds binary inspections.

A scan always writes `audit.json` and exhaustive text views under `reports/`.
Binary and vulnerability findings contain the same evidence with different
groupings; module reconciliation owns build and dependency comparison data.
New views are staged before publication; the previous JSON is preserved in the
flat `history/` directory.
The history filename uses the prior report's recorded scan ID and UTC completion
date; both are required before replacing an existing audit. Individual file
replacements are atomic, with canonical JSON published last. The group of files
is not a filesystem transaction; after an abrupt process failure, views can be
regenerated from the canonical JSON. Concurrent publishers are rejected by
locking the output directory without leaving a lock artifact. Extraction
contents are never replaced by a scan.

With `--strict`, actionable issues give status 1 and save the incomplete result
under `work/failed-*/`, preserving the previous current audit. Informational
reconciliation differences do not make a scan fail. Without strict mode, an
incomplete report can become current, with its coverage limitations recorded.

## Workspace settings and precedence

An optional `pygo-audit.json` contains flat option names:

```json
{
  "rootfs": "rootfs",
  "layers": true,
  "layers-dir": "layers",
  "cache-dir": "cache",
  "work-dir": "work",
  "jobs": 4,
  "timeout": 180,
  "vulncheck": true
}
```

Precedence is explicit CLI options, container settings, batch settings, then
built-in defaults. Relative paths in a settings file are relative to that file;
CLI paths are relative to the invocation directory. Unknown settings and invalid
types are rejected. Negative boolean CLI options override true sidecar values,
for example `--no-layers`, `--no-vulncheck`, and `--no-strict`.

Other path settings include `output-dir`, `history-dir`, `audit-file`,
`image-metadata`, `csaf` (an array), and `targets`. `layer-dir` is an array of
known oldest-to-newest paths and excludes `layers-dir`. Identity options below
are also accepted. Settings are read only from the selected audit directory,
never from an image-owned file under `rootfs/`.

Reports, history, caches, and work default beneath the applicable audit root.
Generated locations must remain outside every subject, including through
symlinks. No cache falls back to a home directory. Go subprocess cache/config
and temporary-directory defaults are redirected beneath `work/`; explicitly
supplied environment locations remain operator overrides. Work/cache directory
names are visible. If report output is explicitly relocated, select its JSON
with `--audit-file` or the `audit-file` setting for later commands.

## Layers and context

Discovery sorts immediate directories lexicographically; `--layer-sort numeric`
compares digit groups as numbers. Discovery order does not prove image chronology.
Discovered layer-only binaries are `unaccounted`; final-rootfs binaries are
`runtime`. These describe presence in the supplied filesystem, not whether a
particular deployed process can reach or execute the code.

Known chronology can be supplied explicitly, enabling whiteout and replacement
inference:

```console
./pygo-audit scan service \
  --layer-dir service/layers/layer-000 \
  --layer-dir service/layers/layer-001
```

Do not combine `--layer-dir` and `--layers-dir`. `--no-layers` skips history.
Symlink layer entries are rejected. No registry manifest is required.

## Batch workspaces

```text
BATCH_AUDIT_ROOT/
├── pygo-audit.json
├── cache/                       shared binary cache
├── work/                        shared temporary work
├── progress.tsv
├── reports/
│   └── container-summary.txt
├── service/
│   ├── rootfs/
│   ├── layers/layer-000/
│   ├── audit.json
│   └── history/
└── worker/
    ├── rootfs/
    ├── audit.json
    └── history/
```

```console
./pygo-audit audit run --workers 4 --jobs 2 --output-dir upload
./pygo-audit audit run --targets selected.txt
```

Each target retains its own `audit.json`. `progress.tsv` records `name`, `status`,
`audit_file`, and `detail`; `reports/container-summary.txt` presents the same outcomes.
The recorded path is the file actually published, including a strict failed scan
under `work/`. A failure before publication or a cancelled target has no audit
path. Batch execution status is separate from vulnerability findings.

For a portable result bundle, `audit --output-dir DIR` mirrors each target's
`audit.json` and complete report views into `DIR/<container-name>/`, and writes
`container-summary.txt` at `DIR/`. The canonical audit, progress file, shared
cache, and work files remain in the batch workspace, so later aggregate commands
still read the normal audit files. Batch `csaf` and `aggregate` use the same
`DIR/<container-name>/` layout for comparison reports.

Discovery examines immediate child directories containing `rootfs/`, workspace
settings, or an existing `audit.json`. Numbered names and completion markers are
not required. Each selected target is validated before work starts. `--targets`
selects a subset: one immediate child directory name per UTF-8 line, with blank
lines and `#` comment lines allowed. Duplicates, missing targets, and paths outside
the batch root fail visibly. This list contains directories, not image references.
`audit`, batch `csaf`, and `aggregate` all honor the same `--targets` selection.

Batch uses the same container scanning operation with shared cache/work defaults.
`--workers` controls containers and defaults to the logical CPUs available to the
process, falling back to one if unknown. Workspace settings and an explicit
`--workers N` override CPU detection. `--jobs` controls binary inspections per
container, so batch concurrency can reach `workers × jobs` inspections.
Batch defaults to strict scanning. `--fail-fast` cancels queued work after a
failure; running targets may finish. Repeating `audit` rescans prepared subjects
and refreshes vulnerability findings; it never re-extracts or skips a target
because an earlier audit exists. Preparation and its dry-run belong to scripts.

## Binary cache validity

One binary cache record keeps build facts and vulnerability results together.
Its identity includes binary SHA-256 and Go reader identity/version.

- Embedded build facts remain reusable for unchanged bytes and compatible tools.
- Vulnerability results require matching analysis settings and the current run ID.
  One standalone scan has one ID; all targets in one batch share an ID. A later
  invocation refreshes vulnerability knowledge even when its binary cache remains.
- Paths, layer history, and runtime disposition carry `requires-observation`
  markers in storage. Cache callers reconstruct them for the current container.
  The marker differs from `unknown`, which is a legitimate result of inspection.

Failed checks never become successful cached results. An old result is not a
fallback when refreshing fails. Entries have integrity checks; damaged or
incompatible entries are recomputed. Removing the cache loses performance, not
saved evidence. Embedded build facts are observations, not authenticity proofs.

## Optional image identity sidecar

By default, `scan` reads `.pygo-audit-image.json` from `AUDIT_ROOT`.
Use `--image-metadata FILE` to select another file. Every field is optional;
unknown fields, duplicate keys, and incorrect types are rejected. Versions and
identifiers are strings. Helpers write the file as JSON with two-space indentation.

```json
{
  "image": {
    "reference": "registry.example/team/service:latest",
    "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "platform": "linux/amd64",
    "extractor": "extract-image-layers",
    "name": "service",
    "vendor_image_name": "example/service",
    "image_build_release": "202604241817.p2.el9",
    "component": "service-container",
    "product_version": "1.2.3",
    "component_version": "1.2.3",
    "product_component": "service-owner",
    "source_git_url": "https://example.test/team/service",
    "cpes": [
      "cpe:/a:example:service:1.2.3"
    ],
    "purls": [],
    "sources": [
      "rootfs/usr/share/buildinfo/labels.json"
    ]
  },
  "products": [
    {
      "name": "example/base",
      "component": "base-container",
      "version": "9.6",
      "release": "1769661443",
      "cpes": [
        "cpe:/a:example:base:9.6"
      ],
      "purls": [],
      "sources": [
        "layers/layer-000/root/buildinfo/labels.json",
        "layers/layer-000/usr/share/buildinfo/labels.json"
      ]
    }
  ],
  "csaf": {
    "product_ids": []
  }
}
```

`image` describes the final container. `products` holds separate product
contexts, each with its own name, component, version, release, `cpes`, `purls`,
and source paths. Helper scripts prepare these records, including any
vendor-specific label extraction and deduplication. `pygo-audit` reads the
supplied records; scanning and CSAF matching do not discover image identity
from container-owned labels. The final image digest is not assigned to a layer
product. `sources` is supplied provenance, not independently verified by the core.

The JSON uses the same snake_case names as saved image evidence. CLI options
remain hyphenated and override the corresponding final-image values:

| JSON image field | Scan option |
| --- | --- |
| `reference` | `--image-ref` |
| `digest` | `--image-digest` |
| `platform` | `--platform` |
| `extractor` | `--extractor` |
| `name` | `--image-name` |
| `vendor_image_name` | `--vendor-image-name` |
| `image_build_release` | `--image-build-release` |
| `component` | `--image-component` |
| `source_git_url` | `--source-git-url` |
| `product_version` | `--product-version` |
| `component_version` | `--component-version` |
| `product_component` | `--product-component` |
| `cpes` | `--cpe` (replaces the list with one value) |
| `purls` | `--purl` (replaces the list with one value) |

`csaf.product_ids` pins matching to exact product IDs in each CSAF document.
Use the combined product ID when the vendor status refers to a component in a
particular platform. A pin does not follow relationships or substitute a similar
ID. If no listed ID exists in a document, the result is `not_identified` and
lists the missing IDs. Pins bypass inferred identity checks and are labeled as
user selections in the output. These identifiers are document-local; verify that
the intended entry uses that ID in each supplied document.

`--csaf-product-id ID` supplies one pin to `scan` or `csaf`. To try an edited
identity file against existing saved findings without rescanning:

```bash
pygo-audit csaf AUDIT_ROOT --image-metadata AUDIT_ROOT/.pygo-audit-image.json --wide
pygo-audit csaf AUDIT_ROOT --csaf-product-id 'exact-combined-product-id' --wide
```

Without an explicit override, `csaf` uses only the identity saved in `audit.json`.
A comparison override does not modify that audit or its fingerprint. Its effective
identity is recorded in `comparison.json`, and the override source appears only
in the final `-vvv` provenance section. An empty `--csaf-product-id ''` clears pins.

Automatic matching compares each context independently: OCI PURL and that
context's CPE alternatives. Explicit versioned OCI PURLs can establish
the declared build; a conflicting known image digest prevents that match.
Multiple PURLs are supplied alternatives within the same product context; they
do not establish that different builds are identical. Architecture variants are
treated as equivalent for comparison; differences remain visible at `-vv`. All
exact CSAF entries are retained; weaker candidates are discarded when an exact
match exists. Without an exact match, plausible fuzzy matches remain separate.
The checker does not generate or select a canonical product ID.

Without supplied PURLs, the checker derives an OCI package-name candidate from
`vendor_image_name` (or `name`) for the image, and from `name` for other products.
LOCAL LOOKUP CANDIDATES separates **CPEs** and **PURLs** into their own tables. The origin
column reads **Provided**, **From image name**, or **From product name**. `comparison.json` preserves supplied `purls` separately from
`derived_purls`, which include the value and originating field. Generated
candidates are not written back to the sidecar or saved audit. CPEs are used
as supplied. Red Hat OpenShift numeric release relationships are labeled fuzzy
and tentative; they do not establish an exact match.
A platform CPE alone does not establish that a vulnerable component is present.
Layer source paths appear only in the final forensic provenance section.

The generated identity sidecar sits outside `rootfs/`. A file with the same name
inside the container is ordinary subject data and cannot impersonate the default
identity file. The structured JSON replaces the old flat identity object;
regenerate identity files and audits when adopting this format. There is no
legacy-format reader or version fallback.

## Read current or previous findings

```console
./pygo-audit report service
./pygo-audit report service --view binary-findings -vv
./pygo-audit report service/history/audit-ID-date.json --view vulnerability-findings
./pygo-audit report --audit-file service/audit.json
./pygo-audit check service --id CVE-2026-0001
```

Targeted checks show the requested identifiers, their detected/not-detected status,
and scan coverage by default. They accept the same `-v`, `-vv`, `-vvv`, and
`--wide` controls as reports. From `-v`, detected checks reuse the
vulnerability-findings layout: aliases and advisory links, modules and packages,
then associated binaries. `-vv` adds fixed versions and expanded binary evidence;
`-vvv` adds symbols and ends with provenance, including the audit hash.
Incomplete coverage still makes an absent match indeterminate. Saved check files
include all details without truncation, regardless of console verbosity.

These commands never reopen subject binaries or run vulnerability analysis.
Current and historical audit JSON use the same reader. A selected file's name
does not determine its identity; its contents are validated as audit evidence.
The compact binary-findings view identifies each binary by filename and displays
its decimal size in MB. `Recorded modules` counts the modules in the scanner's
SBOM, falling back to embedded dependency records when no SBOM inventory is
available; it is not a count of Go packages. Paths remain in expanded output. Compact binary findings
list at most ten affected packages, ordered by
finding count, and ten vulnerabilities ordered by identifier. Hardlinks, symlinks, and layer observations in binary-findings are shown
only at `-vvv`.
The `vulnerability-findings` view starts with image identity and counts of unique
vulnerabilities and CVEs. The default findings list contains only deduplicated CVE
identifiers. `-v` adds named vulnerability sections, aliases, advisory links,
affected binary counts, and aligned binary/layer, runtime disposition, evidence
kind, and rootfs-relative location columns. Findings without a CVE are
also shown at `-v` and above; aliases do not count as additional vulnerabilities.
Each vulnerability has a full-width `=` rule. Modules with current versions and
package lists appear before affected binaries.
`-vv` adds affected module/package counts and reported fixed versions. Each binary
expands into a named block with locations, binary hash, runtime disposition,
evidence kinds, and reachability. `-vvv` adds the bullet list of observed symbols.
Symbol names are
qualified by package and displayed without abbreviation; use `--wide` to remove
list limits. Names absent from the saved findings appear as
`(not recorded)`; a new scan records names from the scanner's finding traces.
Advisory symbol lists are not used as evidence of a binary's observed symbols.
Different versions remain separate, with
binary associations retained for each module/version group. `-vvv` expands
packages into finding-kind and
reachability evidence with their associated binaries. Hardlinks, symlinks, and
full layer history appear inside each binary block only at `-vvv`; scanner
provenance remains the final section.
Missing package information is explicitly reported.
Lists show at most ten entries; add `--wide` to show every entry and unabridged
binary columns. `binary-findings` groups all affecting vulnerabilities
beneath each binary. `module-reconciliation` separately owns build settings,
affected or anomalous module comparisons, and the forensic dependency inventory.
`--output-dir` can save derived views or targeted checks; generated artifacts are
replaced by default, while unrelated files in the destination are preserved.

The `diagnostics` view uses the same image inventory and heading hierarchy.
Its result heading includes scan coverage; operational failures and informational
reconciliation limitations/differences remain distinct. Default output lists
grouped issue summaries. Reconciliation groups come directly from saved
Go-version, module, and finding comparisons. Equivalent observations share one
group with their evidence sources and original binaries; diagnostic messages are
not parsed or used to limit the available comparisons. `-v` expands the messages and comparison details, with
location tables preserving rootfs versus layer scope. `-vv` expands affected
binary records with runtime disposition, hash, scan status, and reconciliation
status. Locations without a unique matching binary remain under `OTHER LOCATIONS`.
`-vvv` adds hardlinks, symlinks, layer observations, original diagnostic paths,
and scanner provenance as the final section. `--wide` removes list and column
limits. Incomplete scan coverage remains visible at every verbosity level.

## Export CVEs, modules, or packages

```console
./pygo-audit report service --view cves > cves.txt
./pygo-audit report service --view modules
./pygo-audit report service --view packages
./pygo-audit aggregate run --view cves > aggregate-cves.txt
./pygo-audit aggregate run --view modules
./pygo-audit aggregate run --view packages
```

Each view emits sorted, deduplicated identifiers, one per line, with no heading,
footer, or truncation. Modules and packages use `path@version`, preserving separate
entries when a path has multiple versions. Missing versions appear as `@unknown`;
recorded development versions such as `(devel)` are preserved.
No matching identifiers produce empty output.
The lists cover all recorded binaries, including historical layer observations;
they do not imply complete scan coverage.
Aggregate views combine the selected child audits and deduplicate across
containers. They print only the identifier list and do not run CSAF comparisons
or write aggregate reports. `--targets` limits which audits contribute.

| View | Included identifiers |
| --- | --- |
| `cves` | Uppercase CVEs from advisory IDs and aliases, including advisories without findings |
| `modules` | Main and dependency modules, original and replacement paths with their respective versions, and modules recorded in scanner inventory, reconciliation, or findings; includes `stdlib` when recorded |
| `packages` | Main package paths, scanner SBOM roots, and package paths in observed vulnerability findings, paired with their containing module's version |

Package versions come first from the finding's recorded version, then from the
same binary's module metadata, applying build replacements. An absent or
ambiguous module version appears as `@unknown`; versions are never borrowed from
another binary.

The package list is limited to paths recorded in the audit. It is not a full
inventory of every package compiled into a binary. Advisory-only affected
module/package declarations are excluded from both inventory exports.

Scans save `cves.txt`, `modules.txt`, and `packages.txt` under `reports/`.
`report --output-dir DIR` refreshes these lists alongside the human-readable
reports. Exporting an existing audit requires no rescan.

## Compare local CSAF evidence

```console
./pygo-audit report service --view cves |
  ./scripts/fetch-redhat-csaf --input-format cves - service/csaf
./pygo-audit csaf service
./pygo-audit csaf service -v
./pygo-audit csaf service -vv --wide
./pygo-audit csaf service --csaf advisory.json
./pygo-audit csaf run --csaf run/csaf
```

The checker reads image identity from current `audit.json`. For one container it
checks every supplied document's product tree, regardless of Go findings or
whether the document contains a CVE. It writes `reports/comparison.json` and a
forensic-wide `reports/comparison.txt`.

A batch root selects its child audits and uses the same comparison operation for
each. Batch `csaf` and `aggregate` compare only CVEs recorded in each container's
audit, including advisories without findings. Selection uses vulnerability records
inside the documents, so an advisory with several CVEs contributes only the
relevant records. Documents for another container do not add negative cases.
This scope also applies to a batch with one selected child.

The batch root's `csaf/` collection is shared by default. Container settings can
override it; explicit CLI options take precedence. Within one invocation, shared
documents are read and indexed once, and identical lookup inputs reuse matching
work. Each container's conclusions still use its own saved binary evidence.
`--jobs` bounds document workers. Inputs are reread on subsequent invocations.

Each document entry in `comparison.json` retains a deduplicated `canonical_urls`
list from `document.references` and the string `current_release_date` from
`document.tracking`. Following
[CSAF section 6.2.11](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#6211-missing-canonical-url),
these are HTTPS `self` references whose filenames correspond to the document's
tracking ID. The free-text reference summary does not determine selection.
Multiple qualifying URLs are preserved; missing references produce an empty
list. Every verbosity uses `<CVE>: <canonical URL>` as the comparison heading.
Multiple URLs appear on separate lines within the same banner; without a URL,
the heading is the CVE alone. The final `-vvv` provenance section identifies each
document by its current release date and lists its canonical URLs. Collection
does not fetch or verify remote content.

The default output separates **Local scan**, **CSAF ID Match**, **Vendor assessment**,
and **Agreement** under each `<CVE>: <canonical URL>` banner, followed by the
discovered candidate IDs. Every locally observed CVE remains visible, including
CVEs without supplied documents.

Local scan is independent of CSAF matching and vendor statements:

- **Affected**: the saved scan contains a vulnerability finding at module,
  package, or symbol precision. Findings solely in deleted/replaced binaries
  participate in the same comparison and show **Runtime available: No**.
- **Not Affected**: scanning completed without operational issues and recorded
  no vulnerable code for this CVE, including scans that found no Go binaries.
- **Undetermined**: no finding was recorded, but scanning was incomplete,
  disabled, failed, or had operational issues.

These are local scan results at the requested evidence level, not an independent
proof of exploitability or remediation. Advisory references without finding
records do not count as detected code. Embedded version metadata counts when
associated with a vulnerability finding; `go version -m` alone does not identify
CVEs. Missing CSAF matches never determine the local result.

Match states are **Document not provided**, **No match found**, **Ambiguous**,
**Fuzzy**, and **Exact**. Exact matching uses the
image digest, a supplied versioned PURL, or an explicitly selected product ID;
a pin remains labeled as a user selection. Exact matches take precedence across
all records for a CVE. Weaker candidates and their statements are discarded from
text and JSON, including weaker records in other documents. Conflicting statements
about exact matches remain inspectable. No fallback occurs when an exact product
has no vendor status.

Without an exact match, a component name and compatible CPE scope
can support fuzzy matching, including a qualified broader numeric version family.
Multiple distinct identities with equally strong evidence produce **Ambiguous**,
including ties between exact selections. A unique stronger identity determines
the headline; weaker links do not outvote it. Candidates with only a partial
name or unresolved product scope are also Ambiguous. No match found means no
candidate identity was identified.
Repeated documents and related entries for one component do not inflate this
count. Architecture-only variants also share one identity for counting purposes.
Their differences appear at `-vv` and do not independently lower match confidence.
Different or unknown build digests still allow a fuzzy component/CPE match;
incompatible component or product scope does not. Supplied versioned PURLs must
agree in all fields apart from architecture to establish an exact match, and a
conflicting recorded digest prevents that exact match.

The Red Hat OpenShift policy uses recorded image/sidecar versions and supplied
CSAF version evidence, never directory names. It pads omitted numeric components
with zero (`4.20` becomes `4.20.0`) and interprets suffixes such as
`v0.3.1-560-gabc` as `0.3.1`, preserving the original text. Uninterpretable values,
including commit hashes and image digests, do not become numeric versions.
Product versions and component versions remain separate subjects.

A declared fixed version provides a tentative boundary only within the same
major/minor release line: earlier versions are inferred affected, and that
version or later versions fixed. Explicit statements for the observed version
take precedence; an earlier applicable fixed build is not undone by a later
fixed build. Cross-release comparisons stay Undetermined. An enclosing platform
CPE is matching scope, not a fix boundary for a particular component build.
An explicitly pinned product ID uses its own statement without version inference.
`-vv` shows the policy, raw and normalized versions, and the inference reason.
JSON retains the original vendor statements separately from effective assessments.

When a local CVE has no supplied document, the report asks the user to check
their CSAF provider. The checker does not fetch documents. Cached absence-record
details appear only in the final `-vvv` provenance section.

Agreement compares each selected product statement with the local evidence,
keeping that statement's flags separate. Each candidate has one of five outcomes:

| Agreement | Meaning |
| --- | --- |
| Yes | An exact match corroborates the local finding. |
| Qualified yes | Applicable vendor execution-path/adversary-control qualifications explain observed code, or fuzzy/ambiguous identities support compatible conditional conclusions. |
| No | An exact product statement is verifiably contradicted, such as a component-absence claim alongside package/symbol evidence in a runtime binary. |
| Qualified no | The vendor statement disagrees with the local finding, but product identity is tentative or the evidence cannot verify the contradiction. |
| Undetermined | Missing documents, no match, missing status, ongoing investigation, insufficient local evidence, or conflicting statements within a candidate prevent a conclusion. |

The overall CVE agreement can additionally be **Mixed** when accepted candidates
reach opposing conclusions (Yes/Qualified yes versus No/Qualified no).
Individual candidates never show Mixed. Different raw status labels alone are
insufficient. Identity uncertainty qualifies a comparison instead of suppressing
it: a clear affected, fixed, or not-affected statement can yield Qualified yes
or Qualified no. Missing status, ongoing investigation, or conflicting statements
within a candidate remain Undetermined.

A vulnerable-code-absence claim or fixed status is not disproved merely by a
retained symbol or version string; fixes/backports may retain both. Historical
findings cannot establish a contradiction about the final image. A document-only
CVE without a local finding remains Undetermined. An affected statement and a
not-affected execution-path qualification can both be compatible with observed
code, producing Qualified yes. Unanimous, unverified disagreement produces
Qualified no; it does not prove that the vendor is wrong. Boundary status labels
are interpreted by the selected policy when usable version evidence is present;
raw labels remain available in detailed evidence.

Every verbosity level starts with `[LOCAL LOOKUP CANDIDATES]`, showing the local
image/inherited product identifiers once for the whole comparison. These inputs
come from the saved identity or its explicit override. Product-ID pins bypass
automatic discovery; otherwise the checker looks for OCI PURL package names,
matching digests, or name substrings in each supplied document's product tree,
then checks the related product/CPE scope. This happens before reading CVE
statuses. Name resemblance alone can therefore produce an unresolved candidate.

Under each CVE, `[IDENTIFIED PRODUCTS]` lists the results grouped by the local
lookup product. The normal view shows sorted, deduplicated product IDs within
each group. Unresolved identities remain visible; presence in this list does not
establish a match. `--wide` shows the complete list. Missing documents and absent
products remain explicit. Vendor statements and agreement stay specific to each
CVE and document, even when the same product is identified more than once.

The default and `-v` views show concise CSAF ID Match and Agreement labels.
Every CVE has a `[LOCAL FINDINGS]` section before its identified products. The
default view lists unique binaries in aligned `BINARY`, `RUNTIME`, and
`EVIDENCE` columns. Evidence kinds such as module, package, and symbol are sorted
and listed on separate lines within each binary's cell. The same column
definition supplies the headings and visibility rules at every table verbosity.
Binaries are deduplicated by full SHA-256; different bytes
with the same name remain separate. Runtime availability is `YES` for a runtime
artifact, `NO` for a deleted/replaced artifact, and `UNDETERMINED` for an unknown
or unaccounted historical disposition. With no local observations, the section
states that no local finding was recorded.

`-v` adds image digest/architecture, reachability, binary locations, and a
sorted, unique module table nested inside `[LOCAL FINDINGS]`, with `MODULE`,
`FOUND VERSION`, and `FIXED MODULE VERSION`. Modules shared by binaries or packages
appear once per version/fix combination. Package names start at `-vv`.
The detailed module/package table orders its columns as `MODULE`, `PACKAGE`,
`FOUND VERSION`, `FIXED MODULE VERSION`, and `BINARY CGO`. Package paths are
relative to their module (`.` means the module's root package). Paths outside
the module, including standard-library paths such as `net/http`, stay intact.

The identified-product groups use local lookup names, not generated vendor IDs.
From `-v` through `-vvv`, each candidate uses the same component-name heading and
shows its full `CSAF product ID`, CSAF ID Match, **Mismatches**, and its own Agreement
result. The candidate's ID is always shown, including unresolved identities. Selected IDs that
differ from that ID appear separately under `Matched product IDs`; these can
identify the component in a particular platform through a CSAF relationship.
A fuzzy match retains its fuzzy label; showing the exact ID text does not imply
exact matching.
Compatible release scopes still sort ahead of broader or incompatible scopes,
but there are no separate release-bucket headings. Mismatches explain the actual
differences. Repeated names within a lookup group gain build qualifiers or product
IDs as needed. Architecture differences appear only at `-vv+`.
Full candidate PURLs, CPEs, vendor statements, and unselected product details
appear at `-vv+`.
Candidates with supported matches appear first. Mismatches identify differences
in component names, build digests, versions, and product/release scope. Missing
build metadata is not presented as a factual mismatch. Architecture differences
appear at `-vv+` and remain explicitly treated as equivalent. Each candidate's
comparison uses its own product statements and their justifications; unresolved
identity makes any yes/no answer conditional on that candidate being relevant.
The headline still combines the selected candidates' conclusions, and exact
matches still discard weaker candidates.

Multiple values are listed on separate lines, including match evidence, agreement
explanations, selected product IDs, checks, vendor statements, paths, and aliases.
Single values stay compact. Tables stack multiple values inside their aligned
cells, preserving one logical binary/package row. `--wide` includes all list
entries without truncation.

Reachability refers to execution of vulnerable code in the final image.
`NO` requires a deleted/replaced artifact or consistent, exact image/product
statements that explicitly place vulnerable code outside the execution path.
A statement about another product context cannot establish a binary's reachability.
Fuzzy or ambiguous matches, conflicting statements, unknown runtime state, and
symbol/module presence alone remain `UNDETERMINED`. A fixed or affected status,
or an adversary-control justification, is not execution-path evidence. `YES`
requires affirmative execution-path evidence, which the current binary scanner
does not provide. This display does not alter the scan's recorded `unspecified`
reachability.

`-vv` expands candidate agreements with explanations, individual product
relationships and vendor statements, and the matching checks. Product IDs appear
as product subsection headings rather than being repeated in separate match and
candidate sections. It also adds local scan explanations. `[LOCAL FINDINGS]`
expands its binary table with `CGO`, followed by the module table
with `PACKAGE` and `BINARY CGO` columns. Reachability explanations and
recorded-reachability entries are omitted from text at every verbosity; the
recorded finding remains in JSON.

CGO is a binary build setting, shown as Enabled, Disabled, or Unknown. Missing,
unrecognized, or conflicting settings are Unknown. The package table lists all
observed binary CGO settings for that package/version without splitting its row.
This does not establish that the package itself uses cgo. `-vvv` shows the setting
for each binary alongside its package findings.

Locations are relative to the container (without `rootfs/`) or historical layer.
Multiple paths for one binary stay together; they may be hardlinks or identical
copies grouped during layer composition. Artifacts are keyed by full binary
SHA-256, with distinct paths, runtime states, aliases, and layer history retained
as observations. Different contents at the same location stay separate. Rows are
deduplicated and sorted before preview limits apply.

`-vvv` expands each binary into a block with its module/package findings and
sorted, unique exact symbols. SHA-256, layer observation count, and symlinks appear
with the binary's other main fields, before module/package and symbol details.
Individual layer events follow without a second count heading.
Both version columns refer to the module as recorded by the local scan; they
are not vendor fixes. Provenance remains at the end. Each CVE has an equals-sign
banner above and below its heading. Bracketed section titles and indented
subsections distinguish the hierarchy without different separator lengths.

`--wide` removes list and column truncation and displays full digests. Saved text
is always forensic and wide. All four verbosity levels render the same computed
result; verbosity does not recalculate matching, agreement, or evidence. JSON
includes matching inputs, per-document
candidates, per-record assessments and raw references, and per-CVE `conclusions`
and `local_findings`. Conclusions include the independent `local_scan` result
and a `candidates` list with each candidate's match, mismatches, and agreement. Its one-based
`document`, `record`, and `candidate` references identify the retained document,
source record, and document candidate. Local artifacts include their computed
`reachability` and nullable `cgo_enabled` values derived from saved build settings.
The finding's raw reachability remains separate. `summary.scan_coverage`
records scan completion and operational issue counts.
The checked-document count includes all supplied documents,
including weaker records discarded after exact matching. Retained documents or
records stay separately inspectable inside their CVE's section; conflicting
statements remain visible. Local evidence
is shown once per CVE. Preview limits keep each conclusion and its evidence
together.

Directory inputs read immediate `*.json` documents and `*.missing` records.
Repeated paths are deduplicated; different documents may contain the same CVE,
and standalone checks include documents without vulnerability records. A cached HTTP 404
marker takes precedence over its retained JSON peer, while a valid document
supplied elsewhere can still be used. Its URL, check time, and marker path appear
only in final forensic provenance. No age-based expiry or network retry is added.
An explicitly requested absent CVE-named JSON file is reported as not found;
other missing input paths are errors. With local CVEs but no documents, the
report shows document not provided. If there are no documents, absence records,
or local CVEs, the command fails.

Use `--audit-file` to select previous evidence and `--csaf` for supplied files or
directories. Standalone `--output-dir` relocates the comparison pair. For batch
`csaf`, it creates one child directory per selected container beneath that output
directory. Without it, each comparison uses its child's configured output directory
or `reports/`. The command never downloads advisories or rescans binaries.

All comparisons are built and rendered before publication. Batch publication
protects every audit, identity override, and advisory input, locks the destination
directories, and restores previous reports after an ordinary write failure.

## Aggregate saved audits

```console
./pygo-audit aggregate run
./pygo-audit aggregate run --csaf run/csaf --jobs 4
./pygo-audit aggregate run --targets selected.txt -v --wide
```

Aggregation runs the shared container comparison and refreshes each child's
`comparison.json` and forensic-wide `comparison.txt`. It also writes
`aggregate.txt`, `cve-aggregates.txt`, `container-aggregates.txt`, `aggregate.json`,
and `pygo-audit-triage.csv` under the batch `reports/` directory. `--output-dir` relocates this batch bundle and adds a
`<container-name>/` subdirectory with each child's `comparison.json` and
`comparison.txt`; the original child comparison locations are refreshed too.
The advisory collection, overrides, target selection, concurrency, and CVE scope
follow batch `csaf` above. A missing document is reported
as not provided, with advice to check the user's provider. No download, rescan,
previous-comparison fallback, or alternate advisory lookup occurs.

Default text shows aggregate statistics, CVSS severity counts, agreement counts,
discrepancy rates, and agreement definitions. `cve-aggregates.txt` lists each CVE and the recorded
local assessment, CSAF ID match, vendor assessment, and agreement for each
container. `container-aggregates.txt` summarizes each container's severity counts,
vulnerable binary count, and CSAF product matches. Severity counts use each CVE's
highest reported score across containers. `-v`, `-vv`, and `-vvv` append container
details using the single-container renderer at that same verbosity. Provenance
appears once at the end of `-vvv`; `--wide` removes preview limits. Saved text is
always forensic-wide.

Severity uses the highest score reported for each CVE across containers: Critical
9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9, None 0.0, and Unscored
when no score was provided. The CVE aggregate lists only recorded comparisons;
an absent container row is not interpreted as Not Affected.

The JSON has `counting_unit: "container_cve"`, batch `summary`, and `containers`.
Each container retains the canonical comparison data, including identity under
`image`, conclusions by CVE, local findings, documents, and `summary.metrics`.
The batch summary contains `container_count`, `unique_cves`, and `metrics`.
Metrics count comparisons and discrepancies, with `agreement_counts`,
`local_scan_counts`, `match_counts`, and `vendor_assessment_counts` derived from
those same conclusions. Counter maps contain observed values only; an absent
label means zero. JSON does not add a batch agreement classification or derived
rate; the text summary calculates discrepancy rates from these counters.

Each container's `audit_summary` groups inventory and reconciliation counts.
Inventory `cve_observations` counts findings per binary/advisory/CVE, with one
observation for an advisory without findings. Repeated aliases within one advisory
are deduplicated. The comparison unit remains one container workspace/CVE pair:
several binaries or advisories do not multiply that pair. The same CVE in two
containers contributes twice to comparisons and once to batch `unique_cves`.
Binaries from earlier layers remain included with their runtime dispositions.

`pygo-audit-triage.csv` is complete regardless of text verbosity or `--wide`. It has one
row per container/CVE pair, sorted by descending highest CVSS score, then
container, agreement priority (No, Qualified no, Mixed, Undetermined, Qualified
yes, Yes), and CVE. Rows without a score sort last. Its columns are:

| Columns | Contents |
| --- | --- |
| `CONTAINER`, `CVE` | Workspace name and recorded CVE |
| `CVSS SCORE` | Distinct CSAF base scores, without the CVSS version prefix |
| `PYGO ASSESSMENT`, `VENDOR ASSESSMENT`, `AGREEMENT` | Local and vendor conclusions, preserving qualifications |
| `EVIDENCE` | Unique evidence kinds recorded in local binaries |
| `BINARIES` | Unique binary artifacts linked to the CVE |
| `CSAF URL` | Canonical advisory URLs |
| `CONTAINER URL` | Recorded image reference |

List-valued cells use semicolons. CSV quoting preserves commas and quotes; text
starting with a spreadsheet formula character is prefixed with an apostrophe.
Full comparison details remain in the child reports. All child comparisons and
the batch bundle are staged together and use the same publication rollback group.

## Exit status and limits

Argument syntax errors use status 2; operational/input failures use status 1.
Scan/report/check `--strict` makes actionable scan issues fail. Finding a
vulnerability is not itself an operational failure. A successful aggregate means
its reports were generated, not that CSAF coverage or matching was complete.

Previous audits preserve what was known then. A new CSAF comparison does not
refresh their Go vulnerability evidence. Go binary checks do not provide complete
CGO/native-library coverage or establish what is running in a deployment.
