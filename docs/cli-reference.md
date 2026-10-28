# pygo-audit CLI reference

`pygo-audit` examines prepared container filesystems, always saves scan evidence,
and compares saved findings with local CSAF documents. Image extraction,
inventory discovery, directory preparation, and advisory downloads belong to
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
| `audit [BATCH_AUDIT_ROOT]` | Parent of prepared container directories; defaults to cwd | Per-container audits, progress and summary |
| `aggregate [BATCH_AUDIT_ROOT]` | Parent of container audits; defaults to cwd | Batch summary and detailed text/JSON comparisons |
| `check [AUDIT_ROOT] --id ID...` | CVE, GHSA, or GO identifiers; defaults to cwd | Targeted findings |
| `csaf [AUDIT_ROOT]` | A container or batch workspace; defaults to cwd | Saved JSON/text comparisons with local documents |

`report` views are `overview`, `binary-findings`, `vulnerability-findings`,
`module-reconciliation`, `diagnostics`, and `json`.
The default view is `overview`.

| CLI | Detail level | Binary content |
| --- | --- | --- |
| default | Summary | Name, MB, scan counts, top packages and vulnerabilities |
| `-v` | Expanded | Locations, aliases, runtime state, and scan errors |
| `-vv` | Detailed | Module/package findings, build settings, and reconciliation exceptions |
| `-vvv` | Forensic | Detailed evidence plus layer, dependency, and normal reconciliation inventories |
| `--wide` | Cardinality modifier | Removes ten-entry limits and hash abbreviations from visible sections |

`-vvv --wide` is exhaustive. Text verbosity changes terminal output only;
generated files under `reports/` always use forensic-wide rendering. JSON is
already complete and rejects text verbosity options.

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
├── .pygo-audit-container.json     optional filesystem facts
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
│   └── diagnostics.txt
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
./pygo-audit audit run --workers 4 --jobs 2
./pygo-audit audit run --targets selected.txt
```

Each target retains its own `audit.json`. `progress.tsv` records `name`, `status`,
`audit_file`, and `detail`; `reports/container-summary.txt` presents the same outcomes.
The recorded path is the file actually published, including a strict failed scan
under `work/`. A failure before publication or a cancelled target has no audit
path. Batch execution status is separate from vulnerability findings.

Discovery examines immediate child directories containing `rootfs/`, workspace
settings, or an existing `audit.json`. Numbered names and completion markers are
not required. Each selected target is validated before work starts. `--targets`
selects a subset: one immediate child directory name per UTF-8 line, with blank
lines and `#` comment lines allowed. Duplicates, missing targets, and paths outside
the batch root fail visibly. This list contains directories, not image references.

Batch uses the same container scanning operation with shared cache/work defaults.
`--workers` controls containers; `--jobs` controls binary inspections per container.
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

By default, `scan` reads `.pygo-audit-image.json` from `AUDIT_ROOT`
(for example, `service/.pygo-audit-image.json`). Use
`--image-metadata FILE` to supply another file. It must be a flat JSON object
whose values are strings; unknown fields are rejected. Every field is optional.
Explicit command-line identity options override sidecar values.

```json
{
  "image-ref": "registry.example/team/service@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "image-digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "platform": "linux/amd64",
  "extractor": "my-extractor",
  "image-name": "service-1.2.3",
  "image-component": "service",
  "product-version": "1.2.3",
  "product-component": "service-owner",
  "component-version": "1.2.3",
  "source-git-url": "https://example.test/team/service",
  "cpe": "cpe:/a:example:service:1.2.3"
}
```

| Sidecar key / scan option | Meaning |
| --- | --- |
| `image-ref` | Original image reference |
| `image-digest` | Resolved OCI manifest digest, in algorithm:hex form |
| `platform` | OS/architecture, optionally including a variant |
| `extractor` | Name of the tool preparing the filesystem |
| `image-name` | Stable logical name supplied by the inventory |
| `image-component` | Component name from source metadata |
| `source-git-url` | Source repository URL |
| `component-version` | Component version from source metadata |
| `cpe` | Supplied CPE identity |
| `product-version` | Product release version from source metadata |
| `product-component` | Product component or owning team label from source metadata |

The package reads these as supplied data. Product metadata preparation is
described in the [scripts reference](scripts-reference.md). Generated
sidecars sit in the audit directory, outside the extracted filesystem, so
image contents cannot overwrite or impersonate the default metadata. A file
with the same name inside `rootfs/` is ordinary subject data and is not loaded
automatically. `--image-metadata` can explicitly select another sidecar location.
Sidecars and saved audits use the field names defined above.

An audit directory may also contain `.pygo-audit-container.json` with OS release and
package observations. The package does not yet incorporate those facts into
its report model or use RPM ownership to match binaries to CSAF products.
The [scripts reference](scripts-reference.md) describes how they are collected.

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
finding count, and ten vulnerabilities. When `reports/comparison.json` exists,
its audit hash must match the selected audit. Vulnerabilities are then ordered by
CVSS base score, CSAF severity (`Important`, `Moderate`, `Low`), and identifier. A
score for a matched product is preferred; otherwise the highest advisory score is
used. Hardlinks, symlinks, and layer observations in binary-findings are shown
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

## Compare local CSAF evidence

```console
./scripts/fetch-redhat-csaf service service/csaf
./pygo-audit csaf service
./pygo-audit csaf service --csaf advisory.json
./pygo-audit csaf run --csaf run/csaf
```

The checker reads current `audit.json` and local `csaf/` by default and writes
`reports/comparison.json` and `reports/comparison.txt`. A batch root selects its child audits;
its default advisory collection is shared. Container settings can override it.
Text starts with two percentages and their counts:

- **VEX coverage:** usable, image-matched conclusions divided by binary-observed CVEs.
- **Affected-status corroboration:** comparable CVEs also marked affected, divided
  by usable comparisons.

The breakdown separates corroborated findings, explained differences, unresolved
conflicts, and missing/uncertain evidence. Detailed CVEs put conflicts first and
retain binary paths, runtime dispositions, finding evidence, VEX explanations,
and advisory sources. JSON preserves the same metrics, numerators, denominators,
and per-CVE classifications. Undefined rates are `null` in JSON and `N/A` in text.

Missing documents, unmatched products, platform-only matches, investigations,
and contradictory affected/not-affected statuses are not usable conclusions.
A clear negative VEX conclusion is usable even when it conflicts with binary
evidence. An accepted VEX explanation counts as an explained difference;
symbol evidence contradicting an absent-code claim remains a conflict.
These rates describe the observed CVE set, not overall vulnerability detection
or exploitability. Binary scan coverage is displayed separately.

Use `--audit-file` to select previous evidence, `--csaf` for supplied files or
directories, and `--output-dir` to relocate a single comparison. Comparison never
retrieves documents or refreshes the binary scan.

Identity assessments state which advisory products match the supplied image
identity. `local_findings` records the observed binaries and findings separately.
A product match alone does not establish component presence or runtime reachability.
Each comparison records the source audit content hash so it can be distinguished
from a comparison of later findings. Matching calculations can be shared within
the invocation; there is no persistent
CSAF result-cache option. Downloaded advisory files remain ordinary reusable inputs.
Product-scoped CVSS v3 base scores and vectors are retained in comparison output;
the selected score records whether it matched a selected product or was the
highest available fallback.

Only observed CVEs are compared. Directory inputs read immediate `*.json` files;
filenames are arbitrary, and each document must contain a `vulnerabilities` array
with CVE records. Multi-CVE documents are supported. Repeated references to one file
are deduplicated; conflicting files for one CVE are rejected. Select the intended
revision explicitly. Missing documents are visible and give status 1. A successful
comparison means documents cover the observed CVEs, not that all products match or
that vulnerabilities are absent. See the [findings guide](findings-guide.md).

## Aggregate saved audits

```console
./pygo-audit aggregate run
./pygo-audit aggregate run --csaf run/csaf --jobs 4
```

Aggregation loads current reports from child audit directories and writes
`reports/aggregate.txt` and `reports/aggregate.json` in the batch root.
`--output-dir` relocates these reports. `--csaf` adds local comparison, also selectable
in workspace settings; otherwise CSAF remains unverified. `--jobs` bounds comparison
workers. No download or binary rescan occurs, and assessment reuse ends with the run.

The text starts with batch headlines and a per-container summary, followed by
details for each container. Containers with unresolved conflicts appear first.
JSON contains the same batch metrics and per-container comparisons, plus the
inventory and reconciliation counters in each container's `audit_summary`.

Batch rates use summed counts, never averages of container percentages. The unit
is one container workspace/CVE pair; repeated binaries or aliases of a CVE within
that workspace count once. The same CVE in two workspaces contributes twice,
including when both workspaces describe the same image. Historical findings remain
included when present in the audit, with their runtime dispositions preserved.
Only pygo-observed CVEs participate. No CSVs are generated; existing CSV files
are left untouched.

## Exit status and limits

Argument syntax errors use status 2; operational/input failures use status 1.
Scan/report/check `--strict` makes actionable scan issues fail. Finding a
vulnerability is not itself an operational failure. A successful aggregate means
its reports were generated, not that CSAF coverage or matching was complete.

Previous audits preserve what was known then. A new CSAF comparison does not
refresh their Go vulnerability evidence. Go binary checks do not provide complete
CGO/native-library coverage or establish what is running in a deployment.
