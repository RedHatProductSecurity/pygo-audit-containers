# Developer guide

Welcome to the part of the repository where a filesystem becomes a model, the
model becomes evidence, and the evidence becomes a report that somebody can
actually read before lunch.

The guiding design constraint is minimalism. `pygo-audit` should remain useful
with a directory produced by almost anything, without becoming a wrapper for
every image or binary-analysis tool people happen to prefer. The repository
currently says “containers,” but the library is really about a filesystem
subject. A mounted root, an extracted archive, a build artifact, or a test
fixture can all be valid input.

## Setup

This project uses bleeding-edge Python 3.14. Enjoy it. Show it off to your
friends. The library has no third-party runtime dependencies:

```console
python3 --version
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

For a source checkout without installation:

```console
./pygo-audit --help
PYTHONPATH=src python3 -m pygo_audit --help
```

The root launcher adds this checkout's `src/` to the import path. The installed
command uses the `pyproject.toml` entry point and needs no path adjustment.

The external programs are intentionally explicit: `go` reads build metadata,
and `govulncheck` performs binary vulnerability analysis. The scanner never
executes a binary found inside the inspected filesystem.

## Black-box safety warning

Deconstructing an image is an input-handling operation, not a trust upgrade.
Treat the image, archives, filesystem contents, and metadata as untrusted
black-box data. A safe default is:

- work as a non-root user in a disposable directory;
- verify the image digest and platform before unpacking;
- make examined files read-only and grant only the scan account the access it
  needs;
- never execute files, package hooks, entrypoints, or scripts from the tree;
- do not follow symlinks while discovering files;
- defend archive extraction against path traversal and special-file surprises;
- keep network access explicit and limited to the host tools that need it;
- bound disk, memory, process, and wall-clock use;
- keep provenance and tool versions beside the resulting report; and
- put temporary caches in the working directory or sandbox, not in `~/`,
  unless the caller explicitly asks for a user cache.

`pygo-audit` itself reads the supplied files and invokes host-side `go` and
`govulncheck`; it does not run programs found in the subject filesystem.
Least privilege is still the right posture for the surrounding extraction and
analysis workflow.

## The codebase in one screen

```text
src/pygo_audit/
├── cli.py             options, defaults, sidecar configuration, and dispatch
├── batch.py           scan prepared children using the same container workflow
├── workspace.py       subject validation and scan publication
├── csaf.py            local CSAF matching and comparison
├── aggregate.py       batch text/JSON summaries and container details
├── comparison.py      shared VEX conclusions, metrics, and headline layout
├── scanner.py         ELF discovery, hashing, Go metadata, govulncheck
├── layer_scan.py      rootfs/layer composition and disposition decisions
├── models.py          canonical report data model
├── reconciliation.py  declared-module versus observed-module comparison
├── vulnerabilities.py govulncheck JSON normalization
├── binary_cache.py    run-scoped content-addressed result cache
├── result_cache.py    shared private storage and locking for derived results
├── storage.py         atomic file publication and semantic JSON hashing
├── audit.py           current and historical audit JSON validation
├── artifacts.py       audit directory publication
├── report_views.py    finding grouping and targeted checks
├── report_sections.py shared subject, provenance, and status sections
├── text_layout.py     text layout, wrapping, and bounded-entry previews
├── text_report.py     compose human-readable views from evidence and sections
└── report.py          public render dispatch

scripts/
├── prepare-audits       batch directory preparation and dry-run
├── extract-image-layers  image/filesystem adapter and product sidecar generation
├── gather-openshift-targets
│                        OpenShift release inventory adapter
└── fetch-redhat-csaf     Red Hat document retrieval and download cache
```

The library is the product. The scripts are vendor and external-tool adapters. If a
future analyst uses a different image tool, the scanner should not notice.

## Inputs and processing

See the [CLI reference](cli-reference.md) for package contracts and the
[scripts reference](scripts-reference.md) for product input preparation.

The scan boundary is intentionally boring:

```text
scan inputs
    │
    ├── root directory(s)
    ├── optional sibling .pygo-audit-image.json sidecar
    │       flat keys matching scan options
    │
    ├── optional ordered --layer-dir values
    │
    ▼
scanner._discover_elf_files
    │  magic check; inode deduplication; symlinks skipped
    ▼
scanner._inspect_elf_file
    │  one streaming pass for content identity
    │  cache lookup before Go/govulncheck subprocesses
    ▼
BinaryReport
    │  build metadata + vulnerability scan + reconciliation
    ▼
AuditReport
    │  container evidence, statistics, and scan/toolchain provenance
    ▼
 audit.json ──strict reader──> text reports / checks / CSAF comparison
```

The flat sidecar is optional. Its keys mirror scan options:
`image-ref`, `image-digest`, `platform`, `extractor`, `image-name`,
`image-component`, `source-git-url`, `product-version`, `component-version`,
`product-component`, and `cpe`. The sidecar supplies defaults; explicit CLI
options override it. Identity validation happens before scanning so a report
does not quietly attach evidence to the wrong image.

The extractor writes both `.pygo-audit*` sidecars in the audit directory,
outside `rootfs/` and historical layers. The container-facts sidecar is
separate from image identity: it records facts read from the extracted rootfs,
including `os-release` values and RPM package coordinates. Missing RPM tooling
is recorded as an evidence limitation rather than treated as an extraction
failure.

`rootfs/` is the normal subject. Repeated `--layer-dir` values are an optional
second observation stream. The scanner scans them with the same model and
worker pool, then composes the observations to determine whether a binary is
runtime, deleted, replaced, unaccounted, or unknown for this scan. The bytes
are not intrinsically “runtime” or “historical”; the scan context decides.

## Semantic and syntactic evidence

Pygo mostly records syntactic evidence: bytes, paths, hashes, Go build
metadata, module inventories, and `govulncheck` output. CSAF/VEX mostly records
semantic conclusions: affected product, vulnerable behavior, reachability,
remediation, or code absence. They are orthogonal descriptions, not duplicate
implementations of one schema.

The comparison layer should therefore preserve both conclusions. If VEX says a
vulnerability affects the product but pygo cannot find the compiled code, that
matters. If pygo finds the code but VEX says the vulnerable code is absent,
that matters too. If different wording still leads to the same concrete
conclusion — the vulnerable compiled code is definitely not in the supplied
filesystem — record agreement rather than punishing vocabulary.

## Reachability is a tool-owned conclusion

`govulncheck` uses a binary’s symbol information internally. Its implementation
falls back to module-level precision when symbols cannot be extracted, but its
stable command/JSON contract does not expose a reliable boolean saying whether
the binary has a usable `.symtab` or equivalent table. A finding with symbol
evidence is useful evidence; the absence of one is not proof that symbols are
missing.

Therefore pygo-audit does not parse ELF sections or infer reachability from raw
bytes. It preserves govulncheck’s module/package/symbol evidence and reports
reachability as `unspecified` when the Go tools do not specify it. This keeps
the library agnostic and prevents a convenient heuristic from becoming a
false fact in the data model.

## Workspace and cache invariants

`cli.py` defines command options and defaults, reads workspace configuration,
resolves paths and precedence, and selects identity sidecars. Command handlers
receive resolved settings and targets; they do not import the CLI or read settings
files. Its `OPTIONS` table supplies types, defaults, and help text to the argument
parser and configuration validator. `identity.py` validates the identity JSON format. Explicit CLI options
must remain distinguishable from parser defaults; only explicit options override
sidecars. Resolve relative paths at their source. Batch passes inherited settings,
a shared cache/work location, and one run ID into the same `scan_workspace` used
by standalone scanning. Extraction and inventory-to-directory work stay in scripts.

`BinaryResultCache` keys records by binary SHA-256 and the Go reader profile.
Records contain both static build facts and vulnerability results. A vulnerability
result is reusable only when its run ID and analysis profile match. Store build
facts even when vulnerability checking fails, but never reuse failed checks as
success or substitute previous findings after a refresh failure.

Cached paths, disposition, and layer history contain explicit contextual tombstones.
Cache loads supply current paths/disposition and clear history for recomposition.
Reconciliation is rebuilt with current evidence. The final model contains no
`requires-observation` markers; `unknown` remains a valid final conclusion.

`ResultCache` owns checked private storage and locking. Payloads have SHA-256
footers; damaged or incompatible entries are recomputed. Public JSON remains
standard JSON. Binary entries contain the evidence model and vulnerability-validity
metadata. Cache shapes are private and asserted in tests; production has no schema
versions or migration paths. Stable build facts can survive process lifetimes;
vulnerability knowledge cannot.

CSAF assessment keys cover run ID, advisory content, CVE, image identity, and detail
mode. Source locations and local findings are assembled from
the current audit. Comparison and aggregation use in-memory reuse; downloaded
advisory documents remain reusable files managed by the retrieval script.

Generated paths must resolve outside subjects. Defaults live under the applicable
audit root, including Go subprocess cache/config/temp paths beneath `work/`.
Explicit environment paths remain caller choices. No implicit home cache is used.

`artifacts.publish_audit` saves and validates staged `audit.json`, then renders
views from that file's reconstructed models. Publication preserves the previous
JSON under `history/audit-<ID>-<date>.json` and publishes canonical JSON last under
a workspace lock. Strict failed scans retain diagnostic output under `work/` and
leave current findings intact. Individual files are atomic; multi-file publication
is not a filesystem transaction.

`artifacts.write_comparison_artifacts` publishes CSAF and aggregate JSON/text pairs
with the same replacement and rollback routine. It checks that outputs differ
from inputs and holds the output directory lock during publication.

## Strong types at the edges

Use explicit types throughout new code:

- prefer dataclasses, enums/constants, `Path`, and built-in generic forms such
  as `dict[str, str]`;
- give functions and methods complete parameter and return annotations;
- narrow untrusted JSON immediately into typed model objects;
- keep `Any` at narrow, documented JSON/tool boundaries only; and
- make invalid states difficult to construct rather than validating them in
  every renderer.

The project currently has a few unavoidable dynamic edges because subprocess
JSON and external documents are not typed by Python. That is a reason to
quarantine escapes, not a reason to spread them through the model.

## Adding a field

Saved audits follow the [internal audit JSON contract](audit-contract.md).
`audit.load_audit` rejects missing or unknown fields, malformed types, duplicate
JSON keys, and evidence that differs from its canonical serialization. Every saved
audit consumer uses this reader. `report_views.iter_binary_vulnerabilities` shares
the original binary and vulnerability objects, retaining empty findings and
reconciliation data that presentation-specific views may omit.

Text reports compose inventory, binary, and package sections in `text_report.py`.
`report_sections.py` supplies common subject, provenance, coverage, and status
sections, while `TextLayout` owns alignment, wrapping, headings, and bounded-list
presentation.
The immutable `RenderPolicy` owns summary, expanded, detailed, and forensic
visibility plus the independent wide/cardinality choice. `report_views.py`
groups repeated observations into shared finding summaries. Renderers group those
summaries by module and package as needed, using the same `group_items` helper.
These derived views do not change the serialized audit contract.
Every generated file under `reports/` uses forensic-wide rendering;
`audit.json` remains the canonical evidence.

Rendering checks for missing identity, incomplete coverage, or historical binaries
inspect the saved report. They must not read current workspace settings, which may
differ from the settings used to produce that audit. The CLI selects the view and
detail level; each `TextLayout` carries its `RenderPolicy` through shared sections.

`comparison.py` supplies the same container/CVE classification to CSAF and aggregate
reports. Its normalized `VexDetails` result includes the final code-presence
comparison without a separate evaluation wrapper. Coverage counts usable conclusions;
corroboration counts agreements
among them. Unknown and conflicting VEX conclusions stay outside that second
denominator. Batch metrics count container/CVE pairs and sum counts before
calculating percentages. Undefined percentages are JSON `null` and text `N/A`.
`aggregate.py` retains inventory/reconciliation counters in `audit_summary`,
using model status choices and shared CSAF counter categories to retain zero counts.
Its text and JSON views use the same
comparison result. CSV serialization is no longer part of aggregation.

Use this checklist so the model remains the single source of truth:

1. Add the typed field to the relevant evidence dataclass in `models.py`.
2. Its name and type define the serialized field; defaults remain required in JSON.
3. Declare nonempty values and supported states on the model for the shared
   `__post_init__` hook; extend that hook for other construction invariants.
   Keep JSON/type and completed-record consistency checks in `audit.py`.
4. Populate it at the observation boundary in `scanner.py` or `layer_scan.py`.
5. Add it to text reports only where it answers a human question.
6. Update batch, CSAF, aggregation, and any adapter consuming `audit.json`.
7. Add a round-trip test and a report test.

`JsonModel` serializes evidence dataclasses; the reader reconstructs their declared
types. Keep computed summaries as properties or methods instead of storing them
again. Dataclasses used only while formatting reports are outside the audit graph.

Do not teach each renderer how to rediscover facts from paths. If a renderer
needs to infer something that belongs in the model, that is usually a smell
wearing a little hat: a normal warning sign with a tiny, whimsical brim. It
may be harmless, but it deserves a look before it becomes architecture.

## Testing and review

```console
PYTHONPATH=src python3 -m unittest discover -s tests
ruff check .
python3 -m compileall -q scripts src tests
git diff --check
```

The integration scanner tests build a tiny Go binary and use fake tools to
verify subprocess counts. Keep those tests: performance regressions are often
more expensive than correctness regressions when there are thousands of
binaries.

The project favors straightforward standard-library code over a dependency
framework. That is not austerity for its own sake. It means an analyst can
copy the repository into a constrained environment, inspect the engine, and
replace the surrounding tools without first adopting an ecosystem.

## Shared storage helpers

Publication locks the existing output directory with standard-library
`fcntl.flock`, so it leaves no lock artifact. Cache computations use `file_lock`,
wait up to their configured deadline, and never proceed unlocked. Cache-key lock
files must not be unlinked during normal operation because waiters must continue
using the same inode. Closing a descriptor releases either kind of lock,
including after process termination.

`storage.py` provides atomic UTF-8 text/JSON publication, a streaming writer
for streamed text, private cache directories, JSON reads, and semantic JSON hashing.
Both library code and scripts use these helpers; vendor-specific logic stays
in scripts.

Writes are create-only by default for the low-level storage helpers. Report
artifact publication explicitly uses atomic replacement, so generated output
is overwritten by default. The caller creates and validates the parent directory
and decides which paths are generated artifacts. The writer publishes a complete 0600
file, syncs it before publication, and attempts temporary-file cleanup afterward.
Cleanup failures print a warning with the path and error to stderr without
changing a successful outcome or masking the original failure.
These helpers publish generated output, not files inside an untrusted subject.

Private-file writers opt into `checksum=True`; both `atomic_read_text` and
`atomic_read_json` accept the same option. The shared text reader
verifies and removes the required footer before decoding the payload. The footer
is a lowercase, 64-digit SHA-256 surrounded by literal LF bytes. It covers every
payload byte before that footer, including any payload trailing newline. Even
formatting changes invalidate it. Verification needs no cache state or index.
Checksums are off by default to preserve standard output formats.

`atomic_read_json` only adds JSON decoding to `atomic_read_text`, so file reads
and checksum verification have one implementation. Each read opens one file
version: paired atomic writers can replace the path without changing that open
file. This does not protect against unrelated writers modifying a file in place.

`json_digest(document)` is separate: sorted keys, ASCII escapes, and compact JSON
give audit evidence and cache lookups a semantic address. Formatting and key order
do not change that address; list order still matters. Audit JSON filenames do not
encode or validate this digest. Cache addresses capture reuse inputs; records do
not duplicate those inputs in a separate schema/identity wrapper.

Prefer standard `Path` methods for simple operations: `Path.absolute()` makes
a path absolute without deliberately resolving symlinks; use `Path.resolve()`
when following links is part of the validation being performed.
