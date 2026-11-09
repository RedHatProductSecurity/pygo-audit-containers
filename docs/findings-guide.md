# Findings and resolution guide

Maintainer advice first: keep dependencies minimal and well-updated. Every
extra dependency creates another version range, another piece of metadata, and
another opportunity for two tools to describe the same code differently.

This guide is about the important question after `govulncheck` and CSAF/VEX
have spoken:

> Do the two sources reach the same practical conclusion about this CVE in
> this scanned subject?

It is deliberately forgiving about language and precise about conclusions.

## What pygo-audit is finding

For each discovered ELF file, pygo-audit:

1. hashes and identifies the file without executing it;
2. asks the host `go version -m -json` command for embedded Go build metadata;
3. asks `govulncheck` to inspect the binary and its module inventory;
4. records the CVEs and affected modules returned by that analysis; and
5. reconciles declared build metadata with the modules observed by
   `govulncheck`.

The result is evidence about the supplied bytes. It is not automatically a
claim that a process can reach a vulnerable function, that the image is
running, or that every native library has been examined.

CSAF/VEX is a separate source. The `pygo-audit csaf` command checks each supplied
document for the image using its recorded identity, regardless of Go findings.
The Red Hat retrieval helper lives separately in `scripts/fetch-redhat-csaf`.
Aggregate reports continue to compare Go-observed CVEs with vendor conclusions.

## Image and platform evidence

The single-image check uses a component PURL, product CPE, image digest and
architecture. It identifies an exact image digest, or an unversioned component
with an exact OCI package name in an applicable product relationship. A platform
CPE alone does not identify the component. Different fixed builds and conflicting
platform constraints cannot supply the scanned image's vendor status. When both
architectures are known and architecture is the only mismatch, an otherwise
supported candidate can supply a tentative comparison, labeled Fuzzy match found
with an explicit architecture qualification. Missing identification is not a
not-affected conclusion.

The default report gives each CVE Local scan, CSAF ID Match, Agreement, and a
sorted, deduplicated list of discovered CSAF product ID candidates, including
rejected candidates. Local scan reports Affected when recorded findings identify
vulnerable modules, packages, or symbols; Not Affected when the completed scan found none;
and Undetermined when missing findings coincide with incomplete scanning or
operational issues. Historical-only findings remain Affected with a qualification.
Vendor statements do not determine this result, and advisory references without
local finding records do not count as detected code.

`-v` adds matching inputs, evidence precision, sorted unique modules with
versions, and `[CSAF MATCH CANDIDATES: <local product name>]` sections. Candidates
are grouped by the image or inherited product being searched. Each candidate has
a short component-name heading, its full CSAF product ID (including rejected
candidates), CSAF ID Match, matching evidence, and Agreement. At `-v`, accepted
IDs that differ from the candidate's own ID appear under `Matched product IDs`.
Architecture/build qualifiers
distinguish repeated names. Full candidate PURLs and vendor statements appear
at `-vv+`. Multiple values are listed on separate lines, including inside aligned
table cells. Candidate agreement
uses that candidate's applicable statements; unsupported matches stay
Undetermined. `-vv` expands the checks and explanations and adds packages and the
sorted binary evidence table under
`[LOCAL FINDINGS]`, including locations, reachability explanations, and detailed
vendor matching evidence. `-vvv` expands binaries with their exact symbols and
ends with provenance. Name/context matches remain tentative.
Document-level canonical URLs are collected from HTTPS `self` references using
the CSAF tracking-ID filename convention. They are retained in each document's
`canonical_urls` list in `comparison.json`. All verbosity levels use
`<CVE>: <canonical URL>` as the heading, with multiple URLs on separate lines and
the CVE alone when none is available. Document source paths remain in the
`source` field in `comparison.json`. The final `-vvv` provenance section
identifies each CSAF document by its `tracking.current_release_date`, with
canonical URLs alongside it.
Exact matches discard weaker candidates in text and JSON. Retained product
statements stay separate so one candidate's flags cannot explain another's status.
CVE banners, bracketed sections, and indented subsections distinguish the hierarchy.

The local-findings section identifies which scanned binaries carry each CVE's
recorded evidence. Reachability is `UNDETERMINED` unless the artifact is absent
from the final image or consistent, exact image/product statements explicitly
exclude the vulnerable execution path (`NO`). Presence, an affected status, or a
symbol does not prove reachability (`YES`); the current scanner cannot establish
that outcome. `-vv` explains the basis, including whether it relies on the vendor,
and distinguishes current paths from historical locations. Duplicate binary
observations merge only when their locations, content, runtime disposition, and
layer context agree; `-vvv` adds recorded symbols and binary history. A local
finding may coexist with a vendor `known_not_affected` statement: the report
preserves both observations without treating binary evidence as proof of runtime
exploitability. Missing local findings are labeled as unrecorded in this audit.

The CPE helper supports URI and 2.3 bindings. The single-image matcher requires
sufficient local attributes to satisfy the product's constraints. A broader
numeric version family can support a qualified fuzzy comparison; it does not
become an exact CPE match or assert a vendor-specific hierarchy. Relationships are followed only
when explicitly linked; unrelated platform statements do not apply.
See the [CPE name-matching specification](https://csrc.nist.gov/Projects/Security-Content-Automation-Protocol/Specifications/cpe/name-matching)
and [CSAF relationship definitions](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32123-relationships).

## Semantic and syntactic conclusions

The two sources are orthogonal:

```text
pygo-audit                         CSAF/VEX
───────────                         ─────────
bytes and paths                    product/component identity
embedded Go metadata               affected/not-affected assertion
module and version evidence        fixed or vulnerable-code explanation
govulncheck result                  provider semantic conclusion
```

Pygo’s output is closer to a syntactic observation of what is in the binary.
VEX’s output is closer to a semantic model of what that product means at
runtime. Both single-image and aggregate comparisons ask whether the descriptions
agree, while retaining their different meanings. The single-image summary marks
fuzzy comparisons as tentative. Each candidate reports Yes, Qualified yes, No,
Qualified no, or Undetermined. Only the overall CVE result can report Mixed,
when accepted candidates reach opposing comparison conclusions. Conflicting
statements within one candidate remain Undetermined. No requires a verifiable
contradiction for an exact match; a symbol alone does not prove the vulnerable
implementation remains. Qualified no records disagreement whose identity or
evidence still needs qualification, such as a vendor fix/backport claim that
local symbols or version metadata cannot disprove.
Absent or historical-only local evidence does not establish safety or contradict
a statement about the final image.

## Batch triage

Batch and single-container reports use the same local findings, product matches,
vendor assessments, and agreement rules. The [CLI reference](cli-reference.md#compare-local-csaf-evidence)
defines the states and their qualifications. Batch comparisons include only each
container's recorded CVEs, so another image's advisory does not create a negative
case for this image.

Open `reports/pygo-audit-triage.csv` to compare containers. Each row is one container/CVE
pair, sorted by descending highest CVSS score, then container, agreement priority,
and CVE. Use `AGREEMENT` to review No, Qualified no, and Mixed results, then inspect
Undetermined cases for missing documents or unresolved identity. The per-container
`reports/comparison.txt` includes candidate and binary evidence; `audit.json` has
the original scan details. Qualified disagreement remains different from a verified
contradiction. A vendor fix/backport can coexist with an old embedded version or
surviving symbol name.

## A useful review sequence

When a CVE needs attention:

1. Confirm the image digest, platform, component, and binary path refer to the
   same subject.
2. Check whether pygo had complete coverage or an operational failure.
3. Read the pygo module path, found version, fixed version, and finding
   evidence in `reports/vulnerability-findings.txt`. Use
   `reports/binary-findings.txt` for the binary grouping and
   `reports/module-reconciliation.txt` for build and dependency comparisons.
4. Read the complete VEX status and flags, not only the headline status.
5. Check whether the provider is discussing Go code, a native library, or a
   product-level condition outside the binary scan.
6. Re-run with current Go/vulnerability databases if the evidence is stale.
7. Keep the disagreement in the report if it remains; do not rewrite it into
   agreement for aesthetic reasons.

Useful commands:

```console
./pygo-audit report audit/audit.json --view vulnerability-findings
./pygo-audit report audit/audit.json --view binary-findings -vvv --wide
./pygo-audit report audit/audit.json --view module-reconciliation -vvv --wide
./pygo-audit report audit/audit.json --view diagnostics
./pygo-audit csaf audit --csaf local-csaf/
```

`reports/comparison.txt` presents per-CVE candidates and linked evidence; its JSON
retains the detailed identity data. `reports/aggregate.txt` summarizes batch counts
and discrepancy rates; `reports/cve-aggregates.txt` groups comparison results by
CVE, and `reports/container-aggregates.txt` summarizes severity, vulnerable
binaries, and CSAF product matches per container. Use `-v` onward for the same
per-container details as `csaf`; provenance appears only at the bottom of `-vvv`. Counts use
container/CVE pairs, with batch unique CVEs reported separately. These counts do
not measure vulnerability-detection accuracy. The original `audit.json` remains
the source for reviewing a binary's full scan evidence.

## Reachability and unspecified evidence

`govulncheck` uses binary symbol information to narrow findings when it can,
and falls back to module-level precision when it cannot extract symbols. Its
stable command/JSON output does not promise a direct `.symtab`-available
boolean. Pygo therefore reports the evidence govulncheck actually emits —
module, package, or symbol — and uses `unspecified` when the Go tools do not
state a reachability conclusion.

That is intentionally less exciting than a homemade ELF heuristic. A symbol
finding is evidence that govulncheck observed a relevant symbol; a clean scan
does not prove that symbol information was present, and no report should imply
otherwise. The same vulnerability data is still fetched and evaluated.

## CGO and native-library limits

CGO is recorded per binary build. The CSAF package table includes `BINARY CGO`
from `-vv` onward, listing Enabled, Disabled, or Unknown for the binaries carrying
that package's findings. Missing or inconsistent build settings remain Unknown.
A package present in several builds can list several settings; this does not
attribute cgo usage to the package itself. Individual binary settings appear in
the binary evidence table and forensic blocks.

`govulncheck` is strongest for Go modules and Go call-graph reasoning. CGO can
bring native code into the program through dynamic libraries, static archives,
system headers, generated bindings, or vendored C/C++ sources. A Go-focused
finding can therefore be accurate about the Go portion while saying little
about a vulnerable OpenSSL, libc, zlib, or vendor library used at runtime.

For CGO-heavy binaries, supplement this audit with the relevant distribution
or native-library scanner and an SBOM that records shared-library provenance.
Check static versus dynamic linking, the actual runtime library search path,
and the image’s package database. Do not infer “no Go CVE found” to mean “no
native vulnerability exists.”

## Secondary filesystem context

If layer directories were supplied, `runtime_disposition` says whether the
observed bytes are present in the final `rootfs/`, explained as deleted or
replaced, or left unaccounted for. This is useful context for deciding whether
a finding applies to the final filesystem, but it does not change what a CVE
means and it does not replace the semantic comparison above.

The Go-tool evidence and layer disposition are context fields. They should help
a reviewer understand confidence and scope, not become shortcuts that erase an
otherwise important mismatch.
