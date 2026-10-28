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

CSAF/VEX is a separate source. Its records may say that a product is affected,
fixed, not affected, or that vulnerable code is absent or unreachable. The
`pygo-audit csaf` command compares the CVEs already present in a saved report
with supplied local CSAF documents, matches relevant product/component
identifiers, and retains the provider's explanations. The Red Hat retrieval
helper lives separately in `scripts/fetch-redhat-csaf`. VEX-only CVEs are intentionally outside this audit universe.

## CPE evidence and the best product match

`pygo-audit csaf` compares the image's recorded `cpe` with CSAF product CPEs. It
also follows directed CSAF `default_component_of`, `optional_component_of`,
`external_component_of`, and `installed_on` relationships from the combined
product to its parent. Nested relationships are supported; cycles and missing
references are skipped. `installed_with` describes peers and is not treated as
parent inheritance. An explicit product CPE stops inheritance, so a conflicting
specific release cannot be bypassed by a broader ancestor.

The comparison accepts CPE URI and 2.3 formatted bindings, including URI packed
editions and escaped characters. It compares concrete part/vendor/product
identities, then checks the remaining attributes for compatibility, including
ANY and wildcard patterns. Conflicting concrete attributes and NA-versus-concrete
values reject a candidate. Missing/ANY attributes do not establish a specific
release, edition, or architecture. Unsupported or malformed forms fail closed;
this helper does not implement the full CPE applicability language.

Numeric version families are a separate, explicitly labeled heuristic:
`cpe:/a:redhat:openshift:4` can yield a `version_family` candidate for an image
with `cpe:/a:redhat:openshift:4.20::el9`. A literal `4` is not a standard CPE
wildcard, and `4.2` does not match `4.20`. Other attribute conflicts still reject
the candidate. See the [CPE name-matching specification](https://csrc.nist.gov/Projects/Security-Content-Automation-Protocol/Specifications/cpe/name-matching)
and [CSAF relationship definitions](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32123-relationships).

The strongest evidence wins, retaining ties rather than choosing arbitrarily:
image digest, component with release/architecture, component, direct CPE, then
parent CPE. Within each CPE tier, exact precedes compatible, then version-family
evidence. JSON and text assessments retain all CPE candidates even when a
stronger container match wins. Each candidate records its referenced product,
statuses, both CPEs, comparison kind, source product, and relationship path.

`match_level: platform` means CSAF contains a related platform/product entry;
it does not establish that the referenced component is installed in this image.
In particular, `known_affected` stays attached to that referenced product, not
every sibling component or the parent platform. A standalone component does
not inherit platforms from all the combinations in which it appears. Image
digest and component matches remain distinct from this platform evidence.

In text and JSON comparisons, platform-only matches remain `unverified` and
do not count as usable VEX coverage. Their statuses cannot produce agreement,
resolution, or code-presence conflicts for the container. Assessments preserve
the related CPE statuses and candidate counts. Aggregate summary fields count each
`csaf_cpe_*` scope, total `csaf_cpe_candidate_count`, and the number of CVEs with
at least one CPE-related affected product (`csaf_cpe_known_affected`). These
counts are separate from container-level `csaf_known_affected`.

This comparison uses the CPE already recorded in image metadata. It does not
discover additional CPEs or infer RPM ownership; package-to-binary mapping is
still a separate next step for establishing more specific component matches.

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
runtime. The reconciliation is not a vocabulary contest. It asks whether the
two descriptions agree about vulnerability status, and it makes disagreement
visible when they do not.

## The comparison table

For the same CVE, product, and sufficiently complete pygo scan:

| Pygo evidence | VEX conclusion | Interpretation |
| --- | --- | --- |
| vulnerable code found | `known_affected` | agreement |
| vulnerable code found | `fixed`, `vulnerable_code_not_present`, or another accepted resolution | `resolved_difference`: different explanation, same “not vulnerable here” conclusion from VEX |
| no matching vulnerable code found | code not present / not reachable | agreement when pygo coverage is complete enough to support that conclusion |
| code/CVE evidence found | `vulnerable_code_not_present` | `code_presence_conflict`: prominent review finding |
| no matching code found | `known_affected` | discrepancy in the other direction; verify component identity, scan coverage, and the binary selected by VEX |
| vulnerable code found | `known_not_affected` with no explanatory flag | `mismatch`: a usable VEX conclusion with an unresolved difference |
| either conclusion | VEX has mutually conflicting affected/not-affected statuses | `conflicting_vex`: uncertain evidence, excluded from usable coverage |

“Fixed” and “vulnerable code not present” can use different words while
pointing to the same practical conclusion. If both sources can definitely
conclude that the vulnerable compiled code is not in the supplied filesystem,
call that agreement — violent agreement, perhaps — rather than an error.

The reverse is just as important: if one source says the vulnerability is
present and the other says the relevant code is absent, do not smooth it away
because the status labels look familiar. That is the point of comparing the
models.

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

`reports/comparison.txt` and `reports/aggregate.txt` lead with VEX coverage and affected-status
corroboration. Coverage divides usable, image-matched conclusions by all observed
CVEs; corroboration divides agreements by usable conclusions. Both display counts
alongside percentages. Unknown evidence is separate from disagreements, and an
undefined rate displays `N/A`. Only binary-observed CVEs participate; this is not
an F1 score or a measure of vulnerability-detection accuracy.

Aggregate reports summarize each container and retain detailed CVE comparisons,
with conflicts first. Their JSON counterparts preserve the same counts and
classifications. The original `audit.json` remains the source for reviewing one
binary's full scan evidence.

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
