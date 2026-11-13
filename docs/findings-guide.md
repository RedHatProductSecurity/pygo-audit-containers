# Findings and resolution guide

This guide explains how to interpret pygo-audit's Go binary findings alongside CSAF/VEX statements. The key question is whether both sources reach the same practical conclusion about a CVE for the scanned subject—not whether they use the same terminology.

## What the audit establishes

For each discovered ELF, pygo-audit hashes and identifies the file, reads embedded Go build metadata with the host `go version -m -json`, runs `govulncheck`, records its CVEs and affected modules, and reconciles its module inventory with build metadata. This is evidence about the supplied bytes. It does not prove that the image is running, that a vulnerable function is reachable, or that native libraries were covered.

CSAF/VEX is evaluated separately from Go findings. `pygo-audit csaf` checks supplied documents against the image's recorded identity, even when the Go scan found no CVEs. The Red Hat retrieval helper is `scripts/fetch-redhat-csaf`; aggregate reports compare Go-observed CVEs with vendor conclusions.

## Identity, findings, and agreement

The single-image comparison uses component PURL, product CPE, image digest, and architecture. An exact image digest identifies the image; an unversioned component can match by exact OCI package name within an applicable product relationship. A platform CPE alone is insufficient. Conflicting platform constraints or different fixed builds cannot establish vendor status for the scanned image. If architecture is the only mismatch and both architectures are known, a supported candidate can provide a tentative, explicitly qualified fuzzy comparison. Missing identity is not a not-affected conclusion. Relationships apply only when explicitly linked.

The default report gives each CVE a Local scan result, CSAF ID Match, Agreement, and sorted, deduplicated CSAF product-ID candidates (including rejected candidates).

- **Local scan:** `Affected` when recorded findings identify vulnerable modules, packages, or symbols; `Not Affected` when a completed scan found none; `Undetermined` when missing findings coincide with incomplete coverage or operational issues. Historical-only findings remain `Affected` with a qualification. Vendor statements and advisory references without local finding records do not change this result.
- **CSAF ID Match:** reflects how well the advisory product identity matches the scanned subject. Exact matches outrank weaker candidates; fuzzy/name/context matches remain qualified.
- **Agreement:** compares local evidence with the applicable vendor conclusion. Candidate statements remain separate, so one product's flags cannot explain another product's status. Unsupported matches and conflicting statements within one candidate are `Undetermined`.

Candidate results can be `Yes`, `Qualified yes`, `No`, `Qualified no`, or `Undetermined`. The overall CVE can be `Mixed` when accepted candidates reach opposing conclusions. `No` requires a verifiable contradiction for an exact match; a symbol alone does not prove that vulnerable code remains. `Qualified no` represents disagreement that still needs qualification—for example, a vendor fix/backport claim that local version or symbol evidence cannot disprove. Absent or historical-only local evidence neither proves safety nor contradicts a statement about the final image.

CPE URI and 2.3 bindings are supported. A broader numeric version family may support a qualified fuzzy comparison, but is not an exact CPE match or a vendor-specific hierarchy. See the [CPE name-matching specification](https://csrc.nist.gov/Projects/Security-Content-Automation-Protocol/Specifications/cpe/name-matching) and [CSAF relationship definitions](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32123-relationships).

## Report detail

- Default output summarizes each CVE and its product candidates.
- `-v` adds matching inputs, evidence precision, unique modules and versions, and grouped `[CSAF MATCH CANDIDATES: <local product name>]` sections. Each candidate shows its product ID, match evidence, and agreement; accepted IDs differing from the candidate ID appear under `Matched product IDs`.
- `-vv` adds full PURLs and vendor statements, detailed checks, packages, and the `[LOCAL FINDINGS]` binary evidence table with locations, reachability explanations, and vendor matching evidence.
- `-vvv` adds exact symbols, binary history, and provenance.

Canonical URLs are collected from HTTPS `self` references using the CSAF tracking-ID filename convention. They appear in `comparison.json` as `canonical_urls` and in CVE headings at all verbosity levels; source paths remain in `source`. The `-vvv` provenance identifies each document by `tracking.current_release_date` and lists its canonical URLs. Multiple values are shown on separate lines.

The local-findings section links each CVE to binaries with recorded evidence. Reachability is `UNDETERMINED` unless the artifact is absent from the final image or consistent, exact image/product statements explicitly exclude the vulnerable execution path (`NO`). Presence, an affected status, or a symbol does not prove reachability (`YES`); the scanner cannot establish it. Verbose output explains the basis and distinguishes current paths from historical locations. Duplicate binary observations merge only when location, content, runtime disposition, and layer context agree. A local finding can coexist with vendor `known_not_affected`; the report preserves both without claiming runtime exploitability. Missing local findings are labeled as unrecorded in this audit.

## Batch triage

Batch and single-container reports use the same findings, identity, vendor-assessment, and agreement rules. A container is compared only against its recorded CVEs, so another image's advisory does not create a negative case.

Open `reports/pygo-audit-triage.csv` to review container/CVE pairs, sorted by descending highest CVSS score, then container, agreement priority, and CVE. Start with `No`, `Qualified no`, and `Mixed` under `AGREEMENT`, then review `Undetermined` cases for missing documents or unresolved identity. Per-container `reports/comparison.txt` contains candidate and binary evidence; `audit.json` retains the scan details. Qualified disagreement is not a verified contradiction, and vendor fix/backport claims can coexist with old embedded versions or surviving symbol names.

`reports/aggregate.txt` summarizes batch counts and discrepancy rates; `reports/cve-aggregates.txt` groups results by CVE; `reports/container-aggregates.txt` summarizes severity, vulnerable binaries, and product matches per container. Counts are container/CVE pairs, with unique batch CVEs reported separately; they do not measure detection accuracy. The original `audit.json` is the source for full binary evidence.

## Review a CVE

1. Confirm the image digest, platform, component, and binary path refer to the same subject.
2. Check scan coverage and operational diagnostics.
3. Review module path, found/fixed versions, and evidence in `reports/vulnerability-findings.txt`; use `reports/binary-findings.txt` for binary grouping and `reports/module-reconciliation.txt` for build/dependency comparisons.
4. Read the complete VEX status and flags. Determine whether the provider discusses Go code, native code, or a product-level condition outside the scan.
5. Refresh Go and vulnerability databases if evidence may be stale. Preserve unresolved disagreements in the report.

```console
./pygo-audit report audit/audit.json --view vulnerability-findings
./pygo-audit report audit/audit.json --view binary-findings -vvv --wide
./pygo-audit report audit/audit.json --view module-reconciliation -vvv --wide
./pygo-audit report audit/audit.json --view diagnostics
./pygo-audit csaf audit --csaf local-csaf/
```

## Evidence limits

`govulncheck` uses binary symbol information to narrow findings when possible and falls back to module-level precision otherwise. Its stable output does not promise a direct `.symtab`-available flag. Pygo reports the evidence actually emitted—module, package, or symbol—and uses `unspecified` when Go tools provide no reachability conclusion. A symbol finding means govulncheck observed a relevant symbol; a clean scan does not prove symbol information was available.

CGO is recorded per binary build. From `-vv`, the CSAF package table lists `BINARY CGO` as Enabled, Disabled, or Unknown for binaries carrying that package's findings. Missing or inconsistent settings are Unknown; multiple binaries may yield multiple settings, which does not attribute CGO use to the package. Individual settings also appear in binary evidence and forensic blocks.

`govulncheck` focuses on Go modules and call-graph reasoning. CGO may introduce native code through dynamic libraries, static archives, system headers, generated bindings, or vendored C/C++. Supplement CGO-heavy audits with an appropriate native/distribution scanner and an SBOM; check linking, runtime library paths, and the image package database. No Go CVE found does not mean no native vulnerability exists.

If layer directories are supplied, `runtime_disposition` indicates whether observed bytes are present in the final `rootfs/`, deleted or replaced, or unaccounted for. Treat this as context for scope and confidence—not as a substitute for the semantic comparison or a reason to erase a mismatch.
