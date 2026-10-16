# Assurance reviewer tutorial: examining a retained pygo-audit snapshot

This tutorial starts from an existing snapshot. It does not extract an image,
scan a root filesystem, invoke `go` or `govulncheck`, contact a vulnerability
database, or modify the shared evidence.

Run the examples from the repository root. Select the retained Argo CD
content-addressed snapshot:

```bash
SNAPSHOT='persona-exercise/snapshots/argocd-deda478bd4d8/audit.json'
```

Do not add `--output-dir` to these commands. Without it, `report` and `check`
only render the stored evidence to the terminal.

## 1. Establish result state and scan coverage

```bash
./pygo-audit report overview "$SNAPSHOT"
```

Start with the `RESULT` section:

- `Status` summarizes the retained snapshot; it is not a fresh database query.
- `Coverage: COMPLETE (4 of 4 binaries)` means every Go binary identified in
  this snapshot completed binary-mode vulnerability scanning.
- `VULNERABILITIES DETECTED` means findings exist. It does not establish
  runtime reachability or exploitability.
- `Reconciliation: PARTIAL` is a separate dependency-correlation state. In
  this example, complete vulnerability coverage and partial reconciliation
  coexist.
- `CGO enabled: 4` means native-code dependency and vulnerability coverage is
  outside this Go audit; it does not invalidate the Go findings.

Near the bottom, review `SUBJECT` and `PROVENANCE`. For this snapshot they
record the source image identity, resolved manifest digest, `linux/amd64`
platform, scanner and Go toolchain versions, scan time, database URL, and
database update observation.

Important qualification: those identity fields record what the scan says its
subject was. They do not cryptographically bind the complete preserved rootfs
to the OCI manifest.

## 2. Inspect provenance without losing the full image reference

Human-readable reports shorten very long values for terminal readability. The
complete machine-readable identity is near the beginning of the JSON view:

```bash
./pygo-audit report json "$SNAPSHOT" | sed -n '1,45p'
```

Use this to preserve the complete `subject.image.reference`, resolved
`subject.image.digest`, platform, extractor, schema version, producer, and scan
timestamps. The full JSON can be very large because it retains detailed
findings and advisory records.

Recorded provenance supports reproducibility of the report from this
snapshot. It does not establish:

- that the vulnerability database is still current;
- authenticity of the snapshot or its signer;
- a whole-rootfs digest;
- historical image-layer contents; or
- runtime reachability of vulnerable code.

## 3. Check the content-addressed snapshot identity

The current CLI has no separate `verify` subcommand. A targeted check prints
the snapshot's semantic SHA-256 in `SCAN CONTEXT`:

```bash
./pygo-audit check "$SNAPSHOT" CVE-2024-3094 |
  sed -n '/SCAN CONTEXT/,$p'
```

For this file, the output contains:

```text
Snapshot SHA-256:       3c8370f7cbec63890b77c2a8d702dbaf83e4c6ae1e4a3b89e9b386bc52dab949
```

That value should match the store filename without `.json`. The following
read-only shell check performs the comparison:

```bash
EXPECTED="${SNAPSHOT##*/}"
EXPECTED="${EXPECTED%.json}"
ACTUAL="$(
  ./pygo-audit check "$SNAPSHOT" CVE-2024-3094 |
    sed -n 's/^Snapshot SHA-256:[[:space:]]*//p'
)"

if [ "$ACTUAL" = "$EXPECTED" ]; then
  echo 'semantic snapshot digest matches content-addressed filename'
else
  echo 'snapshot digest mismatch' >&2
  exit 1
fi
```

Interpret this narrowly:

- It checks the semantic snapshot content address shown by pygo-audit against
  the filename.
- It is not a raw byte-for-byte file checksum; formatting a JSON document can
  change its raw file hash without changing its semantic content address.
- A matching digest detects accidental content/name disagreement, but is not a
  digital signature and does not establish who created the snapshot.
- It does not bind unreported rootfs files or the complete rootfs to the image
  manifest.

For a portable bundle named `audit.json`, there is no digest in the filename.
Use `SCAN CONTEXT` to record its semantic digest, then compare it with the
retained content-addressed store entry when both are available.

## 4. Separate diagnostics from vulnerability coverage

```bash
./pygo-audit report diagnostics "$SNAPSHOT"
```

The Argo CD example reports:

- complete vulnerability coverage for 4 of 4 binaries;
- partial reconciliation for 4 of 4 binaries;
- eight version-unverifiable components; and
- one grouped standard-library representation difference.

Read the `Effect` field. Here, reconciliation limitations are explicitly
informational and do not reduce vulnerability coverage. They still matter to
assurance: a local or `(devel)` component cannot support an exact-version
inventory or a version-based remediation claim.

If diagnostics instead show a scan timeout, failed command, invalid output, or
another operational issue, treat potentially missing findings as a coverage
limitation. Do not describe an incomplete result as clean.

## 5. Review findings with binary evidence

Group findings by vulnerability when the review begins from an identifier:

```bash
./pygo-audit report findings "$SNAPSHOT" --group-by vulnerability
```

This view connects preferred identifiers to affected packages, modules,
current versions, evidence levels, and complete binary paths. Other supported
organizations are useful for different questions:

```bash
./pygo-audit report findings "$SNAPSHOT" --group-by package
./pygo-audit report findings "$SNAPSHOT" --group-by binary
./pygo-audit report findings "$SNAPSHOT" --group-by container
```

Interpret evidence levels carefully:

- Module evidence is broader than package or symbol evidence.
- Package or symbol presence in a binary is evidence of compiled content, not
  proof that an execution path can reach it.
- A declared dependency by itself is not a vulnerability finding and does not
  prove that every package in that module was compiled.

## 6. Inspect individual binary inventory and native-code scope

```bash
./pygo-audit report binaries "$SNAPSHOT"
```

Use this report to review each complete binary pathname, compiled Go version,
main package/module when available, CGO state, vulnerability status, declared
dependencies, versions, and replacements. The human report displays a binary
SHA-256 suffix; the complete digest remains in the JSON snapshot.

For assurance review, distinguish these statements:

- “The snapshot reports this module/version for this binary” is an inventory
  statement.
- “The snapshot contains a finding for this package or symbol” is a
  vulnerability-evidence statement.
- “The vulnerable code is reachable or exploitable” is not established by
  these binary-mode records.

## 7. Answer targeted vulnerability questions

Check several identifiers in one read-only command:

```bash
./pygo-audit check "$SNAPSHOT" \
  CVE-2026-46595 \
  CVE-2025-68121 \
  CVE-2024-3094
```

In this retained Argo CD snapshot:

- `CVE-2026-46595` is `DETECTED` in package
  `golang.org/x/crypto/ssh`, affecting `/usr/local/bin/git-lfs` at
  `golang.org/x/crypto@v0.36.0` and `/usr/local/bin/helm` at
  `golang.org/x/crypto@v0.45.0`.
- `CVE-2025-68121` is `NOT DETECTED IN THIS SNAPSHOT` with complete 4/4
  coverage.
- `CVE-2024-3094` is `NOT DETECTED IN THIS SNAPSHOT` with complete 4/4
  coverage.

Use the exact status language:

- **Detected:** a matching finding exists. Report its binary, package/module,
  version, and evidence level; do not claim exploitability.
- **Not detected in this snapshot:** no matching finding exists and coverage
  is complete. Do not shorten this to “not vulnerable,” and do not infer that
  an associated module or package is absent.
- **Indeterminate:** coverage is incomplete, so absence of a matching finding
  cannot support a negative result. Report the exact failed or missing scan.

The `SCAN CONTEXT` footer ties the answer to the snapshot digest, subject,
toolchain, scan time, and recorded database state. Retain that context whenever
communicating a targeted result.

## 8. Compare all retained snapshots quickly

This loop prints only the leading result section for each stored snapshot and
does not write anything:

```bash
for SNAPSHOT in persona-exercise/snapshots/*/audit.json; do
  echo
  echo "=== ${SNAPSHOT##*/} ==="
  ./pygo-audit report overview "$SNAPSHOT" | sed -n '1,18p'
done
```

Use this as triage, then run `diagnostics`, `findings`, `binaries`, or `check`
against the selected snapshot. Do not compare vulnerability counts as though
they were severity or exploitability scores.

## Assurance handoff checklist

Before accepting a snapshot-backed conclusion, record:

1. the exact snapshot path and semantic digest;
2. source image reference, resolved manifest digest, platform, and extractor;
3. scan completion time, scanner/toolchain versions, and database observation;
4. complete versus incomplete vulnerability coverage;
5. reconciliation limitations separately from scan coverage;
6. affected binary paths, package/module, current version, and evidence level;
7. CGO/native-code and runtime-reachability limitations; and
8. whether the conclusion is `detected`, `not detected in this snapshot`, or
   `indeterminate`.

Snapshot-backed rendering is reproducible, but the snapshot is historical.
Nothing in these commands refreshes it against a newer database or proves the
complete rootfs came from the recorded image.
