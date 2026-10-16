# First pygo-audit demonstration

This outline presents the proof of concept as an analyst workflow: extract one
runtime root filesystem, scan it once, preserve the evidence, and answer
different questions from the stored snapshot without rerunning
`govulncheck`.

Keep the [demonstration cheatsheet](demonstration-cheatsheet.md) open during
the presentation for commands, talking points, and recovery guidance.

## Audience and outcome

The primary audience is a mixed group of vulnerability analysts, Go engineers,
and platform assurance reviewers. In roughly 15 minutes, the demonstration
should establish that pygo-audit can:

- find Go binaries anywhere in an unpacked container root filesystem;
- retain Go compiler, CGO, module, replacement, and dependency evidence;
- associate vulnerability findings with package and binary pathnames;
- distinguish complete coverage from reconciliation limitations;
- give explicit, snapshot-scoped answers for targeted vulnerability checks;
- render several reports from one immutable scan snapshot.

## Before the demonstration

Prepare the host before presenting:

1. Use Linux with `/proc` mounted.
2. Confirm Python 3.14 or newer, Go, `govulncheck`, and `oc` are available.
3. Confirm registry access for the chosen image and network access to the
   vulnerability database.
4. Start with an empty `sandbox/` other than its tracked `.gitignore`.
5. Rehearse with the same image digest and platform.
6. From the rehearsal snapshot, select one detected vulnerability and one
   identifier that produces `NOT DETECTED IN THIS SNAPSHOT`. Do not assume a
   historical result will remain unchanged after the database or image changes.
7. Keep a separately checked-out copy of the
   `persona-experiment-1-results` branch as a read-only fallback.

Suggested environment check:

```console
python3 --version
go version
command -v govulncheck
oc version --client
./pygo-audit --version
```

The scan context records the exact Go scanner version and vulnerability
database provenance actually observed during the audit.

## Demonstration flow

### 1. Frame the scope — 1 minute

Explain that pygo-audit examines the final, merged runtime filesystem supplied
by an extraction tool. It does not execute container binaries, scan historical
deleted layers, assess native libraries, prove runtime exploitability, or
cryptographically attest image identity.

The image reference, platform, and extractor are recorded as supplied
provenance. They are not inferred from the extracted files.

### 2. Inspect and extract one image — 2 minutes

Use a fixed platform so a multi-architecture manifest list is unambiguous:

```console
IMAGE=quay.io/prometheus/prometheus:latest
PLATFORM=linux/amd64

oc image info --filter-by-os="$PLATFORM" "$IMAGE"
oc image extract "$IMAGE" \
    --filter-by-os="$PLATFORM" \
    --path="/:$PWD/sandbox" \
    --confirm \
    --only-files
```

For a repeatable formal demonstration, replace `latest` with the digest
rehearsed beforehand. If the resolved manifest digest is known, also pass it to
the scan with `--image-digest`.

### 3. Scan once and preserve both forms of evidence — 4 minutes

```console
./pygo-audit scan sandbox \
    --snapshot-dir audit-snapshots/first-demo \
    --output-dir audit-artifacts/first-demo \
    --image-ref "$IMAGE" \
    --platform "$PLATFORM" \
    --extractor "oc image extract"
```

Point out the two complementary outputs:

- `audit-snapshots/first-demo/DIGEST.json` is content-addressed immutable scan
  IR;
- `audit-artifacts/first-demo/` is a portable bundle containing
  `audit.json` and the human-readable reports.

The snapshot includes scan time, binary hashes, tool versions, vulnerability
database provenance, image metadata, coverage, dependencies, findings, and
diagnostics. Its digest identifies all of that content; it is not an image
digest or vulnerability-database digest.

### 4. Lead with the container overview — 1 minute

```console
./pygo-audit report overview audit-artifacts/first-demo/audit.json
```

Call out:

- overall result;
- recognized and vulnerability-scanned Go binary counts;
- package and vulnerability totals;
- any diagnostic count;
- scan, database, and image context at the bottom.

### 5. Move from container findings to binary evidence — 3 minutes

Show container-level findings organized for two different questions:

```console
./pygo-audit report findings \
    audit-artifacts/first-demo/audit.json \
    --group-by vulnerability

./pygo-audit report findings \
    audit-artifacts/first-demo/audit.json \
    --group-by package
```

Then show the binary report:

```console
./pygo-audit report binaries audit-artifacts/first-demo/audit.json
```

Emphasize the complete container pathname, Go version, main module,
`CGO_ENABLED` state, declared dependency version, replacement data, and the
finding-to-binary relationship. A declared module is dependency evidence; it
does not mean every package in that module was compiled into the binary.

### 6. Separate diagnostics from vulnerability coverage — 1 minute

```console
./pygo-audit report diagnostics audit-artifacts/first-demo/audit.json
```

Explain the difference between:

- an operational failure that makes vulnerability coverage incomplete;
- a partial or unverifiable reconciliation record;
- an informational difference between `go version -m` and
  `govulncheck`.

Only the first prevents a complete negative targeted result.

### 7. Answer a focused analyst question — 2 minutes

Use the two identifiers selected during rehearsal:

```console
DETECTED_ID=CVE-YYYY-NNNNN
CONTROL_ID=CVE-YYYY-NNNNN

./pygo-audit check audit-artifacts/first-demo/audit.json \
    "$DETECTED_ID" "$CONTROL_ID" \
    --output-dir audit-artifacts/first-demo
```

Interpret each possible result precisely:

- `DETECTED` means the snapshot contains matching binary-mode finding
  evidence and lists the affected packages and binaries.
- `NOT DETECTED IN THIS SNAPSHOT` is a qualified negative supported by
  complete vulnerability-scan coverage. It does not prove the container is
  immune or that a related native component is absent.
- `INDETERMINATE` means coverage was insufficient for a negative result.

The command adds `checks/ID.txt` files without regenerating the base reports
or rerunning `govulncheck`.

### 8. Prove the snapshot is reusable — 1 minute

Rerender a report directly from the snapshot store:

```console
./pygo-audit report overview audit-snapshots/first-demo
```

Because the directory contains one digest-named snapshot, pygo-audit selects
and verifies it. No Go binary inspection or vulnerability database query
occurs during `report` or `check`.

## Questions to invite

- How are Go binaries distinguished from other ELF files?
- What does `go version -m` establish that `govulncheck` does not?
- Why can module, package, and standard-library versions differ by binary?
- What does partial reconciliation mean for confidence in the findings?
- What remains outside coverage when `CGO_ENABLED=true`?
- Why are negative checks tied to one snapshot and its database provenance?
- Which additional evidence would be required to prove runtime reachability or
  extracted-rootfs image identity?

## Fallback plan

If image extraction, registry access, or the vulnerability database is
unavailable, stop the live scan and disclose the failure. Use one successful
snapshot bundle from the `persona-experiment-1-results` branch to demonstrate
`report` and `check` offline. Do not present the recorded findings as a
current scan.

The branch also retains the first Argo CD DNS-failure bundle, which can
demonstrate why incomplete coverage is not reported as clean.

## Success criteria

The demonstration is successful when the audience can identify:

- which container filesystem and platform were examined;
- how many Go binaries completed vulnerability scanning;
- which package and binary path support a positive finding;
- why a negative result is phrased as snapshot-scoped;
- where CGO and reconciliation limitations are disclosed;
- how the same preserved scan answers several questions without rescanning.
