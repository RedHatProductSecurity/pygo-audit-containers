# Using pygo-audit as a Go Remediation Engineer

This tutorial starts from an existing pygo-audit snapshot. It does not extract an image,
rescan a rootfs, invoke govulncheck, or modify the shared snapshot collection.

Run the examples from the repository root. They use this supplied GitOps Operator
snapshot because it contains build metadata, CGO, vulnerability findings, effective
dependency replacements, and reconciliation limitations:

```bash
SNAPSHOT=persona-exercise/snapshots/store/29314403694c6ec4e24eff6ce0c8187040e1113356bd1135f8caa010296b17dd.json
```

All commands below omit `--output-dir`, so they render to the terminal without writing
artifacts. Do not use `pygo-audit scan` in this workflow.

## 1. Start with the container overview

```bash
./pygo-audit report overview "$SNAPSHOT"
```

This answers:

- How many Go binaries were identified?
- Did vulnerability scanning complete for all of them?
- Were vulnerabilities detected?
- How many binaries have CGO enabled?
- Is dependency reconciliation exact or partial?
- Which image reference, digest, platform, scanner version, and database timestamp belong
  to this result?

In this example, coverage is `COMPLETE (1 of 1 binaries)`, while reconciliation is
`PARTIAL`. Those states answer different questions: complete coverage means the binary
vulnerability scan completed; partial reconciliation means some dependency metadata
could not be matched exactly. Do not describe partial reconciliation as incomplete
vulnerability coverage.

The `PROVENANCE` Go toolchain is the toolchain that ran the audit. It is not necessarily
the Go version embedded in the audited binary.

## 2. Inspect each binary's Go build and dependency metadata

```bash
./pygo-audit report binaries "$SNAPSHOT"
```

For each binary, this report shows:

- complete container pathname and hash;
- main package and main module when available;
- embedded compiler version under `Compiled with`;
- `CGO: ENABLED` or `DISABLED`;
- vulnerability-scan status;
- declared dependencies and versions;
- replacement path/version when a dependency has replacement metadata; and
- findings grouped by package for that binary.

Interpret the fields carefully:

- `main module` unavailable is an absent evidence field, not proof of why the program was
  built that way.
- `CGO: ENABLED` does not invalidate the Go findings. It means native libraries require a
  separate audit.
- A declared module is not proof that every package in that module is linked or that a
  vulnerable function is reached at runtime.
- When a replacement exists, use the effective replacement component/version for
  remediation analysis; preserve the declared value as build intent.

## 3. Get a compact build-metadata view with JSON

`report json` prints the stored snapshot without rescanning. If `jq` is available, this
command extracts the fields a Go engineer usually needs first:

```bash
./pygo-audit report json "$SNAPSHOT" |
  jq '[.binaries[] | {
    path: .paths[0],
    go_version,
    main_package,
    main_module,
    cgo_enabled,
    build_settings
  }]'
```

For the example binary `/usr/local/bin/manager`, this reveals an embedded Red Hat Go
1.24.6 build, `CGO_ENABLED=1`, Linux/amd64, and `strictfipsruntime`. The `main_module`
field is `null`; do not infer a cause from that absence.

## 4. List declared and effective dependencies

The human-readable binary report is complete but can be long. This JSON view places the
declared and effective values side by side for every dependency:

```bash
./pygo-audit report json "$SNAPSHOT" |
  jq '[.binaries[] | {
    binary: .paths[0],
    dependencies: [.dependencies[] | {
      declared: {path, version},
      effective: (
        if .replace == null
        then {path, version}
        else {path: .replace.path, version: .replace.version}
        end
      ),
      replaced: (.replace != null)
    }]
  }]'
```

Use the declared value to explain what the build metadata requested. Use the effective
value to explain what was actually recorded after replacement.

## 5. Show only replacement records

```bash
./pygo-audit report json "$SNAPSHOT" |
  jq '[.binaries[] | {
    binary: .paths[0],
    replacements: [.dependencies[] |
      select(.replace != null) | {
        declared: {path, version},
        effective: {
          path: .replace.path,
          version: .replace.version
        }
      }
    ]
  }]'
```

This example includes material version changes such as:

```text
k8s.io/api@v0.33.2 -> k8s.io/api@v0.33.1
k8s.io/client-go@v12.0.0+incompatible -> k8s.io/client-go@v0.33.1
```

It also includes records whose declared and effective path/version strings are identical.
Describe those as recorded replacement metadata with no observed path/version change;
do not claim they represent different source content.

A local replacement such as `./api/v2@(devel)` identifies an effective local path, but
not an immutable revision. Its version remains unverifiable unless separate authorized
build provenance is supplied.

## 6. Review reconciliation diagnostics

```bash
./pygo-audit report diagnostics "$SNAPSHOT"
```

This separates operational scan problems from informational reconciliation limitations
and differences. In the example:

- `github.com/redhat-developer/gitops-operator@(devel)` is an unverifiable component;
- `stdlib@v1.24.6` and the decorated embedded Go 1.24.6 build string are identified as
  the same release represented differently; and
- the report explicitly says these limitations do not reduce vulnerability coverage.

Treat `(devel)` as version-unverifiable. Treat a standard-library representation
difference as a notation difference when diagnostics says it identifies the same Go
release. Do not silently normalize unrelated path or version mismatches.

## 7. Review findings by affected package

```bash
./pygo-audit report findings "$SNAPSHOT"
```

This report answers:

- Which package and module support each finding?
- What current version was found?
- Which binary path is affected?
- Is the evidence at module, package, or symbol level?

Evidence strength matters:

- **module**: the affected module/version was reported, but no vulnerable package or
  symbol was identified;
- **package**: the affected package was identified in the binary;
- **symbol**: vulnerable symbol evidence was identified in the binary.

Even symbol evidence from binary mode is not a runtime call trace. Report it as detected
binary evidence, not proof that an attacker can reach the code.

## 8. Check one or more assigned vulnerability identifiers

```bash
./pygo-audit check "$SNAPSHOT" \
  CVE-2026-46595 \
  CVE-2025-68121 \
  CVE-2026-41889 \
  CVE-2024-3094
```

This focused report avoids searching a large findings report manually. For each requested
identifier it shows:

- `DETECTED`, `NOT DETECTED IN THIS SNAPSHOT`, or an indeterminate result;
- scan coverage;
- affected package/module and current version when detected; and
- every affected binary pathname.

For this snapshot, CVE-2026-46595 is detected in
`golang.org/x/crypto/ssh` from `golang.org/x/crypto@v0.39.0`, and CVE-2025-68121 is
detected in `crypto/tls` from `stdlib@v1.24.6`; both affect
`/usr/local/bin/manager`. The other two identifiers are not detected in this snapshot.

Interpret a negative result precisely:

> No matching finding was detected in this snapshot with the displayed coverage and
> vulnerability-database state.

Do not translate it to “the image is not vulnerable,” “the module is absent,” or “all
native and non-Go components were checked.” If coverage is incomplete, identify the
failed or unscanned binaries before drawing even a snapshot-limited negative conclusion.

## 9. Compare dependency versions across several binaries

The Argo CD snapshot contains four Go binaries, making it useful for spotting version
drift:

```bash
ARGO_SNAPSHOT=persona-exercise/snapshots/store/3c8370f7cbec63890b77c2a8d702dbaf83e4c6ae1e4a3b89e9b386bc52dab949.json

./pygo-audit report json "$ARGO_SNAPSHOT" |
  jq '[.binaries[] | {
    binary: .paths[0],
    go_version,
    cgo_enabled,
    selected_dependencies: [.dependencies[] |
      select(
        .path == "golang.org/x/crypto" or
        .path == "golang.org/x/net" or
        .path == "golang.org/x/text" or
        .path == "google.golang.org/grpc"
      ) | {path, version, replace}
    ]
  }]'
```

This answers whether binaries in the same container embed the same versions. Do not
assume one container has one Go dependency graph: each Go binary carries its own build
metadata and may require a different remediation change.

## Read-only command summary

```bash
./pygo-audit report overview "$SNAPSHOT"
./pygo-audit report binaries "$SNAPSHOT"
./pygo-audit report diagnostics "$SNAPSHOT"
./pygo-audit report findings "$SNAPSHOT"
./pygo-audit report json "$SNAPSHOT"
./pygo-audit check "$SNAPSHOT" CVE-2026-46595
```

These commands reuse the stored snapshot. They do not rerun `go version -m` or
govulncheck, and they do not change the shared evidence.
