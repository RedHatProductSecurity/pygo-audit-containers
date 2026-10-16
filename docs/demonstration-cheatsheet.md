# pygo-audit demonstration cheatsheet

## Before presenting

- Empty `sandbox/` except for `.gitignore`.
- Rehearse the exact image digest and `linux/amd64` platform.
- Choose one detected CVE and one negative-control CVE from that rehearsal.
- Keep `persona-experiment-1-results` available in a separate checkout.

```console
python3 --version
go version
command -v govulncheck
oc version --client
./pygo-audit --version
```

## Extract and scan once

```console
IMAGE=quay.io/prometheus/prometheus:latest
PLATFORM=linux/amd64
SNAPSHOTS=audit-snapshots/first-demo
ARTIFACTS=audit-artifacts/first-demo

oc image info --filter-by-os="$PLATFORM" "$IMAGE"
oc image extract "$IMAGE" \
    --filter-by-os="$PLATFORM" \
    --path="/:$PWD/sandbox" \
    --confirm \
    --only-files

./pygo-audit scan sandbox \
    --snapshot-dir "$SNAPSHOTS" \
    --output-dir "$ARTIFACTS" \
    --image-ref "$IMAGE" \
    --platform "$PLATFORM" \
    --extractor "oc image extract"
```

For the formal demonstration, replace `latest` with the rehearsed digest.

Say: “Every regular file is checked for ELF magic. `go version -m` confirms
the Go binaries, then `govulncheck -mode binary` examines each one. Everything
we show next comes from this single preserved scan.”

## Report commands

```console
# Container result, coverage, complete package/CVE lists
./pygo-audit report overview "$ARTIFACTS/audit.json"

# Findings organized for analyst questions
./pygo-audit report findings "$ARTIFACTS/audit.json" \
    --group-by vulnerability
./pygo-audit report findings "$ARTIFACTS/audit.json" \
    --group-by package

# Go version, CGO, main module, dependencies, replacements, binary paths
./pygo-audit report binaries "$ARTIFACTS/audit.json"

# Coverage failures and reconciliation differences
./pygo-audit report diagnostics "$ARTIFACTS/audit.json"
```

Point out:

- coverage = recognized Go binaries versus completed vulnerability scans;
- findings retain package, current version, and affected binary pathname;
- CGO does not invalidate Go findings; native libraries remain out of scope;
- reconciliation differences are not the same as incomplete scan coverage;
- provenance appears at the bottom so important findings remain first.

## Targeted CVE check

```console
DETECTED_ID=CVE-YYYY-NNNNN
CONTROL_ID=CVE-YYYY-NNNNN

./pygo-audit check "$ARTIFACTS/audit.json" \
    "$DETECTED_ID" "$CONTROL_ID" \
    --output-dir "$ARTIFACTS"
```

- `DETECTED`: matching binary-mode evidence exists; name every package,
  version, and binary path.
- `NOT DETECTED IN THIS SNAPSHOT`: complete coverage found no matching
  finding. Never shorten this to “not vulnerable.”
- `INDETERMINATE`: coverage cannot support a negative result.

Saved checks appear under `$ARTIFACTS/checks/`; no rescan occurs.

## Prove snapshot reuse

```console
./pygo-audit report overview "$SNAPSHOTS"
```

Say: “Report and check read the content-addressed snapshot. They do not inspect
binaries or contact the vulnerability database.”

## Scope phrases

- “This is the supplied final runtime rootfs, not deleted layer history.”
- “Binary-mode evidence does not prove runtime reachability or exploitability.”
- “A declared module does not prove every package in it was compiled.”
- “CGO-linked native dependencies require a separate scanner.”
- “Image identity is supplied provenance, not cryptographic attestation.”
- “Results are tied to this image, platform, toolchain, database state, and
  scan time.”
- “The content address identifies the report contents—not the image or
  vulnerability database.”

## If something fails

- **Manifest list:** use `--filter-by-os="$PLATFORM"` on both `oc` commands.
- **Nonempty sandbox:** stop; never mix extracted root filesystems.
- **Registry/database unavailable:** disclose the failure; never call an
  incomplete scan clean.
- **Artifact conflict:** use a new directory; existing differing evidence is
  intentionally not overwritten.
- **Live scan unavailable:** use a successful prerecorded snapshot:

```console
FALLBACK=/path/to/persona-results/persona-exercise/snapshots/dex-51454e5c706f/audit.json

./pygo-audit report overview "$FALLBACK"
./pygo-audit report findings "$FALLBACK" --group-by vulnerability
./pygo-audit report binaries "$FALLBACK"
```

State that fallback findings are prerecorded, not current.

## Close

“One scan gives us a preserved container result, affected package and binary
evidence, focused CVE answers, and role-specific reports without rerunning
govulncheck.”
