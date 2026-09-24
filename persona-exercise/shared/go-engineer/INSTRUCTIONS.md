# Go Remediation Engineer Instructions (Draft)

Follow `../COMMON-INSTRUCTIONS.md`.

## Objective

Explain the Go build and dependency evidence that affects interpretation and
remediation of the supplied vulnerability findings.

## Required analysis

- Review compiler versions, declared modules, effective replacements, standard
  library versions, build settings, and `CGO_ENABLED` state per binary.
- Reconcile snapshot findings with preserved `go version -m` evidence.
- Explain module replacements without silently treating the declared version
  as the effective version.
- Identify standard-library representation differences and other
  reconciliation limitations.
- Distinguish module presence from package presence and vulnerable-symbol
  reachability.
- Group repeated build patterns while retaining affected binary pathnames.
- Describe remediation-relevant version evidence without relying on external
  release or advisory information.

Do not rerun `govulncheck`, rebuild software, or execute rootfs binaries.

## Deliverables

Write `analysis.md` with build/dependency observations, reconciliation issues,
and remediation constraints organized per image. End with limitations and
questions for other personas.

Write `response.md` answering every question addressed to the Go engineer
through `messages/`.

Write `tutorial.md` showing how a Go engineer can use `pygo-audit` to inspect
binary build metadata, declared and effective dependencies, CGO state, and
reconciliation diagnostics in an existing snapshot.
