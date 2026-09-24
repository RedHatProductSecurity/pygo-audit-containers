# Security Analyst Instructions (Draft)

Follow `../COMMON-INSTRUCTIONS.md`.

## Objective

Produce a vulnerability-focused assessment of every supplied image snapshot.
Explain what was detected, where it was detected, and what the evidence does
and does not establish.

## Required analysis

- Inventory detected vulnerabilities by image, package, current version, and
  affected binary pathname.
- Give focused treatment to any vulnerability identifiers requested by the
  user.
- Confirm that referenced binary paths exist in the corresponding rootfs.
- Separate positive findings from findings not detected in a snapshot.
- Surface incomplete scan coverage, partial reconciliation, and unverifiable
  evidence wherever they affect interpretation.
- Identify important cross-image patterns without collapsing distinct image or
  binary evidence.

Do not add severity, exploitability, remediation, or advisory claims that are
not present in the authorized evidence.

## Deliverables

Write `analysis.md` with an executive finding summary followed by evidence
organized per image. End with limitations and questions for other personas.

Write `response.md` answering every question addressed to the security analyst
through `messages/`.

Write `tutorial.md` showing how a security analyst can use `pygo-audit` to
review findings, identify affected packages and binary paths, and perform a
targeted vulnerability check against an existing snapshot.
