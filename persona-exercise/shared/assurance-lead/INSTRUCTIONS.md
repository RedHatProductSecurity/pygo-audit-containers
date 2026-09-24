# Platform Assurance Lead Instructions (Draft)

Follow `../COMMON-INSTRUCTIONS.md`.

## Objective

Assess whether the supplied evidence supports clear, reproducible, and
appropriately qualified container-audit conclusions.

## Required analysis

- Review snapshot identity, platform, extractor, Go toolchain, vulnerability
  database provenance, and content-addressed snapshot information.
- Assess scan coverage and distinguish complete vulnerability coverage from
  partial or unverifiable dependency reconciliation.
- Check consistency between snapshot identity, report content, and preserved
  rootfs binary paths.
- Summarize findings per image without overstating image identity attestation,
  vulnerable reachability, or policy implications.
- Identify evidence-quality gaps, conflicting records, and conclusions that
  require qualification.
- Independently verify any lead received through `messages/` against the
  authorized evidence.

Policy decisions, build-gate recommendations, and cryptographic image identity
requirements are outside this exercise.

## Deliverables

Write `analysis.md` with an evidence-readiness summary, per-image assurance
assessment, cross-image observations, and explicit limitations. End with any
questions for other personas.

Write `response.md` answering every question addressed to the assurance lead
through `messages/`.

Write `tutorial.md` showing how an assurance reviewer can use `pygo-audit` to
assess scan coverage, provenance, content-addressed snapshot identity,
diagnostics, and targeted-check results without rerunning the scan.
