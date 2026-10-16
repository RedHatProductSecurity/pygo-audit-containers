# AI persona audit experiment

This experiment evaluates whether different analyst roles can reach clear,
appropriately qualified conclusions from the same pygo-audit evidence. It is
also a usability exercise: each persona must explain how it used the CLI and
where the reports were insufficient or easy to misinterpret.

The experiment is intentionally separate from pygo-audit's vulnerability
detection. Personas analyze stored results; they do not rescan containers or
add vulnerability intelligence.

## Versioned layout

The `persona-exercise` branch contains the complete experiment: the reusable
framework and the generated output from the first run:

```text
persona-exercise/
├── README.md
├── TARGETED-QUESTIONS.md
└── shared/
    ├── COMMON-INSTRUCTIONS.md
    ├── QUESTIONNAIRE.md
    ├── assurance-lead/INSTRUCTIONS.md
    ├── go-engineer/INSTRUCTIONS.md
    ├── security-analyst/INSTRUCTIONS.md
    └── messages/README.md
```

The generated material includes:

- five successful content-addressed scan snapshots and portable report bundles;
- one retained Argo CD scan that failed because the vulnerability database was
  unreachable;
- each persona's `analysis.md`, `response.md`, `targeted.md`, and
  `tutorial.md`;
- ten inter-persona questions with evidence pointers.

This branch is deliberately separate because its evidence bundle is large and
represents a point-in-time experiment, not product source.

## Evidence boundary

Personas may consult only:

- the supplied directory under `persona-exercise/snapshots/`;
- the preserved runtime root filesystems under
  `/tmp/pygo-audit-persona-rootfs/`.

They must not use the internet, container registries, advisory sites, source
repositories, earlier audits, or repository documentation as evidence. They
may run pygo-audit `report` and `check` against stored snapshots, but must
not run `scan`, invoke `govulncheck`, or execute a binary from a rootfs.

Messages from another persona are investigation leads, not evidence. Every
claim must be checked against an authorized snapshot or rootfs and cite its
path.

The preserved root filesystems are temporary local data and are not committed
to Git. Consequently, the results branch preserves snapshot-backed conclusions
and the persona record, but a later reviewer cannot repeat rootfs comparisons
unless equivalent extracted roots are supplied again.

## Roles

The security analyst focuses on vulnerability, package, version, and affected
binary evidence.

The Go remediation engineer focuses on build metadata, dependency versions,
replacements, standard-library representation, CGO, and reconciliation.

The platform assurance lead focuses on coverage, provenance, consistency,
reproducibility, and limits on what the evidence proves.

All three roles answer the same questionnaire for every container. This makes
differences in interpretation visible without forcing the roles into the same
report structure.

## Exercise sequence

1. Generate all shared pygo-audit snapshots before assigning persona work.
2. Preserve the corresponding runtime root filesystems outside Git.
3. Give every persona the common instructions, questionnaire, and its role
   brief.
4. Have each persona independently write `analysis.md`.
5. Route cross-role questions through `shared/messages/`.
6. Have recipients independently verify and answer every message in
   `response.md`.
7. Reveal `TARGETED-QUESTIONS.md` only after the organic analyses are
   complete, then write `targeted.md`.
8. Finish with a role-specific `tutorial.md` showing how to answer practical
   questions from the command line without rescanning.

The targeted phase includes both identifiers known to be detected and red
herrings. This tests whether a persona overstates module presence, negative
results, or unsupported native-component conclusions.

## Collaboration protocol

Personas are allowed and encouraged to collaborate through
`shared/messages/`. They may ask for interpretation, request a cross-check,
or challenge a conclusion. They do not read or edit another persona's private
deliverables.

Each message names the sender, recipient, question, and exact evidence path.
Recipients verify the question independently and answer it in their own
`response.md`. This preserves both collaboration and an auditable boundary
between a lead and supporting evidence.

## Reviewing the first results

Fetch and check out the complete experiment branch:

```console
git fetch origin persona-exercise
git switch persona-exercise
```

Begin with `persona-exercise/snapshots/INDEX.md`, then compare each role's
`analysis.md`, `response.md`, `targeted.md`, and `tutorial.md`. Review
the messages between the independent analysis and response phases.

Treat every result as bound to the recorded image, platform, Go toolchain,
govulncheck version, vulnerability database state, and scan time. The branch is
an experiment record, not a claim about the current vulnerability state of an
image tag.
