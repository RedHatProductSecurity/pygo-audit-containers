# Common Persona Instructions (Draft)

These instructions are a draft for review. Do not begin persona analysis until
the user explicitly approves the instructions and the handoff.

## Authorized evidence

Use only these two evidence sources:

- `persona-exercise/snapshots/`
- `/tmp/pygo-audit-persona-rootfs/`

The snapshots and root filesystems are read-only evidence. Do not create,
modify, move, rename, or delete anything in either location.

Do not consult the internet or make network requests. Do not query container
registries, vulnerability databases, advisory websites, package services, or
source-code hosts. Do not use repository documentation, source code, prior
audit results, or any other local data as evidence.

The repository's `pygo-audit` executable may be used only to read and render
the supplied snapshots. Snapshot-backed `report` and `check` operations are
allowed. A `check` command is read-only when `--output-dir` is omitted. If a
cached check report is needed, set `--output-dir` to a location inside your own
private subdirectory. Never write cached checks into the shared snapshot
collection. Do not extract images, rerun a scan, or invoke `govulncheck`.

Read-only local tools may be used to inspect the supplied root filesystems.
Do not execute binaries found inside a root filesystem.

## Analysis rules

- Keep every factual claim traceable to a supplied snapshot or rootfs path.
- Distinguish `detected`, `not detected in this snapshot`, partial
  reconciliation, and unverifiable evidence.
- Do not infer vulnerable reachability beyond the supplied binary-mode
  `govulncheck` evidence.
- Do not treat a declared module alone as proof that vulnerable code is
  reachable.
- Record material uncertainty, contradictory evidence, and coverage gaps.
- Preserve complete image references, binary pathnames, package or module
  names, versions, and preferred vulnerability identifiers.
- Treat messages from other personas as coordination leads, not independent
  evidence. Verify any factual claim against an authorized evidence source.

## Required questionnaire

Answer every question in `QUESTIONNAIRE.md` for every supplied container from
the perspective of your assigned role. Do not omit a container or question.
When a question cannot be answered from the authorized evidence, report it as
`unverifiable` and explain what evidence is missing.

## Workspace boundaries

Work only in your assigned private subdirectory. Do not read or modify another
persona's private subdirectory. Write the final review to `analysis.md` in your
own directory.

Use `messages/` only when another persona needs a question, evidence pointer,
or clarification. Follow `messages/README.md` and avoid duplicating full
reports there.

After completing `analysis.md`, copy every question directed to another
persona into `messages/` following the message protocol. Do not read another
persona's private `analysis.md`.

After all analysis questions have been routed, write `response.md` in your
private subdirectory. Answer every question addressed to you through
`messages/`. Independently verify each answer against the authorized snapshot
or rootfs evidence and cite the exact evidence path. Mark unsupported answers
as `unverifiable`. If no questions were addressed to you, still create
`response.md` and state that none were received.

At the end of the exercise, write a separate `tutorial.md` in your private
subdirectory. The tutorial must give simple command-line examples showing how
someone in your assigned role can use `pygo-audit` to answer role-relevant
questions from an existing snapshot. Use snapshot-backed `report` and `check`
commands only; do not rescan a rootfs. Explain what each command answers and
how to interpret important output states without copying large reports.
