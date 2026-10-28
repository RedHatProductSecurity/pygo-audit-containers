# An author’s note

Hello, future reader.

This repository started with a small question — “which Go vulnerabilities can
we see in these files?” — and then acquired image layers, caches, concurrent
workers, model design, CSAF semantics, and a suspicious amount of opinion
about filenames.

The restraint that keeps it useful is simple:

> Keep the scanner small, keep the evidence explicit, and let surrounding
> tools remain replaceable.

The project says containers because that is where the first users found the
problem. The interesting subject is really a filesystem. A root directory,
mounted tree, extracted archive, or build artifact can all be analyzed if it
meets the input contract.

## What is “a smell wearing a little hat”?

It is not a formal software-engineering term. A code smell is a warning sign:
something that may be harmless but suggests a design deserves inspection. The
little hat is just personality — a tiny flag on the warning so it does not
arrive wearing a necktie and pretending to be a theorem.

In this repository, a renderer rediscovering facts that belong in the model is
a smell wearing a little hat. It might be the right move in a one-line report,
but it is worth asking whether the model forgot to carry the evidence.

## Small opinions

- A filesystem is a subject, not a personality.
- A hash is an identity card, not a biography.
- A VEX flag is an explanation, not a magic spell.
- “Not detected” is not the same sentence as “not vulnerable.”
- Orthogonality is a feature: extraction, scanning, and comparison should not
  need to know each other’s favorite tools.
- A cache should be disposable, content-addressed, and honest about which
  facts belong to the bytes versus the current scan.
- If a report needs a 900-column terminal, it probably wants a CSV.

## The reachability confession

We investigated the `.symtab` question. `govulncheck` uses symbol information
internally and knows when it must fall back to module-level reporting, but its
stable JSON output does not expose a trustworthy table-present flag. So the
scanner no longer invents one by searching raw ELF bytes.

We keep the evidence the Go tool actually gives us — module, package, or symbol
level — and say `unspecified` when it gives us no reachability conclusion. It
is less flashy, more honest, and much easier to keep compatible with whatever
tool analysts choose next.

## Complaints department

The image ecosystem has several ways to say “this file is gone,” and at least
one of them is always hiding behind a directory detail. The scanner therefore
does not infer deletion from absence. If that feels overly cautious, excellent:
the caution is the feature.

The other recurring complaint is tool gravity. Once a repository learns one
image tool, it is tempting to make every analyst install it forever. Resist
that temptation. The library wants files and metadata. The scripts are useful
adapters, not citizenship tests.

## Suggestions for future caretakers

1. Keep dependencies minimal and current.
2. Keep extraction output boring and stable.
3. Keep the canonical model richer than every individual view.
4. Keep caches inside the working context unless a user explicitly requests a
   user-wide cache.
5. Keep tests that count subprocesses; performance is part of the user
   experience when there are thousands of binaries.
6. Keep the jokes, but never let a joke replace an evidence field.

If you add a new report, derive it from `audit.json` or the model. If you add a
new script, make it consume a stable contract. If you add a new status, write
down what evidence earns it and what evidence does not.

And if you find a bug, please leave a test behind. Future you is a very busy
engineer with suspiciously good memory and no recollection of writing this
code.

For the quieter hours, there is now a small [poetry shelf](poems.md).
