# Targeted Vulnerability Follow-up (Draft)

Do not provide this follow-up to the personas until every persona has submitted
its initial, organic `analysis.md` for all supplied containers.

For every supplied container, investigate each of these identifiers using only
the authorized snapshot and preserved rootfs evidence:

- `CVE-2026-46595`
- `CVE-2025-68121`
- `CVE-2026-41889`
- `CVE-2024-3094`

For every identifier-container pair:

1. Report one result: `detected`, `not detected in this snapshot`, or
   `indeterminate`.
2. State whether vulnerability-scan coverage is complete enough to support the
   result.
3. When detected, report every affected Go binary pathname, package or module,
   and current version recorded by the snapshot.
4. When not detected, do not claim that the container or binary is not
   vulnerable. Explain only what the supplied snapshot establishes.
5. When indeterminate, identify the exact coverage failure or missing evidence.
6. State whether rootfs inspection adds evidence relevant to the result.
7. Cite the exact snapshot and rootfs paths used.

After answering all identifier-container pairs, compare the results with the
persona's initial analysis:

- Which targeted results had already been discovered organically?
- Which were missed?
- Did any initial conclusion overstate a negative result or confuse module
  presence with a detected vulnerable package?
