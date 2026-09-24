# Persona Questionnaire (Draft)

Answer every question below for every supplied container. Base each answer only
on the authorized snapshot and rootfs evidence. Cite the exact snapshot and
rootfs paths used.

## Evidence and inventory

1. Which ELF files are identified as Go binaries, and what are their complete
   container pathnames?
2. What Go version, main module, and `CGO_ENABLED` state are recorded for each
   Go binary? Which values are unavailable?
3. Is vulnerability-scan coverage complete for every identified Go binary?
   What operational issues or coverage gaps are present?
4. Does each binary pathname reported in the snapshot exist in the preserved
   rootfs?

## Dependencies and vulnerabilities

5. Which vulnerabilities are detected, and which binary path, package or
   module, and current version support each finding?
6. Which dependencies or standard-library components recur across binaries?
   Where do versions differ within the same container?
7. Which declared dependencies have effective replacements? Report both the
   declared and effective component.
8. What dependency or finding records are partially reconciled, inconsistent,
   or unverifiable? Does that limitation affect vulnerability-scan coverage?
9. What findings are container-wide patterns, and which are isolated to one or
   only some binaries?

## Claims to evaluate

For each claim below, give a verdict of `confirmed`, `rejected`, or
`unverifiable` for the container and cite the evidence. These are hypotheses,
not facts.

10. Every ELF file in the rootfs is a Go binary.
11. Every Go binary in the container uses the same dependency versions.
12. Every vulnerability reported for the container affects every Go binary in
    that container.
13. A declared Go module proves that every package in that module is compiled
    into the binary.
14. If a vulnerability is not detected, its associated module or package is
    absent from the binary.
15. Partial dependency reconciliation means vulnerability-scan coverage is
    incomplete.
16. `CGO_ENABLED=true` invalidates the Go dependency and vulnerability
    findings.
17. The extracted runtime rootfs contains every file from every image layer.
18. Snapshot image metadata cryptographically proves that the preserved rootfs
    came from the identified image.

## Conclusions

19. What are the most important evidence-backed observations for this
    container from your assigned role's perspective?
20. What conclusions cannot safely be made from the supplied evidence?
