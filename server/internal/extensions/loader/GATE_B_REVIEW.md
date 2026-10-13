# Gate B complete-loader qualification

Qualification is pending. The isolated Task 5 candidate is based on `e315f6467207a22944253bb633b339e11583c95f` in worktree `extension-load`. Task 4's reviewed candidate is `978151022617a6792992a6ddd6910b607f99b702`. The primary agent owns final source/head identity, exact-head CI evidence and independent review. This artifact records no implementer-supplied approval.

The [complete-loader audit](ALLOCATION_AUDIT.md) establishes the unchanged YAML pre-allocation families and identifies remaining full-load inequalities for zstd scratch/output, JSON tokens, repeated validator serialization, helper objects and cross-host stacks. Those source proof obligations block Gate B acceptance even though finite measurements pass. Source investigation also identified excessive native-map directory growth in manifest validation and unbounded reader-error formatting in archive reads; both require reviewed remediation before qualification.

## Available local evidence

Go 1.27.1 Linux amd64 focused observation tests pass after missing-API and behavioral RED failures. The three fuzz targets' seeds pass. The finite serial smoke harness records all three cold modes, plus normal-scheduling/normal-GC serial and concurrent two-call peaks. Focused accounting tests, ordinary loader tests, the manifest/DSSE/loader integration test, formatting and vet pass locally. Native CI artifacts and independent review remain pending.

Combined and assembled YAML compare raw bytes/objects with their own same-call snapshots and the unchanged 64 MiB/1,000,000-object/8 MiB stack ceilings. Pre-YAML failures require zero calls; reached YAML requires one. Direct exported Load uses production dependencies and its separate `4*C + 4*T + 128 MiB` envelope. Normal-GC two-call evidence includes post-measurement GC and cross-call ownership mutations. No sample is discarded, retried, baseline-subtracted or excused by fixed runtime slack.

The parent constructs signed archives, exact golden inputs and expected outcomes outside fresh children. Independent scanner/Node comparison runs before parent candidate trials, with the pinned Node oracle and reviewed reference classifier; no oracle/candidate warmup occurs in measured child setup. Corpus success/failure recipes include full-capacity manifests, comments, structural limits, map transitions/guard, source-order defects and adjacent pipeline defects. Extended recipes add compressed/tar/role/file/member limits and dense envelope failures.

## Required evidence still pending

- Independent source-bound resolution and review of every open inequality in ALLOCATION_AUDIT.md, including finite full-object/full-stack bounds.
- Renewed Gate A source/API/provenance approval for the accounted entry and complete three-host native loader-gate-a runs with all 50 repetitions.
- Native Gate B extended runs on Linux x64, Windows x64 and macOS ARM64, retaining every raw metric, failure, serial/two-call peak and native resident-memory result.
- Server race CI and all three anchored 60-second/two-worker loader fuzz targets, retaining failure corpora.
- Exact-head successful required CI aggregation, all six native loader receipts, all 23 main fuzz leaves and live CI omission controls owned by the primary/CI worker.
- Independent code_reviewer Gate B review with an adversarial pass and fix confirmation against the final source/head and retained native artifacts.

Old Gate A evidence remains scoped to its qualified candidate. No Linux measurement claims Windows/macOS support. Neither this artifact nor the exported candidate API authorizes a production consumer; key admission and stateful admission are separate gates.
