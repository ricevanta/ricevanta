# Gate B complete-loader qualification

Gate B is qualified for the Go source at `a19cc54e4748ff0c26379d634c3cb3f3581394ce` on Linux x64, Windows x64 and macOS ARM64. Independent implementation/adversarial, complete source/native and qualification-evidence reviews have no unresolved findings. The primary confirms their exact source hashes and required CI evidence. [Gate A](GATE_A_REVIEW.md) remains qualified for the accounted parser.

The loader returns authenticated package evidence. Current publisher authorization, revocation, id-prefix authority and fenced stateful admission remain caller prerequisites. This qualification introduces no production consumer.

## Source and native proof

The [complete allocation audit](ALLOCATION_AUDIT.md) covers every success and rejection branch, all allocating helper families, pinned pool/cache retention, a conservative finite object inventory and native stack growth. Exact-length sorted membership prevents unbounded map-directory growth. Reader errors preserve the cause without formatting caller text. Recursive field validation precedes structural encoding, so invalid children and incomplete ancestors cannot trigger unchecked serialization.

The field-rejecting branch uses shape-conditioned YAML plus field-valid encoded prefixes, leaving 6,355,875 bytes under the unchanged envelope. All reached scratch, valid partial descendants, arbitrary object visitation orders, inherited encoder initializers and abandoned growth remain charged. Completed and late-failure branches retain their separate source domains. Cold allocation regressions fail with the encode-first mutation and pass with the implemented order; they do not claim an observed complete-loader overflow.

[Native diagnosis 38362276804](https://github.com/ricevanta/ricevanta/actions/runs/38362276804) builds diagnostic head `b825cb538bfcfb3f0feecfce6eadc134ee53d8ba` after verifying its server tree against candidate `a19cc54`. All three jobs pass. Independent extraction binds 78 selected repository source hashes and 14 manifest inputs per host, all six binary identities, active Go 1.27.1 sources, descriptor caches, escape decisions and linked stack records. The audit records exact hashes and formulas. Diagnosis supplies compiler evidence; required PR CI supplies execution evidence.

## Required CI and raw measurements

[CI run 38362466507](https://github.com/ricevanta/ricevanta/actions/runs/38362466507), attempt one, passes all 49 jobs for source `a19cc54`, tested integration SHA `ded2b717aeb7ecfe3e4f2943132c6564e07b2413`. Independent review and the primary verify all 46 exact same-run receipts, including six native Gate A/B leaves, all 23 main fuzz leaves, server race, Gitleaks and Semgrep Code/Supply Chain.

Every Gate B host retains 366 combined, 366 assembled and 366 direct-full intervals, plus 16 serial and 16 two-call intervals. All 3,390 records pass. The separate Gate A artifacts retain all 2,598 records, including 50 fresh-child repetitions per host.

Each YAML interval satisfies its own same-call ledger and the 64 MiB, 1,000,000-object and 8 MiB stack ceilings. Every direct full call satisfies `4*C + 4*T + 128 MiB`. Raw counters include runtime/helper work. No warmup, retry, sample selection, subtraction or allowance is used. Native resident-memory observations are present on all three hosts. Normal-GC serial/two-call runs preserve independent results, apply cross-call ownership mutations after measurement and retain their raw peaks.

Loader race completes in 690.194 seconds, and the race job completes in 732 seconds under the unchanged 15-minute package and 20-minute job deadlines. Detector defaults and complete server coverage remain intact. All required fuzz logs show positive execution with the anchored 60-second/two-worker commands. Local focused/integration tests, vet, formatting and contract checks pass; race, timed fuzzing and extended native qualification run only in CI.

Live negative controls for a missing native row and a missing fuzz target make required aggregation fail in [run 38343100201](https://github.com/ricevanta/ricevanta/actions/runs/38343100201) and [run 38343538349](https://github.com/ricevanta/ricevanta/actions/runs/38343538349). They establish rejection of incomplete CI evidence and are not passing qualification runs.

## Review and renewal

Independent review approves the authenticated pipeline, bounded membership/read errors, field-order regression, measurement/accounting interfaces and CI controls, including the adversarial pass. Separate source review confirms the complete branch inequalities and current native binding; separate qualification review confirms every raw record, receipt and execution log. Complete source/native handoff SHA256 is `c2ff5d27e39330ae4e31c6c5539b63b05265e2c4d89260ec705432af96149b19`; current-source CI and Gate A confirmation SHA256 is `c978f68c26e876e99edab2fff8fc5bc30921ca0a3126f75210e90b57a75cf325`. The audit retains the underlying frozen review identities and evidence provenance.

Each landing head requires successful current-integration CI and eligible final review. Source, compiler, dependency, experiment, linkage or measurement changes require renewal of affected evidence. Finite measurements and isolated pool/stack bounds do not establish an arbitrary concurrent handler budget. Production adoption must specify its resource context and stateful admission contracts.
