# YAML adaptation provenance

The Gate A candidate adapts `go.yaml.in/yaml/v3` v3.0.4 from the verified local module cache. Local finite qualification passes; native CI and independent implementation/source review remain required. No production consumer may use the candidate.

Module checksum: `h1:tfq32ie2Jv2UxXFdLJdh3jXuOzWiL1fo0bu/FbuKpbc=`.

Module metadata checksum: `h1:DhzuOOF2ATzADvBadXxruRBLzYTpT36CKvDb3+aBEFg=`.

Upstream source: <https://github.com/yaml/go-yaml/tree/v3.0.4>. `LICENSE` preserves MIT and Apache-2.0 terms. `NOTICE` preserves Canonical's Apache notice. Copied Go files retain their upstream headers. The same notices cover the test-only oracle copies two directories above this file.

## Source inventory

Checksums in the upstream column identify complete pinned source files. The ranges identify the selected Node/resolver source. Existing scanner/support diffs use complete files and show removed portions. `apic.go` retains parser support from upstream lines 1-103; `yamlh.go` retains support/event/parser declarations from lines 1-335 and 435-653. No emitter or reflection decoder enters the candidate.

| Adapted path | Source/range | Upstream SHA-256 | Adapted SHA-256 |
|---|---|---|---|
| `apic.go` | all | `0ba66e8a481340e9b9e1719efef7a2026736b53b07d369d6b140328f1d8f4b07` | `b1adf129769594cc119b9fd52049a3a1d1ad0a6239b281371e8f246ec597fcad` |
| `readerc.go` | all | `ad43815c77785337e2f980aa8e28d1ac89a25d1642187039aa1f451328a58527` | `7d8591969324c7498b453d71988c9ecbc87dfcca6b37b02dcbe893a93a7dd855` |
| `scannerc.go` | all | `a850fdd79a89f1475c7db3b685af057001ad871390770bf1c90aa808955df084` | `9e9b4e872a3888d3d4e603c352d7d40337e68d639075895830c186269205b79e` |
| `parserc.go` | all | `917227ca67ac2cfec193c6962cc5862244f92a67b7e53ec7ffa3a3729d477077` | `e79db78c5e43aa1b02498d9ca56f99edb6b88428d26071e00631fb71c60fb323` |
| `yamlh.go` | all | `6a8105eedd934f55399d786feb6acfd5c13b4cae4a80e58c0fff7a300921e06f` | `d4b8584cd3b8ebce5ec62ba07ec29570d48ed6a8741df0d32cad9caf05d6aadc` |
| `yamlprivateh.go` | all | `4e2195c00895d14965430b8326595e287ed23a7923ea3a7d43cfa95d0d359958` | `61ac7a4c7d26c4b678fbd5a704c101f7611789cf1a25fe6ac162dba5c763a863` |
| `LICENSE` | all | `d18f6323b71b0b768bb5e9616e36da390fbd39369a81807cca352de4e4e6aa0b` | `d18f6323b71b0b768bb5e9616e36da390fbd39369a81807cca352de4e4e6aa0b` |
| `NOTICE` | all | `f6c2dd3a67b576eafb89b80200b8b1627230bf3821a0c14cb99a22ac19107d00` | `f6c2dd3a67b576eafb89b80200b8b1627230bf3821a0c14cb99a22ac19107d00` |
| `node.go` | decode.go: 1-15, 31-308 | `5531e688b99fa695342c41f3a41d0376e10b64bca635da1156b61bd53a2485da` | `e9dd82b52d810ea7194c1d2b53df15584eb4e235355e3e7a27fcd8bdd75b004d` |
| `resolve.go` | resolve.go: 1-267, 290-326 | `69b6069012fef0a518e379222007f6ea7622cb1c235a35b1355bb5641ab16d26` | `452bce29fde12a2f0d0262f1a934160bb97a21ba0c5cca745305a048c3ad92cb` |
| `../../oracle_apic_test.go` | apic.go (apic: 1-103; others: all) | `0ba66e8a481340e9b9e1719efef7a2026736b53b07d369d6b140328f1d8f4b07` | `d5f85b88dd68f4fbc55c4ea1d43619e088ac3cc59495387ea414c9da5d39b499` |
| `../../oracle_readerc_test.go` | readerc.go (apic: 1-103; others: all) | `ad43815c77785337e2f980aa8e28d1ac89a25d1642187039aa1f451328a58527` | `7662876bf4f3d48e3d09dce8c4fc757b52a5cc2df6ddf5a54e208d0be028a036` |
| `../../oracle_scannerc_test.go` | scannerc.go (apic: 1-103; others: all) | `a850fdd79a89f1475c7db3b685af057001ad871390770bf1c90aa808955df084` | `fa6fc15492222b3fcaec380ba2aa81564df7e4dcbfd7a803652332a03b2110a1` |
| `../../oracle_parserc_test.go` | parserc.go (apic: 1-103; others: all) | `917227ca67ac2cfec193c6962cc5862244f92a67b7e53ec7ffa3a3729d477077` | `2d66112ff2475b3e0c65dc4cff87d133f501c8b8be1e245abfc3c1e592a77109` |
| `../../oracle_yamlh_test.go` | yamlh.go (apic: 1-103; others: all) | `6a8105eedd934f55399d786feb6acfd5c13b4cae4a80e58c0fff7a300921e06f` | `a05af5f86b45362cc16acabec0392c29a4a302ce6678bb2bdcc7b763d6c99f42` |
| `../../oracle_yamlprivateh_test.go` | yamlprivateh.go (apic: 1-103; others: all) | `4e2195c00895d14965430b8326595e287ed23a7923ea3a7d43cfa95d0d359958` | `fffd3812a42dc6b91ec9291988ae44f49ea6d4e1e8efaff1e068ba0005529394` |

Deterministic unified patch SHA-256: `792ebbb56c77e9716dce064ed1c316626d0196d58bb89255039a89a4f9a83cb8`.

Rebuild the patch in table order with Python `difflib.unified_diff`, `splitlines(True)` and UTF-8 encoding. For the first eight rows, use full upstream/adapted text and names `upstream/<name>` and `adapted/<name>`. For `node.go` and `resolve.go`, concatenate the listed inclusive source ranges and use those adapted basenames. For oracle rows, compare the complete upstream source with its test copy, using `upstream/oracle_<upstream basename>` and `adapted/oracle_<upstream basename>`. Preserve LF newlines and concatenate without separators. New budget, preflight, test and fixture helpers are outside this patch.

## Adaptation

- Both passes read the same payload without rewriting it. Scanner comment routines keep upstream lookahead and mark advancement, discard comment characters before buffer writes, and never queue presentation comments. A fixed 65-slot mark summary preserves the earliest matching start in each contiguous comment chain for live indentation levels, including block-end repositioning. Comment presence drives pinned splitting decisions without storing text. Scalar `#` bytes still use upstream scalar scanning.
- Live simple-key slots replace the map; token-number lookup searches at most 64 entries. Token insertion compacts consumed storage before growth and preserves pinned append capacities because flow empty-value marks can depend on a token pointer surviving lookahead. Every queue growth reserves a conservative doubling bound before append. Whitespace/break scratch buffers persist across scalar scans and reset length without refunds.
- Every reachable reader, scratch, token and stack allocation reserves cumulative bytes/objects first. Structural guards remain active before growth, including scalar aggregate limits and malformed suffixes. Explicit tags return `ErrTag`; anchors, aliases and directives return `ErrSyntax` under section 5's profile mapping.
- Preflight stores flat arities in a bounded 65,536-entry buffer. Node construction uses exactly `N+1` Nodes and `N` Content pointers. Counts, container depth, arities and final arena consumption must agree. No partial tree or ledger escapes a failed Decode.
- The Node builder retains pinned kind/tag/value/style/mark/order semantics. Only presentation comment fields are omitted. It copies no emitter, reflection decoder, anchor table or alternate tree builder.
- The resolver retains pinned implicit dispatch and fallback order. Float calls reserve the pinned Go helper's input clone and NumError before invocation. Integer and timestamp recognition use allocation-free tag-only equivalents; `yamlFloat` replaces the pinned regular expression. Their source reasoning and differential tests require independent implementation approval.
- The `_test.go` oracle copies preserve upstream comment storage and scalar scanning. Separate profile counters and lexical restrictions classify every fixture/fuzz input before the candidate. Oracle Node semantics come from the unmodified pinned module. No production file imports or calls the oracle.

[Allocation source audit](ALLOCATION_AUDIT.md) records charges, allocator sources, capacities and recursion. [Gate A evidence](../../GATE_A_REVIEW.md) records finite measurements and pending checks. Source/provenance approval and native evidence remain Gate A blockers.
