# Gate A parser qualification

Gate A is approved for the budgeted YAML candidate: local finite and extended checks pass, the native `loader-gate-a` CI job passes on Linux x64, Windows x64 and macOS ARM64, and an independent Astra xhigh review approved the source bounds, scanner/Node agreement, reference checks and measurements. No production consumer imports the candidate.

The candidate reads the unchanged payload twice, elides presentation comment storage in the scanner, records flat arities, builds exact Node/Content arenas and retains one cumulative allocation ledger. It returns no partial tree or ledger on failure. Explicit tags return ErrTag; anchors, aliases and directives return ErrSyntax under the profile-error mapping.

## Source bounds

[The allocation audit](internal/yamltokens/ALLOCATION_AUDIT.md) identifies every reachable allocation family, rounding rule, clamp, abandoned buffer, helper and recursion bound. [Provenance](internal/yamltokens/PROVENANCE.md) identifies selected upstream ranges, complete-file checksums, preserved notices and the deterministic patch digest.

- Payload and aggregate token values: 1,048,576 bytes. Tokens: 262,208. Live simple-key/indent/state/mark slots: 64. Nodes: 65,536 excluding the wrapper. Container depth: 16.
- The ledger checks each rounded backing allocation before growth and never refunds it. Its cumulative ceilings are 67,108,864 bytes and 1,000,000 objects. Reserve rejects overflow requests before changing either counter.
- A successful tree allocates exactly N+1 Nodes and N Content pointers. Capacities cannot grow. Linux Node size is 152 bytes; charges use unsafe.Sizeof for all required 64-bit targets. At N=65,536, logical Node/Content storage totals 10,485,912 bytes before rounding.
- Comment storage contributes zero candidate allocations. Simple-key lookup has no map. Scalar whitespace/break scratch reuses capacity within each pass. Both passes' allocations remain charged.
- Integer/timestamp/float-pattern classification uses allocation-free tag-only equivalents. Underscore replacement and ParseFloat reserve helper copies/objects first. Fixed overhead reserves 16,640 bytes and eight objects once at entry.
- Node construction has at most 16 container frames plus scalar/caller frames. Native CI must confirm the 8 MiB StackInuse ceiling. The local maximum growth is 32,768 bytes.

Astra xhigh reviewed the fixed-overhead/escape allowance, allocator source reasoning, resolver equivalents and independent reference classification against Go 1.27.1. No source bound is claimed for the unmodified oracle, which remains isolated in test code and outside candidate measurements. Passing finite samples do not establish universal profile acceptance or qualify Gate A.

## Corpus and measurement method

The root test classifies each recipe using a separate pinned, comment-preserving scanner/event reference and unmodified Node oracle before any candidate call. Fixed comment cases carry assigned acceptance/error classes. Check and Decode compare both acceptance directions and rejected-input class/precedence. Successful Decode compares complete kind, tag, value, style, line/column, child order and node/depth counts, ignoring only presentation comments. Deliberate exhaustion stays separate from normal-budget agreement.

The comment matrix includes explicit keys with comments at EOF, empty values, nested dedents, multi-line flow scalars and comments at collection boundaries. Flow empty-value agreement also covers 41 token offsets, three break lengths and four suffixes. The fuzz corpus retains `ce5ca0bdafea4688` and `fc7f1abb137137c8`. Tree comparison still ignores only HeadComment, LineComment and FootComment.

The smoke corpus includes every required recipe and the exact maximum witness, interleaved/collection-boundary comments, 1 MiB padding, all seven other component branches at numeric/cardinality limits, and 65,536-node implicit binary/octal/float-class cases. The witness has 4,096 files with exactly one owner each, 62,437 nodes, depth 7 and 477,323 decoded value bytes. Compact JSON has 639,793 bytes. Comma/colon comment insertion has 855,713 bytes and SHA-256 `af263524ee80433b68ef296023ef57e099d23d5f08fe3237c384f82738ca30bb`. Schema and manifest.Validate checks pass. The schema evaluator reads the checked-in closed schema, independently of manifest's Go field rules; the external offline jsonschema evaluator also accepted the compact witness and all seven branch witnesses during local validation.

Each measured operation runs in a fresh internal parser test process. The root supplies reference outcomes, arities and paths to complete oracle trees through a temporary file. Node-only mode uses a test-only construction entry with those arities and a fresh ledger; it does not run candidate preflight before the snapshot. Preflight measures standalone preparation. Combined mode calls Decode once. Rejected preflight inputs never enter construction, including Node-only mode.

The child builds input and loads reference metadata before measurement, runs one GC, disables GC only during measurement, and keeps payload/tree live through the final snapshot. No warmup runs. Tree walking occurs afterward. Metrics are TotalAlloc/Mallocs deltas, StackInuse growth, retained HeapAlloc, peak RSS and elapsed nanoseconds. Linux RSS uses Getrusage KiB converted to bytes; macOS uses Getrusage bytes; Windows uses GetProcessMemoryInfo peak working-set bytes. API failures fail the child. RSS includes process startup/input generation and is not incremental heap. Retained heap includes transient allocations while GC is disabled.

## Local results

All 144 measurements pass on Go 1.27.1, Linux amd64. The counterexample succeeds unchanged: 524,280 bytes, 65,536 nodes and depth 2. Normal budgets also accept every required valid witness. Ledger charges exceed measured bytes/objects whenever a ledger is available. A failed Decode returns nil Budget, so its measurement has no returned ledger counters; source guards and injected exhaustion tests cover those failure paths.

| Input | Mode | Alloc bytes | Ceiling headroom |
|---|---|---:|---:|
| comment-collections | node | 10,501,104 | 56,607,760 |
| comment-collections | combined | 10,770,416 | 56,338,448 |
| maximum-compact | node | 12,594,720 | 54,514,144 |
| maximum-compact | combined | 14,945,856 | 52,163,008 |
| maximum-commented | node | 12,504,864 | 54,604,000 |
| maximum-commented | combined | 14,766,144 | 52,342,720 |
| maximum-padded | node | 12,594,720 | 54,514,144 |
| maximum-padded | combined | 14,945,856 | 52,163,008 |

The finite maximum is 19,171,616 bytes for `implicit-float/combined`, with 47,937,248 bytes of headroom. Maximum objects: 327,712. Maximum ledger charge: 37,763,108 bytes and 327,717 objects.

### Finite measurement table

Ledger columns show cumulative source charges. A zero ledger on a rejected combined/Node-skipped call means no ledger was returned, not a zero allocation bound.

| Input | Bytes | Mode | Status/error | Alloc | Objects | Stack | Heap | RSS | Time ns | Ledger bytes | Ledger objects |
|---|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| comment-collections | 1048576 | preflight | preflight-rejected/YAML limit | 269296 | 12 | 32768 | 269296 | 17133568 | 16732334 | 295936 | 18 |
| comment-collections | 1048576 | node | preflight-rejected/YAML limit | 0 | 0 | 0 | 0 | 20279296 | 310 | 0 | 0 |
| comment-collections | 1048576 | combined | preflight-rejected/YAML limit | 269296 | 12 | 32768 | 269296 | 20279296 | 16853029 | 0 | 0 |
| plain | 1048576 | preflight | accepted | 2365984 | 27 | 32768 | 2365984 | 20279296 | 14965649 | 2474464 | 33 |
| plain | 1048576 | node | accepted | 3152664 | 28 | 0 | 3152664 | 20279296 | 8440973 | 3261296 | 34 |
| plain | 1048576 | combined | accepted | 5518584 | 54 | 32768 | 5518584 | 20279296 | 20182845 | 5719120 | 59 |
| comment-keys | 1048576 | preflight | preflight-rejected/YAML limit | 2367792 | 65551 | 32768 | 2367792 | 20369408 | 9790635 | 6589920 | 65557 |
| comment-keys | 1048576 | node | preflight-rejected/YAML limit | 0 | 0 | 0 | 0 | 20369408 | 93 | 0 | 0 |
| comment-keys | 1048576 | combined | preflight-rejected/YAML limit | 2367792 | 65551 | 32768 | 2367792 | 20828160 | 12641708 | 0 | 0 |
| comments | 1048576 | preflight | accepted | 270752 | 17 | 0 | 270752 | 20828160 | 3923190 | 298848 | 23 |
| comments | 1048576 | node | accepted | 9192 | 17 | 0 | 9192 | 20828160 | 3839356 | 29620 | 25 |
| comments | 1048576 | combined | accepted | 279880 | 33 | 32768 | 279880 | 20828160 | 12479973 | 311828 | 40 |
| tiny-comments | 1048575 | preflight | accepted | 270752 | 17 | 32768 | 270752 | 20828160 | 6141887 | 298848 | 23 |
| tiny-comments | 1048575 | node | accepted | 9192 | 17 | 0 | 9192 | 20828160 | 6054980 | 29620 | 25 |
| tiny-comments | 1048575 | combined | accepted | 279880 | 33 | 32768 | 279880 | 20828160 | 11984278 | 311828 | 40 |
| escaped | 1048576 | preflight | preflight-rejected/YAML limit | 2364848 | 23 | 0 | 2364848 | 20828160 | 10587536 | 2472096 | 29 |
| escaped | 1048576 | node | preflight-rejected/YAML limit | 0 | 0 | 0 | 0 | 20889600 | 185 | 0 | 0 |
| escaped | 1048576 | combined | preflight-rejected/YAML limit | 2364848 | 23 | 0 | 2364848 | 20889600 | 6390617 | 0 | 0 |
| block | 1048576 | preflight | accepted | 2367808 | 31 | 32768 | 2367808 | 20889600 | 7473817 | 2477984 | 37 |
| block | 1048576 | node | accepted | 3154824 | 32 | 0 | 3154824 | 21291008 | 6230457 | 3265482 | 39 |
| block | 1048576 | combined | accepted | 5522568 | 62 | 32768 | 5522568 | 21291008 | 20246803 | 5726826 | 68 |
| empty-flow | 1048576 | preflight | preflight-rejected/YAML limit | 810864 | 20 | 32768 | 810864 | 21291008 | 13356170 | 1026976 | 26 |
| empty-flow | 1048576 | node | preflight-rejected/YAML limit | 0 | 0 | 0 | 0 | 21291008 | 315 | 0 | 0 |
| empty-flow | 1048576 | combined | preflight-rejected/YAML limit | 810864 | 20 | 32768 | 810864 | 21291008 | 14164008 | 0 | 0 |
| tiny-keys | 1048575 | preflight | preflight-rejected/YAML limit | 2367792 | 65551 | 32768 | 2367792 | 21291008 | 8748970 | 6589920 | 65557 |
| tiny-keys | 1048575 | node | preflight-rejected/YAML limit | 0 | 0 | 0 | 0 | 21291008 | 250 | 0 | 0 |
| tiny-keys | 1048575 | combined | preflight-rejected/YAML limit | 2367792 | 65551 | 32768 | 2367792 | 21291008 | 8982803 | 0 | 0 |
| explicit-key | 1048576 | preflight | preflight-rejected/YAML limit | 2366512 | 65550 | 32768 | 2366512 | 21291008 | 10003362 | 6587584 | 65556 |
| explicit-key | 1048576 | node | preflight-rejected/YAML limit | 0 | 0 | 0 | 0 | 21291008 | 171 | 0 | 0 |
| explicit-key | 1048576 | combined | preflight-rejected/YAML limit | 2366512 | 65550 | 32768 | 2366512 | 21291008 | 9798365 | 0 | 0 |
| tags | 1048576 | preflight | preflight-rejected/YAML tag | 267728 | 7 | 0 | 267728 | 21291008 | 88860 | 292768 | 13 |
| tags | 1048576 | node | preflight-rejected/YAML tag | 0 | 0 | 0 | 0 | 21291008 | 138 | 0 | 0 |
| tags | 1048576 | combined | preflight-rejected/YAML tag | 267728 | 7 | 0 | 267728 | 21291008 | 130891 | 0 | 0 |
| anchors | 1048575 | preflight | preflight-rejected/YAML syntax | 267728 | 7 | 0 | 267728 | 21291008 | 279581 | 292768 | 13 |
| anchors | 1048575 | node | preflight-rejected/YAML syntax | 0 | 0 | 0 | 0 | 21291008 | 299 | 0 | 0 |
| anchors | 1048575 | combined | preflight-rejected/YAML syntax | 267728 | 7 | 0 | 267728 | 21291008 | 102066 | 0 | 0 |
| missing-end | 1048576 | preflight | preflight-rejected/YAML syntax | 269168 | 11 | 32768 | 269168 | 21291008 | 5747396 | 295648 | 17 |
| missing-end | 1048576 | node | preflight-rejected/YAML syntax | 0 | 0 | 0 | 0 | 21291008 | 303 | 0 | 0 |
| missing-end | 1048576 | combined | preflight-rejected/YAML syntax | 269168 | 11 | 32768 | 269168 | 21291008 | 3682308 | 0 | 0 |
| malformed-suffix | 1048576 | preflight | preflight-rejected/YAML syntax | 270672 | 16 | 32768 | 270672 | 21291008 | 140518 | 298560 | 22 |
| malformed-suffix | 1048576 | node | preflight-rejected/YAML syntax | 0 | 0 | 0 | 0 | 21291008 | 493 | 0 | 0 |
| malformed-suffix | 1048576 | combined | preflight-rejected/YAML syntax | 270672 | 16 | 32768 | 270672 | 21291008 | 172358 | 0 | 0 |
| flow | 31 | preflight | accepted | 278624 | 16 | 32768 | 278624 | 21291008 | 173106 | 313408 | 22 |
| flow | 31 | node | accepted | 19216 | 16 | 0 | 19216 | 21291008 | 60295 | 48306 | 23 |
| flow | 31 | combined | accepted | 297776 | 31 | 32768 | 297776 | 21291008 | 87629 | 345074 | 37 |
| flow | 33 | preflight | accepted | 280160 | 18 | 32768 | 280160 | 21291008 | 79529 | 316544 | 24 |
| flow | 33 | node | accepted | 21152 | 18 | 0 | 21152 | 21291008 | 33430 | 51762 | 25 |
| flow | 33 | combined | accepted | 301248 | 35 | 32768 | 301248 | 21291008 | 227218 | 351666 | 41 |
| flow | 35 | preflight | preflight-rejected/YAML limit | 280080 | 17 | 32768 | 280080 | 21291008 | 74805 | 316256 | 23 |
| flow | 35 | node | preflight-rejected/YAML limit | 0 | 0 | 0 | 0 | 21291008 | 168 | 0 | 0 |
| flow | 35 | combined | preflight-rejected/YAML limit | 280080 | 17 | 32768 | 280080 | 21291008 | 80164 | 0 | 0 |
| flow | 127 | preflight | preflight-rejected/YAML limit | 315408 | 20 | 32768 | 315408 | 21291008 | 165747 | 385984 | 26 |
| flow | 127 | node | preflight-rejected/YAML limit | 0 | 0 | 0 | 0 | 21291008 | 100 | 0 | 0 |
| flow | 127 | combined | preflight-rejected/YAML limit | 315408 | 20 | 32768 | 315408 | 21291008 | 75008 | 0 | 0 |
| flow | 129 | preflight | preflight-rejected/YAML limit | 292848 | 15 | 32768 | 292848 | 21291008 | 159500 | 341024 | 21 |
| flow | 129 | node | preflight-rejected/YAML limit | 0 | 0 | 0 | 0 | 21291008 | 82 | 0 | 0 |
| flow | 129 | combined | preflight-rejected/YAML limit | 292848 | 15 | 32768 | 292848 | 21291008 | 51052 | 0 | 0 |
| flow | 131 | preflight | preflight-rejected/YAML limit | 292848 | 15 | 32768 | 292848 | 21291008 | 86293 | 341024 | 21 |
| flow | 131 | node | preflight-rejected/YAML limit | 0 | 0 | 0 | 0 | 21291008 | 97 | 0 | 0 |
| flow | 131 | combined | preflight-rejected/YAML limit | 292848 | 15 | 32768 | 292848 | 21291008 | 131549 | 0 | 0 |
| indent | 167 | preflight | accepted | 273888 | 32 | 32768 | 273888 | 21291008 | 195870 | 304832 | 38 |
| indent | 167 | node | accepted | 17296 | 32 | 0 | 17296 | 21291008 | 32071 | 45040 | 54 |
| indent | 167 | combined | accepted | 291120 | 63 | 32768 | 291120 | 21291008 | 231513 | 333232 | 84 |
| indent | 186 | preflight | accepted | 279552 | 35 | 32768 | 279552 | 21291008 | 188587 | 315872 | 41 |
| indent | 186 | node | accepted | 22992 | 35 | 0 | 22992 | 21291008 | 55918 | 56754 | 58 |
| indent | 186 | combined | accepted | 302480 | 69 | 32768 | 302480 | 21291008 | 217613 | 355986 | 91 |
| indent | 206 | preflight | preflight-rejected/YAML limit | 271632 | 32 | 32768 | 271632 | 21291008 | 67312 | 300992 | 38 |
| indent | 206 | node | preflight-rejected/YAML limit | 0 | 0 | 0 | 0 | 21291008 | 237 | 0 | 0 |
| indent | 206 | combined | preflight-rejected/YAML limit | 271632 | 32 | 0 | 271632 | 21291008 | 57774 | 0 | 0 |
| indent | 2207 | preflight | preflight-rejected/YAML limit | 271632 | 32 | 0 | 271632 | 21291008 | 257546 | 300992 | 38 |
| indent | 2207 | node | preflight-rejected/YAML limit | 0 | 0 | 0 | 0 | 21291008 | 232 | 0 | 0 |
| indent | 2207 | combined | preflight-rejected/YAML limit | 271632 | 32 | 32768 | 271632 | 21291008 | 162051 | 0 | 0 |
| indent | 2274 | preflight | preflight-rejected/YAML limit | 271632 | 32 | 32768 | 271632 | 21291008 | 173429 | 300992 | 38 |
| indent | 2274 | node | preflight-rejected/YAML limit | 0 | 0 | 0 | 0 | 21291008 | 145 | 0 | 0 |
| indent | 2274 | combined | preflight-rejected/YAML limit | 271632 | 32 | 32768 | 271632 | 21291008 | 194645 | 0 | 0 |
| indent | 2342 | preflight | preflight-rejected/YAML limit | 271632 | 32 | 32768 | 271632 | 21291008 | 53066 | 300992 | 38 |
| indent | 2342 | node | preflight-rejected/YAML limit | 0 | 0 | 0 | 0 | 21291008 | 415 | 0 | 0 |
| indent | 2342 | combined | preflight-rejected/YAML limit | 271632 | 32 | 32768 | 271632 | 21291008 | 86849 | 0 | 0 |
| nodes | 131069 | preflight | accepted | 2908032 | 65555 | 32768 | 2908032 | 21291008 | 8464991 | 7318528 | 65561 |
| nodes | 131069 | node | accepted | 13131568 | 65555 | 0 | 13131568 | 25976832 | 12772432 | 19778196 | 131095 |
| nodes | 131069 | combined | accepted | 16039536 | 131109 | 32768 | 16039536 | 26570752 | 31870816 | 27080084 | 196648 |
| nodes | 131071 | preflight | accepted | 2908064 | 65556 | 32768 | 2908064 | 21291008 | 8428613 | 7318624 | 65562 |
| nodes | 131071 | node | accepted | 13139792 | 65556 | 0 | 13139792 | 25845760 | 13472107 | 19778486 | 131097 |
| nodes | 131071 | combined | accepted | 16047792 | 131111 | 32768 | 16047792 | 26963968 | 32108086 | 27080470 | 196651 |
| nodes | 131073 | preflight | preflight-rejected/YAML limit | 2908016 | 65556 | 32768 | 2908016 | 21291008 | 9371071 | 7318432 | 65562 |
| nodes | 131073 | node | preflight-rejected/YAML limit | 0 | 0 | 0 | 0 | 21291008 | 72 | 0 | 0 |
| nodes | 131073 | combined | preflight-rejected/YAML limit | 2908016 | 65556 | 32768 | 2908016 | 21291008 | 9458591 | 0 | 0 |
| tiny-keys | 163835 | preflight | accepted | 2367776 | 65549 | 32768 | 2367776 | 21291008 | 8939248 | 6589920 | 65555 |
| tiny-keys | 163835 | node | accepted | 12591312 | 65549 | 0 | 12591312 | 26107904 | 14183407 | 19049588 | 131089 |
| tiny-keys | 163835 | combined | accepted | 14959024 | 131097 | 32768 | 14959024 | 25722880 | 33816104 | 25622868 | 196636 |
| explicit-key | 262136 | preflight | accepted | 2366496 | 65548 | 32768 | 2366496 | 21291008 | 13735278 | 6587584 | 65554 |
| explicit-key | 262136 | node | accepted | 12590032 | 65548 | 0 | 12590032 | 25583616 | 13808987 | 19047252 | 131088 |
| explicit-key | 262136 | combined | accepted | 14956464 | 131095 | 32768 | 14956464 | 26177536 | 25754667 | 25618196 | 196634 |
| comment-keys | 262136 | preflight | accepted | 2367776 | 65549 | 32768 | 2367776 | 21291008 | 9883537 | 6589920 | 65555 |
| comment-keys | 262136 | node | accepted | 12591312 | 65549 | 0 | 12591312 | 25714688 | 14410755 | 19049588 | 131089 |
| comment-keys | 262136 | combined | accepted | 14959024 | 131097 | 32768 | 14959024 | 26107904 | 35567966 | 25622868 | 196636 |
| empty-flow | 196609 | preflight | preflight-rejected/YAML limit | 810864 | 20 | 32768 | 810864 | 21291008 | 13137606 | 1026976 | 26 |
| empty-flow | 196609 | node | preflight-rejected/YAML limit | 0 | 0 | 0 | 0 | 21291008 | 376 | 0 | 0 |
| empty-flow | 196609 | combined | preflight-rejected/YAML limit | 810864 | 20 | 32768 | 810864 | 21291008 | 11338729 | 0 | 0 |
| comment-collections | 524280 | preflight | accepted | 269376 | 13 | 32768 | 269376 | 21291008 | 12553564 | 296224 | 19 |
| comment-collections | 524280 | node | accepted | 10501104 | 13 | 0 | 10501104 | 24141824 | 16549737 | 10527896 | 19 |
| comment-collections | 524280 | combined | accepted | 10770416 | 25 | 32768 | 10770416 | 22175744 | 42838494 | 10807480 | 30 |
| maximum-compact | 639793 | preflight | accepted | 2351200 | 58114 | 0 | 2351200 | 21291008 | 15919624 | 6270272 | 58120 |
| maximum-compact | 639793 | node | accepted | 12594720 | 103902 | 0 | 12594720 | 26226688 | 20364306 | 18688142 | 112101 |
| maximum-compact | 639793 | combined | accepted | 14945856 | 162015 | 0 | 14945856 | 22437888 | 34733009 | 24941774 | 170213 |
| maximum-commented | 855713 | preflight | accepted | 2261344 | 58109 | 0 | 2261344 | 21291008 | 15434799 | 6138976 | 58115 |
| maximum-commented | 855713 | node | accepted | 12504864 | 103897 | 0 | 12504864 | 29814784 | 20413613 | 18556846 | 112096 |
| maximum-commented | 855713 | combined | accepted | 14766144 | 162005 | 0 | 14766144 | 24457216 | 47480335 | 24679182 | 170203 |
| maximum-boundaries | 923361 | preflight | accepted | 2260080 | 58109 | 0 | 2260080 | 21291008 | 15484056 | 6136640 | 58114 |
| maximum-boundaries | 923361 | node | accepted | 12503584 | 103896 | 0 | 12503584 | 24313856 | 22053508 | 18554510 | 112095 |
| maximum-boundaries | 923361 | combined | accepted | 14763600 | 162004 | 0 | 14763600 | 24264704 | 36735588 | 24674510 | 170201 |
| maximum-padded | 1048576 | preflight | accepted | 2351200 | 58114 | 0 | 2351200 | 21291008 | 19457066 | 6270272 | 58120 |
| maximum-padded | 1048576 | node | accepted | 12594720 | 103902 | 0 | 12594720 | 27078656 | 22279352 | 18688142 | 112101 |
| maximum-padded | 1048576 | combined | accepted | 14945856 | 162015 | 0 | 14945856 | 23302144 | 37131206 | 24941774 | 170213 |
| maximum-branch0 | 459483 | preflight | accepted | 1565632 | 33582 | 0 | 1565632 | 21291008 | 11509450 | 3914112 | 33588 |
| maximum-branch0 | 459483 | node | accepted | 7088648 | 58951 | 0 | 7088648 | 21659648 | 14558318 | 10746100 | 63054 |
| maximum-branch0 | 459483 | combined | accepted | 8654216 | 92532 | 0 | 8654216 | 21659648 | 18826437 | 14643572 | 96634 |
| maximum-branch1 | 603371 | preflight | accepted | 1989632 | 46767 | 0 | 1989632 | 21770240 | 15627455 | 5184032 | 46773 |
| maximum-branch1 | 603371 | node | accepted | 9799272 | 85256 | 0 | 9799272 | 22405120 | 13174506 | 14814900 | 89359 |
| maximum-branch1 | 603371 | combined | accepted | 11788856 | 132023 | 0 | 11788856 | 22560768 | 24310231 | 19982292 | 136124 |
| maximum-branch2 | 463269 | preflight | accepted | 1573824 | 33838 | 0 | 1573824 | 21770240 | 11893149 | 3938688 | 33844 |
| maximum-branch2 | 463269 | node | accepted | 7150088 | 59463 | 0 | 7150088 | 21770240 | 9798543 | 10826760 | 63566 |
| maximum-branch2 | 463269 | combined | accepted | 8723848 | 93300 | 0 | 8723848 | 21770240 | 20223232 | 14748808 | 97402 |
| maximum-branch3 | 730209 | preflight | accepted | 2034640 | 40047 | 0 | 2034640 | 21770240 | 15732418 | 5058944 | 40052 |
| maximum-branch3 | 730209 | node | accepted | 8217112 | 67783 | 0 | 8217112 | 21770240 | 12906953 | 12883712 | 71886 |
| maximum-branch3 | 730209 | combined | accepted | 10251672 | 107828 | 0 | 10251672 | 21770240 | 27647170 | 17926016 | 111930 |
| maximum-branch4 | 479844 | preflight | accepted | 1618880 | 35246 | 0 | 1618880 | 21770240 | 7716064 | 4073856 | 35252 |
| maximum-branch4 | 479844 | node | accepted | 7432568 | 62279 | 0 | 7432568 | 21770240 | 9259967 | 11259526 | 66382 |
| maximum-branch4 | 479844 | combined | accepted | 9051384 | 97524 | 0 | 9051384 | 21770240 | 20326884 | 15316742 | 101626 |
| maximum-branch5 | 479972 | preflight | accepted | 1610688 | 34990 | 0 | 1610688 | 21770240 | 11978334 | 4049280 | 34996 |
| maximum-branch5 | 479972 | node | accepted | 7391240 | 61767 | 0 | 7391240 | 21770240 | 10041833 | 11196038 | 65870 |
| maximum-branch5 | 479972 | combined | accepted | 9001880 | 96757 | 0 | 9001880 | 21770240 | 19222300 | 15228678 | 100858 |
| maximum-branch6 | 496937 | preflight | accepted | 1637376 | 35695 | 0 | 1637376 | 21770240 | 7620010 | 4125216 | 35701 |
| maximum-branch6 | 496937 | node | accepted | 7545432 | 63048 | 0 | 7545432 | 21770240 | 16464184 | 11421232 | 67151 |
| maximum-branch6 | 496937 | combined | accepted | 9182744 | 98742 | 0 | 9182744 | 21770240 | 21288457 | 15529808 | 102844 |
| implicit-binary | 262141 | preflight | accepted | 2547616 | 65554 | 32768 | 2547616 | 21770240 | 9910552 | 6827328 | 65560 |
| implicit-binary | 262141 | node | accepted | 12989056 | 131089 | 0 | 12989056 | 26107904 | 15209545 | 19549330 | 131095 |
| implicit-binary | 262141 | combined | accepted | 15536608 | 196642 | 0 | 15536608 | 26570752 | 28050144 | 26360018 | 196647 |
| implicit-octal | 262141 | preflight | accepted | 2547616 | 65554 | 32768 | 2547616 | 21770240 | 9899685 | 6827328 | 65560 |
| implicit-octal | 262141 | node | accepted | 12989056 | 131089 | 0 | 12989056 | 25714688 | 29568208 | 19549330 | 131095 |
| implicit-octal | 262141 | combined | accepted | 15536608 | 196642 | 0 | 15536608 | 26439680 | 33377759 | 26360018 | 196647 |
| implicit-float | 393211 | preflight | accepted | 2547616 | 65554 | 32768 | 2547616 | 21770240 | 15921165 | 6827328 | 65560 |
| implicit-float | 393211 | node | accepted | 16624064 | 262159 | 0 | 16624064 | 29253632 | 22862646 | 30952420 | 262165 |
| implicit-float | 393211 | combined | accepted | 19171616 | 327712 | 32768 | 19171616 | 30699520 | 33722673 | 37763108 | 327717 |

## Review finding coverage

A-01 has an exact regression for `? a\n#c\n`. The oracle's implicit null at Document.Content[0].Content[1] has Line 2 and Column 2. The candidate agrees. The comment matrix and fuzz seeds include the input with LF and CRLF.

A-02 transports a separate oracle tree file for every accepted recipe. The root establishes each tree before candidate calls using the independent profile reference and unmodified YAML Node decoder. It clears only HeadComment, LineComment and FootComment. Node-only and combined children load and compare the complete tree after allocation, timing, retained heap, stack and peak RSS measurements. Oracle tree storage stays outside measurement. Agreement tests cover all 272 extended recipes; the measurement corpus has 816 mode/recipe pairs.

The tree negative control supplies an oracle with a changed scalar value. Both construction modes must fail with complete-tree disagreement. The rejection negative controls call the same assertion used by agreement tests and fuzzing. They require failure for oracle rejection with candidate acceptance, oracle acceptance with candidate rejection, Check error-class mismatch and Decode error-class mismatch. Fixed comment cases retain independent assigned outcomes for ErrSyntax, ErrTag and ErrLimit.

## Verification

All Go commands run from the repository root with `GOPROXY=off GOCACHE=/tmp/ricevanta-extloader-gocache`. The only extended measurement run is the required scalar-mutation proof. An unmutated extended measurement run remains a native CI check. Complete-tree agreement for all 272 extended recipes passes locally in the focused suite.

| Check | Exact command | Result |
|---|---|---|
| A-01 exact reproduction | `go test -C server -count=1 ./internal/extensions/loader -run '^TestExplicitKeyCommentMark$' -v` | PASS; implicit null Line 2, Column 2 |
| Tree negative control | `go test -C server -count=1 ./internal/extensions/loader/internal/yamltokens -run '^TestMeasurementRejectsTreeMismatch$' -v` | FAIL before tree validation in both modes; PASS with validation |
| Rejection mutation | `go test -C server -count=1 ./internal/extensions/loader -run '^TestAgreementRejectsOutcomeMismatch$' -v` | FAIL for all four controls with the comparison disabled; PASS with the comparison restored |
| Extended scalar mutation | `go test -C server -count=1 ./internal/extensions/loader -run '^TestParserBudgetExtended$' -v -args -loader-budget-extended` | FAIL at plain/64/node and plain/64/combined with complete-tree disagreement; 814 other pairs PASS |
| Focused suite | `go test -C server -count=1 ./internal/extensions/loader/... -run 'Test(Token\|YAMLFraming\|Preflight\|ParserBudgetSmoke\|BudgetedNode\|ParserAllocation\|CommentElision\|MaximumManifest\|ScannerGrowthBounds\|AggregateBeforeGrowth\|ParserStackGuards\|ParserLayouts\|ExplicitKeyCommentMark\|MeasurementRejectsTreeMismatch\|AgreementRejectsOutcomeMismatch)' -v` | PASS; 272 extended agreement recipes and 144 smoke measurements |
| Fuzz seeds | `go test -C server -count=1 ./internal/extensions/loader -run '^FuzzParserQualification$' -v` | PASS; 225 seeds |
| Vet | `go vet -C server ./internal/extensions/loader/...` | PASS; no output |
| Formatting | `gofmt -l server/internal/extensions/loader` | PASS; no output |
| Whitespace | `git diff --check` | PASS; no output |
| Fuzz smoke | `go test -C server -count=1 ./internal/extensions/loader -run '^$' -fuzz='^FuzzParserQualification$' -fuzztime=20s -parallel=2` | PASS; 103,831 executions with two workers |

Both mutations are restored. `cmp /tmp/extloader-node-original.go server/internal/extensions/loader/internal/yamltokens/node.go` passes. The rejection comparison is present in `assertAgreementResults`; the restored focused suite exercises every negative control. No Git state-changing command runs. No race test, full-module suite or native Windows/macOS check runs locally.

## Files in this fix

Line counts include the whole file. Paths are relative to the loader directory. The comment-mark summary and token-queue growth change the adapted production sources `internal/yamltokens/apic.go` (140 lines), `internal/yamltokens/scannerc.go` (3,008 lines) and `internal/yamltokens/yamlh.go` (570 lines); `PROVENANCE.md` records their digests.

| File | Lines |
|---|---:|
| `GATE_A_REVIEW.md` | 239 |
| `internal/yamltokens/qualification_test.go` | 364 |
| `internal/yamltokens/qualification_agreement_test.go` | 44 |
| `yaml_agreement_test.go` | 152 |
| `yaml_budget_test.go` | 91 |
| `yaml_oracle_test.go` | 168 |
| `yaml_rejection_test.go` | 64 |
