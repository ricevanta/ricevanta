# Complete-loader allocation audit

The implemented fields-before-encoding source establishes the field-valid rejecting-prefix domain below. The three-target native source/compiler/cache/stack facts are bound to current source `a19cc54e4748ff0c26379d634c3cb3f3581394ce`. Independent source/native and qualification reviews approve Gate B for this code, with successful current-source PR CI. Archive, YAML, JSON/DSSE, shared registry/formatter, retention, completed manifest and admitted-prefix proofs retain their frozen scopes. The numeric tables and escape facts below use successful native diagnosis run `38362276804` for the amended source, with independent source-reviewer confirmation supplied by the primary. The complete loader has an allocation envelope, not an allocator interceptor or hard process limit; no production admission follows from this audit.

Current array-loop source is `manifest/fields.go` SHA256 `67f27c7c543bf448447c7fc289c861b71a5bb98531ce1f211c2e8b226d415dc0`. Its approved contract is [manifest section 6.2](../../../../docs/specs/extension-manifest.md#62-validate-each-array-item-before-encoding-it), approved contract snapshot SHA256 `ca8e9d15b1cbbbd390fe849d253a64f9d9525930d375f311fe9bd9533ae536c3`. Source-local ordering, arithmetic and the native bindings below are current. Stateful admission remains a separate production prerequisite.

## Observation boundary

`yaml.go` contains one conversion body, `decodeVerifiedYAMLAccounted`, and one call to `yamltokens.DecodeAccounted`. The legacy wrapper delegates once and discards two scalar usage values. Inspection, duplicate detection, mapping guard and conversion retain the same parser ledger. Every error returns a nil map and a snapshot after the last attempted reservation. There is no closure, defer, interface boxing, observer or formatting helper in this wrapper. `usageYAML` returns two uint64 values by value.

Go 1.27.1 Linux amd64 escape output reports `usageYAML` and `Budget.Usage` inlineable, their budget pointers nonescaping, and the legacy converter inlineable. The sole `&Budget{}` still escapes through the parser, as it did before the adapter change. There is no additional descriptor allocation or new source growth site. The existing once-only entry charge covers this same 64-byte ledger. Current native Linux x64, macOS ARM64 and Windows x64 artifacts bind these observation routines and the amended complete candidate; independent qualification review confirms this binding.

## YAML ledger and conversion proof

The [parser audit](internal/yamltokens/ALLOCATION_AUDIT.md) owns scanner, reader, lookahead, resolver, exact Node/Content arenas, strings, abandoned storage and fixed entry costs. All these charges survive failures through `DecodeAccounted`. The ledger checks 64 MiB and 1,000,000 objects before each reached allocating family; failed reservations change neither counter.

Unchanged `tree.go` continues that ledger through these families:

| Family | Source bound before allocation |
|---|---|
| Profile inspection | Two rounded 416-byte walk/copy objects. Walk depth is 17 slots, not an input-sized stack. UTF-8 and unsigned integer recognizers use fixed locals. |
| Duplicate detection | Three rounded walk/copy objects, a rounded 24-byte slice header, and one exact `16*largestMappingArity` string-header backing. The inspected tree bounds the largest arity by 32,767. Sorting reuses the backing and recurses on the smaller partition, at most 15 frames. No key byte copy or hash map is made. |
| Mapping guard | Two rounded walk/copy objects. Complete profile and duplicate passes precede the guard. Every mapping is limited to 896 pairs before any output container exists. |
| Conversion stack | One rounded 512-byte array of sixteen 32-byte frames. Traversal is iterative. |
| Native maps | For zero pairs, round 48 bytes. For one to eight pairs, add a rounded 264-byte group. For nine to 896 pairs, add rounded 8-byte directory, 32-byte table and `264*c/8` group backing, where c is the smallest power of two at least `floor(8*n/7)`, at most 1,024. Exactly n distinct inserts cannot split this table for any seed. The pinned runtime/compiler proof and layout sources are in `tree.go` and spec section 4.3. |
| Sequences | Round exact `16*n` backing and a 24-byte interface slice-header box separately, including empty sequences. |
| Scalar interfaces | Charge 64 bytes and one object before each scalar; string/json.Number headers share immutable Node string bytes, bool uses static storage. |
| Helpers/errors | Static comparisons and sentinels, fixed assertions, unsigned recognition and UTF-8 checks allocate nothing. No reflection decode, alternate parse, formatting or serialization occurs in conversion. |

`yamlAllocation` bounds small objects by `2*s+32` and large objects by `s+8192`. Reservations include fixed objects even when the compiler keeps them on the stack. The adapter does not change these source limits. Stack growth is separately measured, with an unchanged 8 MiB ceiling. Maximum valid manifest presentations and all small-map/table transitions remain in the corpus.

## Boundary, notation and allocator

The contract is [loader sections 3 and 6](../../../../docs/specs/extension-loader.md). `F` is the effective listed-file cap, `0 < F <= 1 GiB`; zero selects 64 MiB. `T=F+8 MiB`, `C=T+1 MiB`. The unchanged full-call heap envelope is `4C+4T+134,217,728`. YAML allocation is already inside it. No allowance, subtraction, cap change or production admission follows from this audit.

`A<=C` is received compressed bytes; `S<=T` is checked decoded frame size; `D<=F` is actual ordinary-file body bytes; `B<=1 MiB` is exact authenticated YAML bytes; `E<=2 MiB` is envelope bytes; `m<=4098` is retained regular tar members. Attempted physical headers can reach 4099, including one terminating rejected header. Checked tar size is exactly

```text
S = 1024 + 512m + sum(size + pad512(size))
D+B+E+512m+1024 <= S <= D+B+E+1023m+1024.
```

Each byte formula bounds cumulative heap allocation, including abandoned backings and cold helpers. `R(n)` is raw noscan size-class/page rounding. `A0(n)=max(16,R(n))` for positive noscan requests, with `A0(0)=0`, charges each tiny event a whole block regardless of packing. `Ap(n)` rounds scanned storage, including the eight-byte small-object header for requests above 512 bytes; scanned requests do not use the tiny allocator. Go 1.27.1 `runtime/msize.go:16-35`, `internal/runtime/gc/sizeclasses.go:84-98` and `runtime/malloc.go:1141-1147,1226-1240,1280-1295` supply the table and tiny rule. Large requests round to 8192-byte pages:

```text
R(n), A0(n) <= n+8191
R(n) <= 1.25n+27/4; A0(n) <=1.25n+15 (positive n).
```

Raw rounding and full tiny charge are different: `R(1)=8` and `A0(1)=16`. The raw `1.25n+7` bound cannot be applied to A0. Where tiny string/header families use the weaker `A0(n)<=1.25n+16`, that includes their full-block charge. Round every allocation, not only the final total. Scanned slice bounds use the header explicitly. Compiler elimination never refunds a charged family unless all three native artifacts establish the exact conversion.

Finite growth calculations use pinned `nextslicecap` (`runtime/slice.go:326-357`): requests above twice old capacity return their requested length; old capacities below 256 double; otherwise repeatedly add `(capacity+768)>>2` until the request fits, then round the byte capacity according to runtime. Enumerate size classes and page capacities up to the largest possible output. For each increasing capacity edge retain maximum cumulative allocated bytes and object count. Requests in a rounding interval use its smallest length, maximizing allocated-bytes minus the linear length charge. Physical byte capacity is not replaced by a full tiny allocation charge: capacity eight still needs replacement when length grows to nine, even if its first tiny event charged sixteen. This deterministic source enumeration is distinct from measured workloads.

## Reachable branch partition

`loader.go:90-109` performs JSON preflight, DSSE verification, exact payload equality, YAML conversion and manifest validation in order. Authentication precedes every YAML operation. The following alternatives must remain separate:

| Reached path | Families that may coexist |
|---|---|
| Snapshot/frame failure | Snapshot and bounded read-error holder; no decoder or later stages |
| Decoder failure | Snapshot, decoder setup/scratch and one final bad-block output growth; no tar/JSON/YAML |
| Tar failure | Snapshot, successful decode, attempted headers; no JSON/YAML |
| JSON/DSSE rejection | Archive prefix plus rejected JSON/DSSE; no YAML or validator |
| YAML or tree/shape rejection | Accepted JSON/DSSE, YAML ledger and validator preflight; no fields encoding or path helpers |
| Fields rejection | Accepted JSON/DSSE, shape-conditioned YAML and only recursively field-valid encoded prefix items; full reached scratch and validated child-prefix work remain charged; no path Split |
| Fields success, relations/metadata rejection | Accepted JSON/DSSE, fields-conditioned YAML, serialization, regex and path helpers; ownership relation unavailable |
| Manifest success, publisher/file rejection | Complete-valid YAML/validator and archive success upper row, including fingerprint, File vector and sorts when reached |
| Completed Load | Complete-valid families and all result clones |

Fingerprint construction at `loader.go:110-111` precedes publisher rejection. File vector allocation at `:122` and sorts at `:131-132` precede later file-set/size/digest failures. The smaller archive prefix never covers those late errors. Success upper rows conservatively include result clones that those failures do not reach.

## Archive and zstd proof

`frame.go:86-163` checks one frame, explicit size, window at most 8 MiB, no dictionary, checksum, bounded blocks and exact end. `frame.go:31-36` supplies concurrency one, low-memory mode, cap limiting and exact capacity `S`. `NewReader(nil)` returns before streaming Reset; streaming channels, context and goroutines are unreachable. `DecodeAll` runs synchronously and Close runs on all exits. History aliases output. A copied compressed `dataStorage` and asynchronous sequence vector are unreachable, but the synchronous Go sequence fallback is reachable and is charged.

Snapshot capacities start at 32768, double and end at the checked `C+1` clamp (`frame.go:readSnapshot`). Every unclamped backing is an exact page multiple; only the clamp and final archive clone add page rounding. Snapshot/chunk is at most `3C+8194`, and adding the success archive clone gives `4C+16385`. Actual-size alternatives are snapshot `4A+8191` and success `5A+16382` when `A>32768`; when `A<=32768`, snapshot/chunk is 65536 and success adds at most `A+8191`. There are at most 17 snapshot backings, one chunk and one archive clone.

At `blockdec.go:367,399,432`, literal growth allocates exactly `n+16` visible capacity and the next request requires `n>oldCapacity`. No other assignment reduces that capacity. Successive growth n values therefore differ by at least 17, including across literal modes. Each successful literal size belongs to that block's output. Low-memory RLE scratch requests `n+1` (`blockdec.go:152-155,208-210`) at strictly increasing n, including the initial zero-size request. Successful RLE and literals belong to different block types, so both charge jointly to completed output at most `S`. One final failed literal/RLE block and one compressed scratch backing each cost at most 139264. With `K=131072`, full tiny event charges give:

```text
rho(n)=max(0,4A0(n+16)-5n)
Dlit(n)=max(Dlit(n-1),rho(n)+Dlit(n-17)); Dlit(n)=0 for n<0
Dlit(K)/4=481/4
sum(max(0,A0(n+1)-1.25n), n=0..K)=640/4
combined residual=1121/4=280.25 <= retained1356
literal plus RLE/compressed scratch <=1.25S+279884.
```

The finite literal recurrence maximizes every legal spacing history, with n=0 included conservatively; a sum over all consecutive n would ignore the source spacing. At most 7711 literal backings occur. Capacity monotonicity alone is insufficient; spacing, completed-block output and one terminating block establish amortization. All final archive constants remain unchanged because the corrected residual fits their retained 1356-byte charge.

A successful frame has only its exact output backing, at most `S+8191`. A bad final block can grow raw/RLE/zero-sequence output. Nonzero-sequence fallback at `seqdec_asm.go:115-117` can also allocate temporary output before append. Each temporary is at most `K` and corresponds to mandatory output growth. For `S>=4K`, the first 1.25 growth leaves at least `K` slack, so only one growth occurs. For `S<4K`, summing backwards across capacities growing by at least 1.25 bounds grown output plus matching temporaries below 8 MiB. Uniform extra failure cost is `1.25S+8 MiB`, at most 54 growth plus 54 temporary objects. This never coexists with tar or YAML.

Cold decoder setup in isolated execution costs 304064 bytes:

| Family | Bytes | Source |
|---|---:|---|
| Decoder/options/block/frame/channel/CRC/bitreader/defer descriptors | 1616 | zstd `decoder.go:88-122`, `framedec.go:228-232`, `blockdec.go:639-647`; Go channel layouts |
| Three 5128-byte FSE decoders rounded to 5376 each | 16128 | `fse_decoder.go:14-43`, `blockdec.go:560-620` |
| Huffman/FSE scratch, tables, cold buffers and failed weight output | 278144 | `huff0.go:166-172`, `huff0/decompress.go:129-139,223-228`, `fse/decompress.go:173-188,288-329` |
| Three 128-byte local arrays and shared FSE queue/ring | 560 | Go `sync/pool.go:68-77,224-245`, `poolqueue.go:204-226` |
| Cold predefined tables, including encoder transforms | 7616 | `fse_predefined.go:75-107,146-155`, `fse_encoder.go:79-98` |

FSE weight table growth uses powers `2^5..2^15`, cumulative 262016 bytes. Successful weight output stays in the supplied 256-byte array; one excessive output terminates decoding. All three native escape artifacts show the four inlined `huff0.Scratch.Decoder` descriptors do not escape. The standalone method's escape result does not describe these calls. Native assembly is active; a generic noasm Huffman substitution requires new proof.

Strict regular USTAR preflight precedes `tar.NewReader` (`tar.go:154,171-175`). PAX/GNU/sparse/link/STAR helpers are unreachable. Count raw header/name conversions even before rejection. Per attempted header, Header and bounded numeric/text parsing, prefix join, portable Split and potential segment conversions cost at most 5620 bytes and 151 objects; Reader/Header costs are already included in 5620. One terminating malformed path can have 241 Split elements, requiring a 4096-byte scanned backing instead of the normal 2048; charge the additional 2048 once. Retained member capacities `16,32,...,4096,4098` sum 12274 forty-byte slots, rounded cumulatively to 501568 bytes in ten backings. Body vector costs 163840; File vector costs 327680. Body data alias decoded tar until success.

Successful body clones cost at most `1.25D+28672`. This tighter batch bound uses raw classes with a separately proven tiny-packing tail, not the false full-event `1.25n+7` lemma. In one uninterrupted GC-off, non-race, P=1 noscan copy batch, cumulative actual-minus-raw debt is at most eight bytes from any initial tiny-cache offset. Positive debt implies cached offset at most eight; the next request at most eight fits under tiny alignment. A larger tiny request that fits pays zero against raw sixteen, and one needing a new block cannot replace cached offset at most eight. Requests at least sixteen do not change the tiny cache (`runtime/malloc.go:1254-1295`). Finite offset 0..16/request 1..15/debt 0/8 transitions establish the invariant.

`bytes.Clone` appends to an empty slice (`bytes/bytes.go:1391-1395`); growslice rounds byte requests 1..8 to capacity eight before malloc (`runtime/slice.go:201-216,263-265`). Exact-size lowering also satisfies the invariant. The body clone loop (`loader.go:150-152`) only clones/assigns headers, with no interleaved candidate tiny family; its maximum residual is `(27/4)*4096+8=27656<=28672`. Potential portable-segment copies form a separate batch of at most 120 copies/240 bytes, giving `1.25*240+(27/4)*120+8=1118<=1140`. `runtime/string.go:225-234,331-338` supplies the same byte-copy mechanism; zero-copy/stack lowering only reduces cost. The constructor's eight-byte channel queue holds a pointer, so its scanned raw eight-byte class requires no noscan tiny charge.

Manifest/envelope clones cost `B+E+16382`; archive clone is already included in the snapshot term. Fingerprint and both reflection sorts cost 768 bytes and at most 11 objects. Sort recursion uses the smaller partition, at most 13 frames. Source sites are `loader.go:79,110-111,122,131-132,150-155`, Go `sort/slice.go:24-29` and `internal/reflectlite/swapper.go:65-76`.

The per-file digest string-to-byte conversion at `loader.go:129:70` is nonescaping and zero-copy in each complete native `escape-decisions.txt`: Linux lines 11648-11649, macOS lines 11593-11594 and Windows lines 11647-11648. These current `native-field-38362276804/{ubuntu-24.04,macos-15,windows-2025}/escape-decisions.txt` artifacts bind the pinned Go 1.27.1 source identity below. The archive table consequently charges no fallback 64-byte conversion backing or object per file; this omission requires that exact three-target compiler binding. SHA return values and source-local fixed arrays remain in the compiled stack metadata or conservatively charged crypto family. Any source/toolchain change affecting the conversion requires renewed evidence.

The authoritative combined archive rows exclude JSON `J`, YAML `Y`, validator `V`, shared registry `H` and formatting `Q`:

| Domain | Archive bytes |
|---|---|
| Completed success or late post-validation failure, admitted caps | `4C+3.5T+27,831,590` |
| Same domain, `A>32768` | `5A+2.25S+1.25D+B+E+5620m+1,647,431` |
| Same domain, `A<=32768` | `A+2.25S+1.25D+B+E+5620m+1,704,776` |
| Failure through manifest-validation rejection, compressed cap | `3C+2.25S+5620m+1,265,741` |
| Same prefix, `A>32768` | `4A+2.25S+5620m+1,265,738` |
| Same prefix, `A<=32768` | `2.25S+5620m+1,323,083` |

The prefix constant is `8194+288075+304064+501568+163840`. Decoder failure instead has upper row `4C+3.5T+9,128,188`, plus `H/Q`, and stops before all later families. A finite conservative archive object cap is 762041, comprising snapshot 19, literal 7711, RLE 131073, compressed scratch one, failure growth/temp 108, cold helpers 58, tar `151*4099+1`, vectors 12, fingerprint/sorts 11 and body/control clones 4098. Object inventory is evidence, not an invented acceptance threshold.

The bounded read-error holder stores the exact cause interface, returns static text, matches ErrRead and unwraps without invoking cause methods. Each reached failure site costs at most 64 bytes and one object. Reader callback work and caller-directed unwrapping are outside the isolated library bound. The exact-length sorted membership and static-text read-error fixes have independent prerequisite approval.

## JSON and DSSE proof

Go 1.27.1 selects `encoding/json/v2_stream.go` and `encoding/json/jsontext`, with default experiments and no override. Legacy stream/unquote/scanner locations cannot prove this candidate. `envelope.go:17-85` walks the entire token stream with UseNumber and at most four containers; a fifth opener can grow a stack once before rejection. DSSE `parse.go:124-224` checks every signature before its count check, so rejected multiple-signature arrays require both complete token walks. Closed exactly-one-signature paths have nine string tokens per walk. Syntax, UTF-8 and surrogate pairing checks precede base64.

Each streaming decoder has Reader/wrapper/state/options descriptors, token and name-offset stacks, and cumulative buffers `64,128,...`. The full series through 4 MiB is 8388544 bytes. v1 AllowDuplicateNames disables generic namespace maps. String Token creates decoded string/interface storage and nonverbatim scratch; Number creates lexical/header/flag storage. Valid aliases envelope bytes through the buffered decoder pool, without another streaming buffer or arshaler cache. Source sites: `v2_stream.go:38-57,250-260`, `jsontext/decode.go:122-155,204-228,582-590`, `jsontext/token.go:278-299`, `jsonwire/decode.go:258,413-419`.

### Accepted whitespace and suffix coupling

Let `b=B`, `p=4ceil(b/3)`, `e0` be input prefix through the accepted root close, `l` the quoted payload span and `v` be one for nonverbatim payload spelling. Let `s` be the payload intersection of the one payload-name copied raw suffix. Name copy precedes refill (`decode.go:175-181`); each saved name is copied once after its offset becomes nonnegative (`state.go:666`). Earliest complex-name suffix intervals are disjoint except a fixed name can straddle one refill by at most 68 bytes. Five allocated name backings cover all names, and decoded ancestor prefixes total at most 16 bytes per event. Thus cumulative names per walk satisfy

```text
Names <=1.25*(e0-l+s)+42445
42445 =1.25*(5*68+5*16)+5*(192+8192).
J_json_normal <=2*((4MiB-64)+v*l+p
                    +1.25*(e0-l+s)+150476+42445+320).
```

The 150476 fixed token charge includes fixed spellings, nine boxes and eighteen page gaps; 320 charges five discarded trailing errors. Normal accepted buffers reach at most 2 MiB before root close: that buffer reads all remaining source bytes, so no further names fetch occurs. General `s<=min(l,1MiB)` applies. All fixed nonpayload syntax uses at most 1452 bytes even with six-byte Unicode spelling. If `p>1MiB+1452`, a pre-payload compaction of a 1 MiB buffer would move payload start to at least `1MiB-1452` and violate `E<=2MiB`. The last growth retains uncommitted whitespace/fixed text, placing payload start at least `512KiB-1452`; consequently `s<=525740`. Otherwise `p<=1050028` and `b<=787521`.

Final trailing whitespace can force a 4 MiB EOF buffer after successful root close because uncommitted whitespace does not advance prevStart (`decode.go:837-846`). That refill requires at least 1.5 MiB trailing whitespace, hence `e0<=512KiB`, `b<=393216`, `p<=524288`. Use names `1.25e0+42445` and the full 8 MiB buffer series, with these smaller base64/PAE limits. Ignoring this EOF refill or uncommitted leading whitespace is invalid.

Add the following source families to each coupled two-walk expression, before maximizing:

```text
5355776 + 1048576 + 1808
+ A0(b+2)+3A0(p)+A0(66)+3A0(88)
+ A0(b+61+digits(b))+A0(61+digits(b))+2A0(7).
```

Base64 input conversions remain charged, along with decoded capacity including padding and canonical byte/string re-encoding (`base64.go:201-204,424-427`). PAE is one payload-plus-prefix backing (`dsse/pae.go:5-9`). Key admission costs 5355776 bytes: field residues have at most four words, products eight, at most 329 point-add calls with 19 field operations each, ten other field operations and 333 coordinate checks. Each field operation charges 520 bytes; GCD/Jacobi/Montgomery exponentiation use bounded Euclidean/fixed-width iterations. Large division/Karatsuba and Tonelli-Shanks are unreachable for this modulus (`ed25519key/key.go:30-66`, `point.go:20-50`, `math/big/nat.go`, `natdiv.go:597-651`, `int.go:867-888,973-997,1172-1174`). The 1 MiB standard-crypto cap charges native Ed25519/SHA, cold NAF/fixed-base/FIPS helpers and promoted fixed locals, including 64 largest 704-byte SHA work arrays. It is a derived finite inventory, not runtime slack.

All three native compiler artifacts establish that the exact four-byte surrogate conversion at `parse.go:94,105` does not escape and fits the compiler/runtime 32-byte temporary. Valid has already checked four hexadecimal digits, so no ParseUint error allocates there. The accepted complete caps are:

| Accepted branch | `J` heap bytes |
|---|---:|
| Normal large payload | 30152019 |
| Normal small payload | 29380515 |
| Final trailing-whitespace EOF growth | 29353762 |

Use their maximum 30152019, rather than summing unrelated JSON and base64 maxima. Accepted objects are at most 104697. The alternative charging every four-byte surrogate copy is 35744419 bytes; it is unnecessary only while the native conversion identity remains bound.

### Rejected JSON source maxima

For a quoted live ancestor key of length `n` with `u` unpaired surrogates, decoded length is at most `3(n-2)-15u`. Initial scratch reservation, geometric replacements, decoded copy, boxes and both Unicode-error passes cost at most `18.5n+15.5u+42048`. Other completed tokens cost at most `35(n+1)`; delimiters/separators establish total source charge at most `35(E+1)`. Syntax pointer length is at most `3K-15U+35`, where `K/U` sum the at-most-four live key spans/surrogates. Three pointer copies join the live-key terms to `35(E+1)-7.5K-29.5U+105`; maximizing sets `U=0`. Exact minimal append capacities give pointer backing sum 33258240 at `3E+35`; evaluating capacity-threshold endpoints proves

```text
max_K(PointerBackings(3K+35)-7.5K) =19762005.
```

Name preservation may reserve a raw suffix rather than just its decoded key. The full finite increasing-capacity graph through requests `3E` gives cumulative Names at most 37732840. This is an over-approximation of every append history, not a sampled chain. Cold syntax translation owns five fixed replacement patterns, total 73 bytes, longest 18, at most 147 trie nodes/tables; fixed quote/message/replacer helpers cost 47904. Source sites: `jsontext/errors.go:82-117`, `state.go:181-212,651-666`, `jsonwire/wire.go:130-160`, `v2_scanner.go:67-91`, `strings/replace.go:158-218,268-297`.

The hardest syntax cap at `E=2MiB` is reproduced by

```text
35(E+1)+37732840+19762005+4*42048+3*8192+105
 +(4MiB-64)+816+47904 =135331033.
```

A 4 MiB input buffer requires a terminal contiguous unfinished token or whitespace span of at least 1.5 MiB; completed tokens and keys then charge only the remaining prefix, giving 102689854. Pointerless preflight/UTF-8/surrogate rejection costs 119523003. Syntax-valid dense multiple-signature/shape rejection costs 131337371: both walks and copied-name errors are counted; one wrong numeric value replaces dense-token source bytes and does not add independently. Exactly one closed signature with arbitrary valid strings costs 68955552, including general base64/PAE/key helpers. Every branch stops before YAML. The maximum rejected `J+H` is 135331281, below the archive-prefix residual 136400082.25 at `F=1`; residual increases with `F`.

Per-source charges bound rejected objects by 16916380 using a charged minimum of eight bytes per allocating source event. Eight is not an asserted runtime minimum allocation size. This deliberately loose object cap is not an acceptance ceiling.
## Same-call conditional YAML proof

All variables refer to the same successfully converted tree. `L=B<=1048576` is raw YAML bytes, `N<=65536` is nodes excluding the document, `Sx/Mx/Ax` count scalar/map/sequence nodes, `S0` nonempty scalar nodes, `V` value scalars, `V0` nonempty value scalars, `Ea` sequence edges and `q<=1048576` total decoded scalar bytes including keys/bool lexemes. `Sx+Mx+Ax=N`, value scalars are a subset of scalars, and total edges are `N-1`. Here `Sx` differs from archive size `S`.

The same-call ledger `U<=67108864` supplies a mandatory source discount:

```text
Y <= U-[100max(S0-32,0)+48V+80Mx+272Msmall+56Ax].
```

Each pass's first small scalar buffer over-reserves at least 50 bytes, with at most 32 large-first buffers per pass; two passes give the 100 coefficient. Non-key string/number boxes over-reserve 48; map descriptors 80; nonempty maps of at most eight entries 272; boxed arrays 56. Bool static storage and empty strings only increase the discount. The first buffer can append an entire whitespace chunk, so its capacity need not be 32. The exact minimum discount is 50 at capacity 33. Sources are `yamltokens/budget.go:14-38,103-121`, `tree.go:229-259,303-319`, Go `runtime/iface.go:437-464` and allocator/map layout. Existing abandoned allocations remain charged. This discount is a source comparison within one call, not measurement subtraction.

A scalar/scratch byte buffer with largest visible length `b>0` has cumulative backings at most `5b+32`: capacities double until the final possibly clamped growth, previous sum is below twice the previous capacity, and the final capacity is at most `max(32,2b)`. Let `w` be maximum retained scratch lengths for disjoint whitespace/break slots. Two passes cost `10q+10w+64S0`, plus fixed scratch offsets. Node value copies cost `1.25q+16S0`; Node/Content logical storage contributes `160N`.

Live token lookahead continues only while a saved simple key is at queue head (`scannerc.go:652-662`). Its source index expires after 1024 characters or a line change. At most 1025 consuming dispatches emit at most three tokens each; at most 64 indent ends and three boundary tokens add. Thus live queue is at most 3142. Compaction precedes growth, and pinned append capacities are `1,2,4,8,18,37,75,151,341,625,1024,1479,2048,2787,3697`; every abandoned backing totals 1771568 per pass. Sources: `scannerc.go:882-932,1002-1067,1363-1428`, `apic.go:57-70`, Go `runtime/slice.go`.

After shape success, closed inventory has at most thirteen map properties. Actual maps cost 48 empty, 336 for one to eight entries, 664 for nine to thirteen. A seven-node file/outbound record costs 336; component inventory implies total map cost at most `59N+1680`, or after fields `48N+336Kc+1680`. Arrays cost `20Ea+40Ax`, including boxed headers; value boxes `16V`. Scalar resolver copies/errors cost at most `2.5q+80V`: one underscore-stripped string, one float-range-error clone and one 48-byte error per value; keys start with a letter and never enter those branches. Resolver errors that fall back to strings remain charged (`yamltokens/resolve.go:48-76`).

Fixed `F0=3869992` consists of entry 16640, two readers 4096, simple-key/indent/state/mark 18176, arity 262144, token backings 3543136, duplicate scratch 208, fixed conversion 7184, exact arena rounding 16384, five inventory maps 1680, document Node 152 and scratch offsets 192. Exact Node/Content arenas and bounded iterative converter preserve the existing parser audit.

The direct same-call formulas are:

```text
Yshape <=F0+13.75q+10w+219N+80Sx+96V+20Ea+40Ax
       <=55971112.
Yfields <=F0+10L+3.75q+208N+80Sx+96V+20Ea
          +336Kc+40Ax+7680 <=44804160.
Ycomplete <=40361796.
```

Shape allows arbitrary field-rejected text/arrays. Fields acceptance permits scratch-origin whitespace only in publisher/license, total 768 bytes, and short escapes `\L/\P` only in publisher. Their expansion and retained scratch are disjoint, so `q+w<=L+768`; never assume `q<=L`. Fields also gives `Kc<=64`, `Ax<=263`. Complete validation additionally enforces ownership, giving `N<=62437`, `V<=29204` from fixed values, at most 200 per browser component and four per listed file. These stricter bounds apply only after their named stage succeeds.

## Manifest storage, serialization and helpers

Shape preflight precedes fields (`manifest.go:43-58`, `fields.go:118-209`). Only map[string]any, []any, string, bool and json.Number reach encoding. At `fields.go:175-185`, each reached array first passes cardinality, allocates its entire exact-length seen slice, recursively validates the child, then retains `encoding(v)` through `tree.go:71`. Scalar success establishes local field rules; object success establishes all children; array success establishes cardinality, children and uniqueness. Induction therefore makes every encoded item recursively field-valid.

An invalid child, duplicate child array or partial invalid component returns before its own enclosing item encoding. Earlier valid descendants/siblings of a partial component may already have encoded and stay charged; map visitation may select any subset before failure. Root invalid file records have no component ancestor and likewise do not encode. Every reached seen backing is charged at its full checked length even if the first item fails. Structural equality, sorting private strings, input immutability, sentinels and whole-stage precedence remain unchanged.

Each original occurrence is encoded at most twice: through its field-valid direct item and a field-valid component ancestor. Accepted JSON containers remain at most five and map keys thirteen. Let Kc count components reached after the outer maximum-64 cardinality gate, including a partial last component; an excessive outer array reaches no component work. This reached count is not the unchecked whole-tree component length.

Membership storage follows [manifest section 6.1](../../../../docs/specs/extension-manifest.md#61-deterministic-validator-membership-storage): exact checked-length slices, iterative heapsort and lower-bound search, one owner byte per listed path. There is no input-sized hash-directory growth. With `Ac<=7+4Kc<=263`, pinned class arithmetic gives `Ap(16n)<=20n+16`, `1<=n<=4096`, hence

```text
Vsets <=20N+40Ac+Ap(16*64)+Ap(16*4096)+A0(4096)+3Ap(24)
      <=1392096 bytes, <=532 objects.
```

The remaining five used-kind/interface inner maps and their outer map have at most four/five entries, all eight-slot groups; cost 1632 bytes/12 objects. The general set-only contract bound 9521456 bytes/131078 objects is conservative; the tighter closed-schema row above does not include encoding output/helper costs.

### Pooled encoding recurrence

`jsonwire/encode.go:68` reserves `len(src)+2` before escaping. `jsontext` owns output buffers and underutilized discard (`pools.go:78-85`). Enumerating capacities up to 1.5 times the maximum logical output `6*1048576+6*65536=6684672`, with source nextslicecap intervals and class/page endpoints, gives 1282 states and 214578 transitions. Dynamic programming from initial 64 retains every abandoned backing and proves

```text
G_chain(lg)<=6.25lg for lg>=65, at most38 objects; grown capacity <4*request.
```

`lg` is a growing call's final output length, or the largest such length within that physical lifetime. This theorem does not compare an initializer with later tiny no-growth output. Direct field-valid files/outbound/paths/MIME encode to at most 355/295/242/749 bytes. MIME uses `127+5*124+2=749`, including HTML ampersand escaping, and remains below 1 KiB. Only component outputs can exceed 1 KiB.

A physical lifetime starts at the pool's initializer make and ends at Buf=nil or this call's final encoding. The cold exclusive P=1/GC-off/non-race pool proof uses three disjoint charges (`jsontext/pools.go:46-85`):

1. If the largest growing-call output exceeds 1 KiB, charge the whole initializer/replacement chain once to that maximum-output component call. The cold-64 finite recurrence includes the initializer; a larger power-of-two initializer embeds as one legal virtual growth from 64, with subsequent actual edges, dominated by the chosen output. Whole charge is at most 6.25*lg.
2. Otherwise, if the inherited initializer exceeds 4 KiB, no output request at most 1 KiB can grow it. Only the initializer allocates. Its power-of-two size is at most max(64,2*l) for the immediately preceding allocation-free discard. Such a large seed requires a component discard; charge it solely to that call, with 2*l<=6.25*l.
3. Otherwise the initializer is at most 4 KiB and every growing output at most 1 KiB. Exact finite arithmetic across initializers 64..4096 and all requests through 1024 gives 26624 transitions and whole-chain cost at most 4096, within retained 6400. Replacement capacities stay at most 2048. Capacity at most 4096 always recycles, so this stable small lifetime cannot end by underuse discard.

Owners are distinct: a growing call leaves capacity below four times its request and cannot also discard. Every lifetime receives exactly one charge, so an initializer is not assigned both to a growth owner and a prior discard. Component owners are at most Kc; the retained Kc+1 stable-small-episode count is conservative under either visit order. This gives the current valid-prefix recurrence

```text
Gbuf_prefix<=6.25Lc+6400*(Kc+1).
```

Lc sums reached field-valid component outputs. Valid descendants of a partial invalid component remain inside small chains/copies/reflection and exact reached scratch; that ancestor contributes no large encoding. This proof includes inherited no-growth initializers and abandoned growth, not only final capacity. Independent lifetime clarification SHA256 is `31161eee4f2503faa921aa6d04ba179fb2a06ed4fdd62d62058ed8f0551a8945`.

Result byte/string copies obey `2sum A0(l_i)<=2.5sum l_i+32Kcalls`, checked at every size-class/page lower endpoint. Reflection costs

```text
16Kcalls+32(Kc+Mlisted+Uout)
+40(8Kc+3Mlisted+3Uout)+16(Mlisted+13Kc+2Uout).
```

The numeric term `Wnum=Mlisted+13Kc+2Uout<=13120` applies to every actual encoding because each item has passed field checks. It does not count unchecked unencoded tree values. On rejection, array-item encoding calls use distinct nonnumber nodes, arrays cannot contain numeric items, and each original numeric value has a distinct map-key node and is serialized at most twice. Therefore `Kcalls+Wnum<=N`, so their combined sixteen-byte cells cost at most `16N`. Direct-item map/pair caps remain bounded by cardinality checks before child encoding. The rejecting reflection bound is `16N+32*(64+4096+4096)+40*(8*64+3*4096+3*4096)=2316288`. The broader 2526208 family cap used in relaxed sums remains conservative; no unchecked unencoded descendant is assigned an encoding visit. Number.MarshalJSONTo uses its 64-byte AvailableBuffer and ConsumeNumber/WriteValue (`encoding/json/v2_decode.go:212-233`), without another Valid/encoder borrow or pool registration; canonical unsigned at-most-twenty-digit preflight excludes its formatting error.

MapRange and key/value reflection descriptors, including Number method handling, are charged; a generic member vector is unreachable for concrete string-key maps. Four nested map-sort depths cost 5856 bytes/52 objects: each owns a 24-byte header plus backings for sizes 2..13. Pooled state is retained only in the isolated context.

Portable path Split runs after all fields succeed (`relations.go:127-141`). ASCII path length `l<=240` has at most `(l+1)/2` nonempty segments; exact class/header arithmetic gives `Ap(16r)<=19r`, `r<=120`. Total cost is at most `19(Bpaths+path_occurrences)/2`, generally 10584064 bytes and at most `N` objects. Segment bytes are not copied. This entire family is unreachable on fields rejection.

### Regex and cold fixed helpers

The twelve compiled patterns reach exactly four pools (`regexp/exec.go:521-549`): onePass, bitState, matchPool[1] and matchPool[2]. Identifier/registration has 2033 instructions (at most 65 calls); URL 283 (at most two); host 256 and version 53 use bitstate. Other 6..131-instruction programs use onePass. MatchString uses zero captures, so no match-result vector allocates.

Bitstate has one 176-byte state, 8192 uint32 visited words and job capacities `256,512,848,1280,1792,2560,3584,5120`, cumulative 255232 backing bytes. No AltMatch or epsilon cycle occurs. Maximum jobs are `1+epsilon_depth*(input_length+1)` with depths 2/2/5 and input maxima 512/1012/925, giving 4631. LIFO continuations and nondecreasing active positions establish this frontier. State plus bitmap totals 288176 bytes/10 objects. NFA machines have two bounded sparse/dense queues, at most `2I` threads with capture backings, every free-pointer backing, machine and fixed matchcap. Full regex cap is 731008 bytes/9312 objects. Source sites: `backtrack.go:80-133`, `exec.go:104-112,317-355`, `regexp.go:231-255`.

Six arshaler types are string, bool, json.Number, map[string]any, []any and any. Each charges a 24-byte arshaler, at most five 128-byte closure environments and three 16-byte captured cells, totaling 4272 bytes/54 objects (`v2/arshal_default.go:126,211,774,1465,1795`, `arshal_methods.go:256-259,352-355`). Default unmarshal closures are charged even though never called; struct/time/byte-array constructors are unreachable.

The frozen native ELF64/Mach-O64/PE64 descriptor walk asserts moduledata types/etypes at offsets 296/312 and follows exact ABI descriptor sizes, alignment, uncommon records and methods (`internal/abi/type.go:750-837`). Primitive types outside the index are reached through indexed pointer descriptors' elements. The current native loader.test binaries have one module and no plugin/shared-module loading. Independent six-binary extraction confirms the following complete-loader descriptor table:

| Target | Indexed descriptors | Descriptor bytes | Initial index capacity | Rounded backing |
|---|---:|---:|---:|---:|
| Linux x64 | 1867 | 197288 | 2055 | 18432 |
| macOS ARM64 | 1838 | 194824 | 2029 | 16384 |
| Windows x64 | 1874 | 199272 | 2075 | 18432 |

Initial capacity is floor(descriptor_bytes/96), larger than descriptor count; no index append growth occurs (`runtime/type.go:508-550`, `reflect/type.go:1754-1789`). Each of the six types is unique. Only []any has PtrToThis zero, and its pointer name has no indexed match, giving one pointer-cache miss, no typesByString result backing and one constructed pointer/name pair. Arshaler cache keeps the conservative six-entry hashtrie: sixteen four-bit hash levels give at most `1+15*(6-1)=76` indirect nodes plus six entries. Hash collisions use chains, without native-map directory doubling (`internal/sync/hashtriemap.go:50,165-195,540-575`).

Native cold cache cost is `18432+12448+208+4272+128+416+352=36256` bytes/148 objects: module type index, arshaler hashtrie, one-entry pointer hashtrie, closures/cells, pointer/name records, runtime name-offset maps and module-index cache. Runtime name-offset maps stay below eight entries. This binary-specific proof requires renewal if linkage changes; it does not use the full types/etypes region as an index-descriptor count.

Encoder state costs 576 bytes/nine objects: Encoder 320, five-level token backings 128, four name-offset backings 64 and number AvailableBuffer 64. Tiny backings receive full-block charges. Buffered successful Marshal cannot flush names (`jsontext/encode.go:160`) or produce semantic errors/StackPointer; v1 options disable namespaces. All three native artifacts keep the fixed encoding option and relation literal arguments off heap, while the result string copy remains charged.

URL checks are at most two 2048-byte ASCII strings, after relations. Grammar excludes IPv6, zones, userinfo, fragment and malformed host/percent branches. Charge URL, path builder/unescape/re-encoding, both potential byte conversions, netip and port-error descriptors by

```text
2*(Ap(144)+3A0(2048)+2A0(6144)+2Ap(48)+A0(5))=37376.
```

Tree ParseUint overflow costs at most 72 bytes/two objects; retain it conservatively although it does not coexist with metadata. License parsing uses substrings/fixed locals, at most nine active expression/term/factor frames each. Successful buffered Marshal has no syntax pointer/name flush/error; default v1 options disable namespaces. Exactly one manifest failure wrapper has static rendered output at most 44 bytes; its cost belongs to `Q`, not the manifest tail.

The fixed tail before pool-local/queue storage is `36256+576+37376+72+1632=75912` bytes/191 objects. Six manifest pool-local arrays add 768 bytes/six objects (`sync/pool.go:68-79,224-244`). Four simultaneously borrowed string-sort slices return one to private storage and three to a shared queue; one 48-byte chain element and 128-byte eight-interface ring add 176 bytes/two objects (`pool.go:112-117`, `poolqueue.go:220-228`). The queue does not fill or lose its element under isolated P=1/GC-disabled reuse. Other manifest pools hold one object at a time. The full cold tail is therefore `76856` bytes/199 objects, excluding shared registry H and formatter Q. These frozen completed-family bounds have scoped independent review for their source/binary context. The fields-first prefix transfer preserves these source families, and current native cache/escape extraction confirms the retained constants.

### Complete-valid joint formula

Let `P` be component file references, `Rpol` browser policy strings, `I` MIME strings, `X` other capability strings, `Uout` outbound records and `Re<=11` required interfaces. `Cstr=P+Rpol+I+X`; `Kc<=64`, `Mlisted<=4096`. `Hmime` counts MIME ampersands, at most 124 per MIME/32 MIME per parser component. Only these accepted serialized ASCII bytes HTML-escape. Define `Bc` component text and `Bd` text copied by direct descendant calls. Then

```text
Lc<=Bc+5Hmime+3Cstr+18Uout+150Kc
sum l_i<=q+Bd+10Hmime+5Cstr+35Uout+17Mlisted+150Kc+22
Kcalls<=Kc+Mlisted+Cstr+Uout+Re.
```

Complete relations impose `P<=Mlisted`; component file path text is at most listed path text plus `delta<=30720` for at most two additional path occurrences per component. Joint output/Split weighting becomes `16.375Bpaths+4.375delta`. Other serialized text costs at most 11.25 per byte. The MIME extra after using 16.375 for nonpath text is `51.125Hmime`. The resulting variable/model bound is

```text
Vmodel<=16.375q+4.375delta+99.25Cstr+452Uout+318.75Mlisted
        +1979.5Kc+40Ac+68Re+175+6400(Kc+1)+731008+5856
      <=33489395.
```

Use `P<=Mlisted` to combine their cost to `418Mlisted`. Per-component capability and MIME costs share the same 64 components: parser maximum 206120, browser 19216, connector 29008, console 2998.25, responder 973.25, others 40. Maximizing these jointly, rather than summing every kind's independent maximum, proves the model cap. With the independently reviewed 76856-byte cold tail, `Vcomplete<=33566251`.

Fields-success/relations-failure cannot use ownership. Its independently reviewed general bound is `Vfields<=46042575`: growth 16194400, copies 14532087, reflection 2526208, sets 1392096, Split 10584064, regex 731008, sorts 5856 and tail 76856. The amended ordering extends it to field-rejecting valid prefixes, including partial descendant work, because every actual encoding satisfies the same field-valid premises. The bounded implementation is independently approved and current native binary binding is independently confirmed; the complete source proof and qualification evidence have independent approval.

The conservative success validator object bound is `2N+145344+N+532+52+9312+199+4967=357014`, using N<=65536. Retain the broader 357091 all-stage cap, including 77 extra conservative overcount objects beyond the 357014 complete-valid cap. The amended rejection only encodes field-valid prefixes and introduces no extra unchecked encoding lifetime; partial children/full seen scratch remain covered. The 4967 output term includes 38-object histories and initializers across 64 components/65 small lifetimes. This is a source inventory, not a full-loader object acceptance ceiling.

## Shared registry, formatting and runtime context

The twelve reached dependency pools are zstd Huffman/FSE/Scratch buffer, fmt printer, math/big stack, jsontext buffered decoder/encoder, jsonv2 string-sort and four regexp pools. There is no loader-owned decoder cache/shared ledger. The independently reviewed [loader section 2.1](../../../../docs/specs/extension-loader.md#21-pinned-dependency-state) permits only these exact pinned transitive families, with reset, retention, ownership and initialization-before-read obligations. Design approval does not prove those source obligations.

The active reuse paths preserve these concrete boundaries; they do not erase every retained byte:

| Borrowed state | Initialization, retention and output boundary |
|---|---|
| Zstd Huffman/FSE | `history.go:35-46` clears logical history, restores recent offsets, frees sequence tables, clears Huffman/dictionary pointers. New-frame repeat mode requires a current table. `blockdec.go:439-456,579-619` reads/transforms current Huffman/FSE or sets current RLE before use. Buffers/tables may retain bytes; failed initialization terminates the frame, with no Package returned. A borrowed Scratch not returned on an early table error increases cold allocation, already charged, but does not enter another output. |
| JSON buffered state | `jsontext/pools.go:46-59,132-139` resets encoder logical buffer length/state and decoder source/state on acquisition. Decoder return drops its source buffer. Encoder may retain bytes and strikes; repeated underuse discards/regrows even with GC off. `v2/arshal.go:163-173` clones completed output before deferred return. Loader then owns a separate string copy. |
| JSON names/type caches | `v2/arshal.go:547-561` resizes borrowed name scratch and clears references on return. Current MapRange fills names before sorting. Arshaler/reflect caches retain immutable type helpers for closed types, not package values or verification results. Cache publication and fixed type-helper initialization are charged in the native tail. |
| Regexp | `backtrack.go:80-110` resets jobs, clears visited bits and initializes captures; `exec.go:397-408` resets one-pass match state. `regexp.go:262`, `exec.go:392`, `backtrack.go:58` clear input references on return. NFA queues mark current PCs and release current threads. MatchString produces only a bool with zero captures; retained machine scratch cannot alias Package data. |
| Formatting/arithmetic | `fmt/print.go:145-174` resets printer flags and buffer length, clears wrapped-error length and retains at most 64 KiB buffer. Every returned Errorf message is copied. `math/big/nat.go:280-290` lends exclusive scratch and returns its logical length to zero; current arithmetic writes reached result words before use. Retained words are public-key intermediates. No scratch slice is returned by key admission. |

Zstd Close does not establish erasure or release of every input reference. `Decoder.Close` drains its channel, but `blockDec.Close` is empty (`blockdec.go:221-224`); final one-frame Huffman/FSE tables are not necessarily returned through a later history reset. A registered Scratch.decPool can keep its owning Huffman Scratch reachable through runtime allPools/oldPools, and the embedded FSE scratch byte-reader can retain a compressed-weight subslice of the received archive. The archive can therefore remain retained until pool GC generations drop that owner. This affects retained-heap/RSS interpretation; it does not add a second archive allocation, expose mutable result aliases or supply erasure. By contrast, buffered JSON Valid explicitly drops its borrowed input on return (`jsontext/pools.go:138`).

`sync.Pool.Get` removes a borrowed mutable object until Put; the synchronous caller does not publish it while borrowed. Lost/evicted objects may allocate again; exclusivity does not imply survival or erasure. Every call repeats signature verification and binding. Successful Load clones exported archive/control/body slices; tree strings/maps belong to that call's new YAML arena/conversion. Failure returns zero Package. Separate normal-scheduling two-call ownership/race evidence tests this boundary; the table supplies source reasoning, not independent Gate B approval.

Under fresh-process `GOMAXPROCS=1`, prescribed pre-snapshot GC, GC disabled through the snapshot and no unrelated runnable pool user, `sync/pool.go:272-281` clears allPools before the interval. Registrations grow pointer capacities `1,2,4,8,16`, charging `H=248` bytes/five objects once. Per-pool local/ring costs stay with their owning family. Candidate code remains cold; runtime preparation is not candidate warmup.

Only decoder or manifest terminating errors format. Decoder can make two bounded Errorf calls, leaf at most 80 bytes then 25-byte wrapper, or one leaf at most 113. Arguments are bounded integers/static errors, never raw content or arbitrary caller causes (`huff0/decompress.go:64,841,1075`, `fse/decompress.go:251`, `seqdec.go:336`). Manifest makes one static wrapper at most 44 bytes. These alternatives cannot coexist. `fmt/print.go:121-176`, `fmt/errors.go:36-65` and finite 113-byte growth give

```text
Q<=Ap(168)+128+GrowthFinite(113)+2A0(113)+2Ap(32)+A0(8)
   +2*(3A0(8)+Ap(48))=1256 bytes, <=157 charged events.
```

`Q=0` for JSON/DSSE rejection and completed success. This cost includes fmt's local once and excludes `H`. Its 157-object bound comes from the positive charge attached to each enumerated allocating source event within the 1256-byte inventory. This source bookkeeping argument does not assert a minimum runtime allocation request or object size.

Normal GC can evict pool locals, retain/drop victims and force reallocation; changing `P` adds rounded `128P` locals. The exact residue includes cumulative local/ring/replacement buffers and registry growth at each reached registration, depending on preexisting registry length. Outside concurrent work is not bounded by input caps. Therefore `H=248`, one cold regex/sort/cache term and the stack theorem below are isolated qualification results, not arbitrary-public-runtime guarantees. Separate serial/two-call normal-GC evidence passes with raw counters and no exclusions. Adoption by a production consumer still needs reviewed resource/concurrency context.

## Current native full-stack proof

Linked Go 1.27.1 ELF/Mach-O/PE pcsp records supply `maxSP(f)` using `runtime/symtab.go:1219-1233,1284-1310`. Preserve ABI wrappers even when printed names repeat. Define `W(f)=align16(maxSP(f)+max(args(f),0)+16)`. Incoming/outgoing ABI space is already in caller frames (`cmd/compile/abi-internal.md:190-224`); unknown assembly args need no duplicate charge, while known args are conservatively added again. This includes assembly and linked functions omitted by focused compiler selection.

Charge one union copy of every linked function, excluding only 27 `runtime.call16` through `runtime.call1073741824` reflected-call argument trampolines. They require Value.Call/CallSlice, MakeFunc or reflected method values, none reachable with these closed types. JSON uses concrete TypeAssert and typed interface calls; sort reflectlite uses typedmemmove. Other irrelevant functions remain overcounted once.

Charge every member of a recursive strongly connected component, not a representative frame. Linked JSON symbols have multiplicity six, reflection five, pdqsort fifteen, Once/OnceFunc/OnceValue two. Cold Ed25519's outer self-test Once retains the inner fixed-table Once. Remaining source multiplicities are:

| Family | Maximum active frames per function |
|---|---:|
| Envelope walker / JSON Valid value recursion | 5 |
| Valid object/array containers combined | 4 |
| Fixed error-replacer trie | 19 |
| YAML node child / manifest tree visit | 17 |
| Manifest shape / fields | 9 each |
| License expression / term / factor | 9 each |
| Regexp machine.add | 2034 |
| YAML duplicate pdqsort | 15 |
| Final File/member pdqsort | 13 |

Machine.add marks the program counter before descending, so 2033 instructions plus terminal call bound recursion. Shape/container/node caps bound all other data recursion. YAML converter/inspection are iterative. Fixed closed type layers bound reflection descent. Unreachable recursion includes oracle/reflection YAML decode, JSON struct-field/unmarshalAny paths, reflected calls, HashTrieMap Range/All, regexp compilation before interval, big-integer large division/Karatsuba/even-modulus exponentiation and recursive fmt value printing. Runtime map/cache growth, interface hashing of string/pointer leaves and profiling bucket allocation are iterative/fixed-depth. GC-disabled execution excludes marking/shrink recursion. ABI alias self-relocations do not add activations; systemstack/morestack switches use fixed runtime stacks. The isolated reader is bytes.Reader or a fixed bounded failure reader, with no blocking callback, system I/O, plugin load or custom marshaler.

Let live-frame bound `Bs=sum W+sum((multiplicity-1)W)`. Pinned guards are 928 on Linux/macOS and 5024 on Windows. Doubling gives post-call candidate stack less than `2(Bs+guard)`; GC off immediately frees old large stacks and prevents repeated shrink/growth. Small span caches add at most four 32768-byte orders on Linux/macOS, two on Windows. Thus:

| Native target | Linked records | Union W | Recursive extras | Live Bs | Post-call growth |
|---|---:|---:|---:|---:|---:|
| Linux x64 | 6214 | 1068032 | 1043600 | 2111632 | 4356192 |
| macOS ARM64 | 6074 | 1100896 | 1073840 | 2174736 | 4482400 |
| Windows x64 | 6223 | 1112064 | 1047424 | 2159488 | 4394560 |

Final columns equal `2(Bs+928)+131072` or `2(Bs+5024)+65536`, all below 8388608. This proves post-call candidate StackInuse growth, not peak during copying or a process-wide guarantee under arbitrary scheduling. Runtime/helper activity remains in the raw qualification interval. Stack spans use allocManual (`runtime/stack.go:200,422`) and StackInuse (`mstats.go:187-194`); they do not enter heap TotalAlloc (`mstats.go:63-68`). Heap-promoted fixed locals remain charged. No measurement subtraction occurs.

The current table binds source `a19cc54e4748ff0c26379d634c3cb3f3581394ce` under Go 1.27.1 native compilation. The independent reviewer verified 78 repository compiler-input hashes per host, fourteen manifest-binary source entries per host, binary hashes and selected standard-library/compression sources (673/657/651 standard-library and 92/88/92 compression files on Linux/macOS/Windows); the qualification child hash is `8b4173d0ba4287a51f6615e11485108289ef887eadcd57690da84cb52f725897`. The reordered fields function has `(maxSP,args,W)=(344,24,384)` on Linux/Windows and `(368,24,416)` on macOS. The author and independent reviewer re-extracted pcsp and reproduced every linked count, union, recursive subtotal and final stack row without executing a foreign binary.

Native diagnosis run 38362276804 has three successful jobs. Retained artifact root is `.superpowers/sdd/extension-loader/native-field-38362276804/`, with `ubuntu-24.04`, `macos-15` and `windows-2025` directories. Each retains identity.json, manifest-identity.json, compiler-summary.json, compiler-frames.jsonl, escape-decisions.txt and both test binaries. Source/binary identities are:

| Native host | loader.test SHA256 | manifest.test SHA256 |
|---|---|---|
| Linux x64 | `3d20d17f67b45891930468a92858824cbfb4630dd8c8c9d90f8f7fefc761e132` | `e824d3de276cfc8fe956677f32d0ba9f22ce1323360837203514e5c72b85e008` |
| macOS ARM64 | `7e23d9f662780d97389d1c6509a52f40fc0828fee2fe4c1d230133ed508ead21` | `3245b3619e2a4852f06ec44a10afff16d290608a78682f343ce27da974cef710` |
| Windows x64 | `ead9419545e6913d37f6a59ea279b3731fe29cd6896787bb222fb1bda2b0d593` | `e7ae7927aaecdd32a55c6dd7b8181d5f2aeed8cc813be63badbf1ba328bad5bf` |

All compiler exits are zero, GOEXPERIMENT override is empty, and active JSON is the default v2-backed facade. The exact reached escape facts in each directory's escape-decisions.txt are:

| Fact | Linux lines | macOS lines | Windows lines |
|---|---|---|---|
| Four inlined Huffman Decoder descriptors do not escape | 8385-8386,8407-8408 | 8342-8343,8364-8365 | 8384-8385,8406-8407 |
| DSSE exact four-byte surrogate conversions do not escape | 10880-10881 | 10825-10826 | 10879-10880 |
| Manifest encoding option variadic does not escape | 11384 | 11329 | 11383 |
| Manifest result string copy escapes and remains charged | 11383,11385 | 11328,11330 | 11382,11384 |
| Relation fixed string slices do not escape | 11395,11399 | 11340,11344 | 11394,11398 |
| Loader digest conversion does not escape and is zero-copy | 11648-11649 | 11593-11594 | 11647-11648 |

The four-byte conversion uses the pinned 32-byte compiler/runtime temporary; other base64 input copies stay charged. Current native-binding details supplement frozen family reports without rewriting those reports. Any source/toolchain/experiment/linkage change requires renewed extraction, including descriptor-cache arithmetic. Sampled stacks alone cannot establish these limits.

## Complete-loader source byte domains

The reviewed complete-valid families bound completed success and late post-validation failure by

```text
Archive_success+Jaccepted+Ycomplete+Vcomplete+H
<=4C+3.5T+27831590+30152019+40361796+33566251+248.
```

The residual against the unchanged envelope is `6500128+0.5F` bytes. JSON/DSSE rejection is closed separately above; early archive/decoder failures stop before later families. The fields-first rejection domain below closes the source-level unchecked-encoding obligation. Current native binding confirms the retained family constants; these sums do not replace final Gate B/CI review.

### Admitted rejecting-prefix refinement

After a successful tar return, `m>=2` and `r=m-2` ordinary members. This domain has `A<=C`; oversize snapshot rejection remains outside it. Let a snapshot power be `32768*2^j`. If C is exactly such a power, the C+1 clamp is unreachable for admitted A and snapshot/chunk is at most `2C`. Otherwise let P be the largest snapshot power below C; geometric storage plus the one rounded clamp gives

```text
Snapshot(C)<=2P+8192*ceil((C+1)/8192).
Archive_prefix<=Snapshot(C)+2.25S+5620m+1257547.
```

The fixed 1257547 subtracts the coarse 8194 snapshot residue from 1265741; no result clone, File vector, fingerprint or final sort is reached (`frame.go:47-69`, `loader.go:90-109`). No compressed-size-to-tar-size ratio is assumed.

Each positive file body spends one admitted byte before earning its first padded block, and 512 additional bytes per further block. With `u=min(F,r)`, padded ordinary files are at most `512*(u+floor((F-u)/512))` for r>0, zero for r=0. Controls contribute at most 3 MiB padded bodies because both role ceilings are multiples of 512. Thus

```text
Smax(F,m)=min(T,1024+512m+3MiB+padded_files(F,m-2))
Rp(F,m)=4C+4T+134217728-Snapshot(C)-2.25Smax(F,m)
        -5620m-1257547-30152019-248-1256.
```

Smax/header charges are nondecreasing in m, so minimum Rp uses m=4098. Check every F<=4096. Above 4096, each 8192 increment inside an open snapshot-power interval increases Smax and rounded snapshot by 8192 and residual by 38912. Therefore each interval's first 8192 integer values and exact power boundaries cover all F through 1 GiB. Exact quarter-byte arithmetic over 69639 candidates yields:

| Minimum-residual quantity | Value |
|---|---:|
| F, m | 4096, 4098 |
| T, C | 8392704, 9441280 |
| Snapshot/chunk | 26222592 |
| Smax | 7342080 |
| Archive prefix | 67030579 |
| Contract envelope | 205553664 |
| Rp after accepted J/H/Q | 108369562 |

This is a conservative upper-proof extremum, without an assertion that all component maxima are attained by an archive. It corrects independently maximizing every file's padding at tiny F. All variables refer to one admitted call.

Before fields, flat YAML 67108864 plus even the entire manifest fixed tail 76856 leaves `41183842` bytes; encoding/sets/regex/Split are unreachable. After fields succeeds but relations/metadata rejects, Yfields 44804160 plus Vfields 46042575 leaves `17522827`. Ownership is not applied to this latter branch. These two unchanged rejection domains retain their scoped approval. Fields rejection now uses the separate shape-conditioned valid-prefix row below.

### Conservative complete-loader object inventory

For the isolated cold context, the reviewed source-family caps permit the following deliberately branch-insensitive finite inventory. The fields-first prefix transfer introduces no new source allocating family; current native extraction confirms the retained cache/escape charges:

| Family | Allocating objects/events upper |
|---|---:|
| Archive, decoder, tar, commitments and clones | 762041 |
| Maximum rejecting JSON/DSSE family | 16916380 |
| Entire YAML reservation ledger | 1000000 |
| Uniform manifest all-stage family | 357091 |
| Shared registry H | 5 |
| Bounded formatter Q | 157 |
| Additional conservative readError holder | 1 |
| Sum | 19035675 |

Accepted JSON's 104697 objects fit inside the larger rejecting-family row. These maxima cannot all coexist, so summing them only overcounts. The extra holder is retained independently even though an early read failure replaces success-only archive cloning. Caller reader callback work remains outside this isolated library model. Charged event caps use their source-family conventions, not a runtime minimum object size. The independent reviewer confirmed this sum and top-level holder coverage; refreshed native digest/cache/escape facts retain the same source-family inventory. Options, loadDependencies and Package pass/return value headers; direct function values have no allocated capture environment. Member/body/File backings, result storage, sort boxes and callbacks are already archive families. One private cause-interface holder (`errors.go:30`, `frame.go:74,81`) covers non-EOF/no-progress failure; returning its pointer through error adds no second cause-sized object. This confirmed finite inventory creates no object acceptance threshold, allocator ledger or arbitrary-runtime pool-history guarantee. Raw full-call object observations remain diagnostics.

### Field-rejecting valid prefixes

Shape completes before fields. The implemented child-before-encoding induction, full seen reservation and three-case pool partition therefore transfer Vfields to every field-rejecting prefix as Vprefix<=46042575. Late relation/Split/unvisited suffix helpers in that cap only overcount rejection. Yshape<=55971112 applies without assuming fields success. Against the admitted-prefix residual:

```text
Yshape+Vprefix<=55971112+46042575=102013687
108369562-102013687=6355875.
```

No invalid child or incomplete ancestor encoding reaches the scalar/tuple sixfold-escaping recurrence. Those families are absent from the amended source's current byte proof. The source ordering removes the unclosed branch without reducing text/node/cardinality limits, changing the corpus or adding slack. Frozen family source proofs and current native binding support this arithmetic; independent Gate B review and current-source CI confirm the complete qualification.

### Discriminating field-order regression

The external two-case `TestFieldOrderAllocation` uses a component-child path or root-file-record path containing 262144 ampersands. Tree/shape pass; every other field is a short valid literal. Each complete fixture has fewer than 128 original node/key occurrences, four length-one arrays and at most four encodings under any map visitation order. Invalid item/partial ancestor do not encode; each remaining valid output is below 1024 bytes. Setup recursively copies maps/slices without encoding and remains outside the cold one-processor/pre-GC/GC-off raw Validate TotalAlloc interval. Assertions/restoration/logging happen afterward; no warmup, retry, subtraction or time cutoff applies.

A premeasurement source upper is

```text
731008 regex +76856 fixed tail +1256 fmt +512 registry
+25600 four independent small chains +8192 two copies per output
+16384 reflection +128 full exact seen slices +5856 sorting
=865792 bytes.
```

The 512 registry term conservatively doubles the 248-byte pointer history for at most sixteen registrations; it is a source charge for this finite regression, not a whole-loader allowance. Four 6400 chains intentionally do not assume reuse. Up to 128 encoded visits at 128 bytes each cover fixture reflection; maps have at most seven keys, traversed at most twice. Four sixteen-byte seen slots are conservatively charged twice. Full regex and later fixed helpers are retained rather than reduced to actual fixture usage.

Local supporting ELF/Mach-O/PE manifest-test extraction found descriptor counts 1477/1454/1489 in 157656/155544/159256 bytes; initial capacities floor(bytes/96)=1642/1620/1658 exceed counts. Each index is at most 14336 bytes, below retained 18432. Six types are unique; only []any misses PointerTo with no pointer-name match. Those local builds are supporting static evidence, not native execution. Current independent native manifest.test extraction in run 38362276804 confirms the same counts and descriptor regions on the actual three hosts. Each current index allocates 13,568 bytes, native cache 31,392 and full tail 71,992, all below the retained 76,856-byte threshold tail. This binds the finite regression threshold without changing its ceiling.

Encode-first must allocate a copied JSON output containing at least `6*262144+2=1572866` bytes before rejection, already above 865792. Supplied valid cold red samples are 13785920/10624256 bytes with intended exit one; field-first samples 121368/137920 pass with exit zero. A disposable encode-first mutation again fails, 13785104/10503992. Behavioral cases pass in each order and prove compatibility separately. These two fixed cases distinguish source ordering; they do not claim an observed whole-loader overflow. This synthesis ran no tests.

Regression source SHA256 is `75f58e3f30394c5ea403470d9dc16aa0e7734f111fb77731fc23eeafeccc9754`; implementation report `39b690b8047ec5041134b09f210abd0717fe05217149e111c494f8ca5a063107`; threshold derivation `a60787fd24cf35f9a6d43346a52fb4c8e205fcfd085fb55f744de68719888102`. Primary verified focused ordinary tests. Independent code/adversarial report SHA256 `7197e382b00f8b760be77fd119df1a285f49aaa59ecb3b9749bd09f8dc0af4d1` approves the exact reordered source/test; current native refresh binds their compiler/cache facts. Gate B review also includes the complete-loader source proof and native CI evidence.

## Evidence and independent review scope

Archive, conditional YAML, JSON/DSSE, shared registry/formatter, pinned-pool retention and native stack results have scoped independent source review. The frozen scoped review SHA256 is `882d98538468e00199002df778b1c769430ceab9c9c34aa518aeabccc0811e59`; its JSON/DSSE follow-up reports no unresolved family finding in the isolated qualification context. The frozen archive report SHA256 is `637781262ec2def2cd60c7d4b1c7a54d16cff14a23c502824091a190b0c53901`. Its frozen constants script SHA256 is `8d58abb5fbff750c952791ddb150f16e04d35e61cb653bfc7a6645f6849cbc24`; the raw-class/full-tiny correction is incorporated with unchanged final archive constants, independently confirmed at the refrozen correction. The frozen JSON report is `8d5cb6af9c732ef3ee6842923c56f27ba0790b7202196582cb88d53f0aab1872`; its arithmetic script is `4fdbcbde7515a3ac0399aed31ece493941986e7cad5b104b196bf8869b4cde86`. Manifest completed-family report SHA256 is `e44e890d0483ad321898ccc9583fa735100d6d43f44f69ca1b5ee7f3cdcb7c46`, with freeze inventory `6329d5b9a19c1e360d1df87f73c48f4e9bb45d4846a91374a0c5200796158b7a`. Completed manifest families have scoped independent approval. The implemented fields-first source has independent code/adversarial approval and uses the approved source-prefix/lifetime partition; refreshed native facts bind source a19cc54. Independent composite source review and qualification review approve the current candidate. The approved rejecting-prefix/closed-domain report SHA256 is `0cfaa9f064106156189211a0111dff3ba8bb6388f96d0d0247037219af7088b0`, arithmetic script `2d6e6c2ba8786e7509c553c1b342dee6bb38f435ab75d31de3680b997493e0fd`, log `f56a660d4e76a2b65cc789fe8d22196805cbd3f2c8f2dff12e90b759899bbc9c`. Its terminal projections are diagnostic unclosed upper relaxations and are excluded from that scoped approval. Author reports/scripts are retained by the primary as evidence; this tracked audit contains the proof definitions and formulas and grants no independent approval itself.

[Gate A evidence](GATE_A_REVIEW.md) and [Gate B evidence](GATE_B_REVIEW.md) own qualification logs and approval status. [PR CI run 38362466507](https://github.com/ricevanta/ricevanta/actions/runs/38362466507) passes all 49 jobs at source `a19cc54e4748ff0c26379d634c3cb3f3581394ce`, tested integration SHA `ded2b717aeb7ecfe3e4f2943132c6564e07b2413`, attempt one. Independent review and the primary confirm all 46 exact same-run receipts, 2,598 Gate A records and 3,390 Gate B records, including runtime controls, each YAML ledger and full envelope comparisons. Loader race completes in 690.194 seconds; all required fuzz jobs pass with positive executions. Native diagnosis 38362276804 supplies source/compiler/descriptor/stack binding and does not replace required PR CI. Complete Gate B source and qualification reviews approve this candidate. Each landing head still requires current-integration CI and eligible final review.

Each measured interval uses its own raw counters: combined YAML, assembled same-call conversion with real validation, and one exported Load without an observation closure. No warmup, retry, sample selection, allowance or subtraction applies. Ownership mutation occurs after measurement. Normal-scheduling serial/two-call runs keep ordinary GC. RSS uses native helpers on every supported OS, and missing/failed observations fail qualification. Passing finite measurements support these exact contexts alongside the complete source proof; production admission remains separate.

Field-order design approval SHA256 is `647641435c8b6a3eaeba7d510212e6895e3e43ab682ebf91a2b058d03050ba66`, binding manifest spec `ca8e9d15b1cbbbd390fe849d253a64f9d9525930d375f311fe9bd9533ae536c3` and plan `0769fdc5f38f07ff6edfb9e40e708b30acf5971da73efe2719453490aba631f4`. Prospective source applicability SHA256 is `6d0b03fe086a493bbad9b75f76bf4d49772634cbfef92cd68f4a6f71cc6241d0`, supplemented by the lifetime clarification above. These identities approve design/source applicability; the separate code/adversarial approval and current native identities bind actual implementation. Current independent source/native report SHA256 `69d2c26559af34e35198ff06fa19276544cbdae5892aac9f36f7ca8b00a724c8` approves the actual-source transfer, six descriptors and full three-target escape/source/pcsp bounds with no unresolved finding. It supplements frozen original family scopes without rewriting them. The combined source/native and qualification reviews establish Gate B approval. Each landing head still requires successful current-integration CI and eligible final review.

Complete source/native handoff SHA256 `c2ff5d27e39330ae4e31c6c5539b63b05265e2c4d89260ec705432af96149b19` approves the proof and native tables transferred into this audit. Current-source qualification confirmation SHA256 `c978f68c26e876e99edab2fff8fc5bc30921ca0a3126f75210e90b57a75cf325` approves all required CI evidence and Gate A renewal. These reviews have no unresolved findings; status-only edits do not change their bound source bytes or arithmetic.
