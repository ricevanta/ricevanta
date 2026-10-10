# Authority journal protocol

This candidate defines a safety model for the BE-12 independent journal. It is not an implementation contract. Exact schemas, domain reducers, audit encoding and qualification fixtures remain blockers in section 10.

## 1. Target guarantee and boundary

The target makes PostgreSQL a rebuildable projection and one signed live head per organization the current authority. The journal is intended to keep every accepted record needed to reconstruct that head. The required result is that a database-only writer cannot grant authority, undo a deny, lower a counter floor or reuse a consumed identifier. This candidate does not establish that result across a database lock and an independently completing store or network request.

The online coordinator and journal signer authorize ordinary mutations. Compromise of both can append an ordinary grant without custodians. The offline quorum authorizes only recovery resolutions, signer replacement and epoch transitions; it is not routine grant approval. The candidate record checks detect a database rollback, missing journal record, broken hash chain, forged signature, mismatched projection and uncertain apply. Stale-writer safety across stores remains unproved. A journal-store administrator can deny service. An administrator who can make every trusted reader accept a stale current object can hide a suffix; retained versions do not supply freshness by themselves. Host root defeats the local backend when no independent trusted copy exists.

The protocol does not claim atomic transactions across PostgreSQL and a file or S3-compatible store. It does not use object listing as a lock, treat Object Lock as writer fencing, infer expiry from object lifecycle, or use PostgreSQL as the current-head selector. Amazon S3 gives strong reads after successful writes and atomic updates to one key, not a multi-key transaction ([consistency model](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html#ConsistencyModel)).

## 2. Canonical objects

Payloads are JSON Canonicalization Scheme bytes under [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785). Unsigned 64-bit values are decimal strings. Hashes are lowercase `sha256:<hex>`. Times are UTC RFC 3339 with nanoseconds. Signatures are Ed25519 under [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) over `"ricevanta-authority-v1\n" || object_kind || "\n" || JCS(payload)`. A signed envelope contains only `object_kind`, `key_id`, the canonical payload as a base64url string without padding, and the base64url signature. An object hash is SHA-256 over the canonical envelope bytes. Previous hashes name those exact bytes. Verifiers reject unknown fields, duplicate keys, invalid UTF-8, noncanonical bytes and unsupported schema versions.

Every record payload binds `installation_uid`, `organization_uid`, `journal_schema`, `operation_uid`, `record_kind`, `stage_ordinal`, `record_sequence`, `recovery_epoch`, `writer_fence` and `previous_record_hash`. An operation uid is UUIDv7 and remains stable across prepare, commit and publication. The deduplication identity is `(operation_uid, record_kind, stage_ordinal)`. A retry of that identity must reproduce identical bytes; different record kinds for one operation are distinct. A repeated identity with different bytes seals writes. Sequence, fence, epoch or ordinal overflow seals writes.

The projection is a sorted set of canonical items keyed by `(kind, uid)`. An item contains its epoch, revision, state (`active`, `denied`, `consumed`, `retired` or `recovery_pending`), public authority fields, encrypted recoverable fields and ciphertext metadata. Its digest is the RFC 9162 Merkle Tree Hash of each canonical item as one leaf, ordered by the UTF-8 bytes of `kind || 0x00 || uid` ([Merkle tree algorithm](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1)). The empty projection uses RFC 9162's SHA-256 empty-tree hash. Duplicate keys fail. An implementation may cache tree nodes, but verification from all items must produce the same root.

## 3. Records and live head

The journal has seven immutable record kinds:

| Kind | Required content | Projection effect |
|---|---|---|
| `genesis` | Offline-root-signed installation, organization, journal signer certificate, epoch 1, fence 0, sequence 0 and empty root | Create the empty projection |
| `writer_claim` | New owner uid, prior fence, new fence, lease serial and expiry | None |
| `writer_renewal` | Owner uid, unchanged fence, incremented lease serial and expiry | None |
| `prepare` | Request, exact before images or absence proofs, recoverable after images or tombstones, irreversible effects, reserved floors, action digest and expected committed root | Apply irreversible effects and mark affected grants pending |
| `commit` | Prepare hash, database apply uid and digest, external result digests, final root | Apply the prepared after images |
| `resolution` | Prepare hash, `aborted` or `tampered`, inspected evidence, signer set and resulting root | Keep irreversible effects; discard uncommitted grants; mark ambiguous resources `recovery_pending` |
| `epoch_transition` | Prior head, custodian request, repair set, replacement signer and new epoch | Apply exact repairs and invalidate prior-epoch authority |

Irreversible effects are typed deny, consumption and counter-floor operations. A domain reducer must reject an effect that lowers or removes one. A prepare never activates a grant. Each domain must provide deterministic `validate`, `prepare_reduce`, `commit_reduce` and `resolution_reduce` functions with positive and negative fixtures. Generic JSON patch is unsupported.

The signed head contains the organization identity, signer id, epoch, record sequence and hash, authority resolved sequence and hash, audit resolved sequence and hash, projection root, pending prepare hash or null, writer owner, fence, lease serial, expiry, and previous head hash. Genesis has no previous record or head hash. The head never embeds a storage ETag or version id because those values are known only after the write. The backend returns them as the opaque compare-and-swap token and verification receipt.

At most one prepare may be unresolved per organization. An authority action and its administrative audit record share one operation uid, prepare and commit. The journal record carries the audit payload hash and intended outcome transition. Denied attempts use an audit-only prepare. This serializes administrative writes but gives them one unambiguous order. This candidate does not define the full audit payload, its own previous-record hash, final-outcome encoding, sequence projection or database rebuild rules. Audit integrity remains blocked on those typed contracts.

## 4. Required backend operations

The journal backend exposes only:

1. `ReadCurrent(org) -> signed head, CAS token, receipt`, which reads the current head key directly.
2. `CreateRecord(hash, exact bytes)`, which succeeds only when absent; an existing exact object is success after read-back, while different bytes are an integrity failure.
3. `CompareAndSwapHead(old token, exact new head) -> new token, receipt`, which changes only the current head named by the old token.
4. `ReadRecord(hash)` and `ReadHeadVersion(receipt)` for verification.

Every success requires exact-byte read-back or a qualified full-object checksum and size. A timeout has an unknown result. The caller reads the current head and accepts only the intended head or a valid descendant. It never retries an unconditional write.

### 4.1 Local filesystem backend

One process holds an operating-system exclusive lock on a dedicated local journal volume. It creates a record in the target directory with exclusive creation, writes and `fsync`s the file, then `fsync`s the directory. It creates the signed head at `heads/<head hash>` the same way. It then writes the same bytes to a unique file, `fsync`s it, atomically renames it over `HEAD`, and `fsync`s the head directory. The compare-and-swap token is the verified prior head hash while the lock is held. Orphan records and temporary heads are not authority and can be removed only after a retained-head reachability scan.

Network filesystems, shared-volume failover and copied live volumes are unsupported. They need a separately qualified lock, atomic replace and crash-durability contract.

### 4.2 S3-compatible backend

Records use `PutObject` with `If-None-Match: *`. The stable head key uses `PutObject` with `If-Match: <current ETag>`. AWS documents both conditional writes and their conflict behavior ([conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)). The client records the returned version id and ETag and reads the new exact version before accepting success.

The bucket must enable versioning and Object Lock compliance retention for every record and head version. Serving credentials may get, conditionally put and list required versions, but may not delete objects or versions, create delete markers, shorten retention or bypass retention. Object Lock protects a version but permits newer versions and delete markers, so it is evidence retention rather than a lock ([Object Lock limits](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html#object-lock-managing-delete-markers)).

Registration must prove current-key strong reads, conditional create, conditional replacement, exact-version read-back, checksum behavior, concurrent-writer exclusion, versioning, retention and policy denial. An endpoint that merely implements S3-shaped APIs is unsupported. Cross-region replication, gateways with caches, eventually consistent stores and stores that normalize object bytes are unsupported until the same fixtures pass.

## 5. Writer ownership, expiry and fencing

Writer acquisition always reads and verifies the current head. An unexpired owner renews by creating `writer_renewal` and replacing that exact head. A contender waits until `expiry + maximum_clock_skew`, then starts a synchronous PostgreSQL transaction and locks the organization row. It rereads the current head, stops if that head is not expired, and otherwise creates `writer_claim` with `writer_fence + 1` and replaces the exact observed head. In the same locked transaction it installs that fence in `organization_state` and commits. The claim cannot perform work until this commit succeeds. A loser rolls back, rereads and stops.

The local backend first acquires its operating-system lock, then installs its claim under the PostgreSQL row lock. The operating-system lock excludes the old local writer. The row-first takeover above applies to a conditional-update backend where two hosts can issue requests.

Lease duration is 30 seconds, renewal starts after 10 seconds, and configured maximum wall-clock skew is at most 2 seconds. The owner also starts a monotonic stop timer when acquisition or renewal succeeds. It starts no store request unless its deadline leaves enough time for that request and stops journal and database work before `duration - maximum_clock_skew` elapses. Clock expiry restores liveness only. Head compare-and-swap and database fence checks reject ordinary stale retries after an observed takeover, but they do not order a delayed accepted request against a database lock release.

The backend does not compare time or expire an object atomically. These lease values therefore require clock-skew and pause fault tests. A process that keeps writing after its stop timer, a stolen signer, or stolen current writer credentials is a compromised coordinator and outside stale-writer protection.

Every authority database connection starts with `transaction_timeout = 10s`, `idle_in_transaction_session_timeout = 5s`, `statement_timeout = 5s` and `lock_timeout = 5s`, and the coordinator verifies them before taking a lock. Journal requests made inside a transaction have a four-second client deadline. PostgreSQL 17 terminates a session whose transaction exceeds `transaction_timeout` ([client connection defaults](https://www.postgresql.org/docs/17/runtime-config-client.html)). After every lock wait or journal request, the coordinator checks that its database transaction still exists, rereads the current head, and checks owner, fence, CAS ancestry and monotonic lease time before continuing.

These checks limit ordinary stalls but do not retract a request accepted by a remote store. A process can submit a conditional head write, stop, lose its PostgreSQL lock to `transaction_timeout`, and have the store accept that write later. A new shared-lock reader can observe the old head and start a grant before the delayed pending head becomes current. The same race exists if a filesystem operation completes after the database lock is released. Exact database role settings and prevention of weaker session overrides remain DDL blockers, but timeout DDL alone cannot close this race.

## 6. Candidate prepare, apply, commit and publication

Normal mutation paths acquire journal ownership before a PostgreSQL lock. Initial acquisition and expired-owner takeover attempt section 5's PostgreSQL-row-then-head order. The delayed-completion counterexample means that this order does not form one cross-store fence. The candidate authority flow is:

1. Read and verify the head and its chain suffix. Refuse an unresolved prepare. Reconcile any committed head that the database has not published.
2. Begin a `READ COMMITTED` transaction with `synchronous_commit = on`. Lock `authority.organization_state` with `SELECT FOR UPDATE`, then reread the current head and compare its epoch, fence, resolved hash and projection root with the database state. PostgreSQL holds the row lock until transaction end ([row locks](https://www.postgresql.org/docs/17/explicit-locking.html#LOCKING-ROWS)).
3. Build the deterministic prepare from the locked before state. Create its immutable record and replace the exact head with a pending head. If replacement fails, roll back.
4. Through one migration-owned function, compare the transaction's epoch, fence and prepare hash, apply exact after images as `pending`, persist irreversible effects, and insert `authority.apply_receipt(apply_uid, prepare_hash, before_root, pending_root, after_root)`. Serving roles cannot update these tables directly.
5. Commit PostgreSQL synchronously. After a connection loss, query the prepared transaction's exact apply uid and roots. An absent row is ambiguous, not proof of rollback.
6. Create the deterministic commit and replace the pending head. Exact matching database and signed external-action evidence may complete this step after coordinator restart. Conflicting evidence seals writes.
7. In a second synchronous transaction, lock the organization row, verify the commit head directly, mark the exact rows published, and advance the database state to its resolved hash and root. Authority views expose only rows whose publication reference matches that state.
8. Return a result or expose an external grant only after step 7. A retry by operation uid returns the stored exact result.

A cached projection contains the full canonical item map reconstructed from genesis through the current resolved head. It is a performance cache, not authority. A domain reducer derives the complete dependency-key closure for a decision from the request and that map. It cannot derive mappings, policies, denies or target relations from rows returned by PostgreSQL. The decision executes against the journal projection; a required database after-image must exist and hash exactly to the matching journal item. Missing, extra, deleted or retargeted items fail closed. Comparing only selected query rows or a database-stored root is forbidden.

The candidate guard begins a bounded transaction, locks `organization_state FOR SHARE`, reads the current journal head after the lock wait, and compares the cached projection and database state with that head. The prepare path takes `FOR UPDATE` and attempts to publish the pending head while holding the lock. This ordering does not prove an immediate deny or consumption boundary because a timed-out store request can complete after the exclusive lock releases.

Holding the shared lock through an acknowledged external send is also insufficient. A process can submit a request, stop, lose its database transaction, and have the kernel or remote recipient make the request effective after a later deny. Acknowledgement timing cannot prove effect timing. External side effects need either a recipient that validates the current journal fence atomically with applying the effect or an independently fenced dispatch gate whose grant cannot outlive the database guard. The journal head update likewise needs an independent gate that prevents a submitted update from taking effect after its database guard ends, or one linearizable primitive that covers both readers and head publication. Generic filesystems, PostgreSQL and S3-compatible APIs do not provide that composition in this candidate.

Cached projection and dependency-closure rules remain useful inputs to a future guard, but no grant, signature, issuance, dispatch, consumption or authority-bearing stream can be handed to implementation from this ordering model. A local single-process prototype may exercise record and recovery mechanics only; it cannot claim the cross-store safety property.

## 7. Resolution, restore and epoch transition

An unresolved prepare blocks later writes. Exact database and action evidence completes its commit. Otherwise custodians sign one canonical resolution request naming the prepare, evidence set, resulting projection and every resource made `recovery_pending`. The journal appends `resolution` under a new writer fence. A missing row, expired lease, process crash or operator statement cannot authorize an abort. The online journal signer alone cannot sign a resolution.

Restore starts sealed. The coordinator reads the live head, verifies that the backup head is an ancestor, replays the suffix and rebuilds the projection. It refuses a gap, missing ciphertext, invalid signature or unresolved prepare. The restored database is replaced from that projection while APIs remain sealed.

An epoch transition requires the configured distinct custodian threshold and a signature from the offline root over the custodian manifest. It binds the exact prior head, backup digest, unused recovery operation uid, new epoch, replacement signer, repair items and key-inventory digest. The new epoch must exceed every retained epoch. Its head replacement uses the exact prior CAS token and increments the writer fence. Verifiers accept the new signer only through this transition. Old tokens, approvals, certificates and signatures are not relabelled; repaired grants require new authorization.

## 8. Crash and concurrency outcomes

| Interruption | Durable state | Required recovery |
|---|---|---|
| Record created before head replacement | Orphan record | Ignore; later reachability cleanup |
| Head replacement succeeded, response lost | Intended head or valid descendant is current | Read current; continue only from verified chain |
| Prepare head published before database commit | Pending head | Commit from exact evidence or obtain custodian resolution |
| Database commit succeeded before commit head | Pending head and exact apply receipt | Publish deterministic commit, then publication transaction |
| Commit head succeeded before database publication | Resolved journal, pending database rows | Replay publication transaction |
| Publication committed before response | Fully committed | Retry returns request result |
| Two owners replace one observed head | One compare-and-swap wins | Loser stops and rereads |
| Takeover races an old write | One head replacement wins | Journal order is known; database ordering still needs the missing gate |
| Process stops after submitting head CAS | Database lock expires; CAS may still become current | Safety is unproved; seal on mismatch and retain the trace for gate design |
| Process stops after submitting external send | Database lock expires; recipient may act later | Safety is unproved unless the recipient enforces the current fence |
| Claim head wins but fence-install transaction rolls back | New head and old database fence disagree | Seal; after claim expiry, install a higher fence through takeover |
| PostgreSQL restored behind journal | Root or resolved-hash mismatch | Seal, replay journal, rebuild projection |
| Journal restored or hidden behind database | Database is ahead of authenticated head | Seal; never select the database head |

## 9. Event, hold and export dependencies

Ordinary event ingest and its EV-04 acknowledgement fence do not use this journal. An authority-producing action binds its audit payload hash to the same operation before its result or event is exposed. The audit protocol still must define how the full prepared payload, final outcome and audit chain reconstruct from that binding. Audit export is asynchronous evidence distribution and never the live publication barrier.

Creating, narrowing or releasing a legal hold is a protected authority action, but capture completion remains under EV-07. An authority commit may publish the requested hold state only as `capturing` or `releasing`; it cannot publish `active` or `released` without the hold protocol's verified receipts. S3 event export uses its own immutable plan and cannot reuse journal ownership or head objects.

## 10. Qualification and implementation boundary

This document is a research candidate for independent review. It proposes one CAS head, immutable records, conservative prepare effects, exact-evidence commit, quorum resolution, post-commit database publication and sealed restore. The row-lock and CAS composition does not establish the required cross-store ordering. It does not authorize journal implementation.

The next proof obligation is an executable model of one synthetic item moving `absent -> pending -> active`, with two writers, a stopped process, database timeout before remote completion, delayed successful CAS, delayed external effect, unknown results and crashes at every numbered step. The current composition must produce the two counterexample traces in sections 5 and 6. Any replacement must show one linearization point that prevents both traces, either through an independent gate with server-enforced lifetime and fencing or through recipient fence validation and effect application in one linearizable operation. The model must then show that no grant or external effect becomes effective after its deny and no stale fence reaches publication.

The handoff remains blocked first on that cross-store gate or recipient-fencing contract and its proof. It also remains blocked on exact JSON Schemas for every record, head, signature envelope, storage receipt, projection item, apply receipt, publication row, operation result, resolution request, custodian signature, signer certificate and genesis object; byte and negative fixtures for canonicalization, hashes, Merkle roots, genesis, identifiers and overflow; deterministic dependency-closure and reducer contracts for every authority domain; the full audit prepare, outcome, chain, sequence and rebuild contract; signed external-action evidence; database DDL, grants and timeout enforcement; and a model-checked transition system plus crash fixtures. Each contract needs independent review.

Empirical qualification remains required for the local filesystem and every named S3-compatible product and deployment mode, including crash durability, clock skew and process pauses, conditional conflicts, unknown results, exact read-back, store policy enforcement, versions, retention and delete-marker denial. Signer and custodian key custody, restore at fleet scale, audit volume and latency, and the hold and export protocols also remain unqualified. Passing Amazon S3 documentation does not qualify another endpoint.

Safety favors sealing over guessed aborts and makes denies, consumptions and floors irreversible. Liveness therefore depends on the live head, journal signer, backend availability and custodian threshold. One unresolved prepare serializes administrative work. More concurrency would require independently fenced subjournals plus a specified atomic composition rule, which this version does not support.
