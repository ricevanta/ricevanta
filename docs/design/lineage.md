# Lineage design

Lineage records revision-qualified provenance and preserves effective classification when graph evidence expires or reaches a resource cap. The graph model, identities, durable sensitivity floor, transport, retention and work bounds live here. Confidence calibration and cross-device provenance remain implementation blockers (`../analysis.md` section 3); console exploration is in `console.md` section 5.5. Decision: LIN-01 in `../decisions.md`.

## 1. Model

Nodes are entities and activities in the W3C PROV sense: file incarnations and their content revisions (section 2), content hashes, processes, users, devices and destinations. Destinations include removable volumes, cloud sync folders, browser targets and network peers. Edge types are PROV-DM `used`, `wasGeneratedBy`, `wasDerivedFrom`, `wasAttributedTo` and Ricevanta `copy`, `move`, `rename`, `compress`, `extract`, `upload` in the `io.ricevanta` namespace. File endpoints name the exact revision observed, never a mutable file node whose latest hash changes earlier evidence.

Every edge carries a timestamp, observation order, confidence, observed or inferred status, and evidence: OCSF event uid plus a compact summary of class, time, process, revision and path. An edge remains interpretable after its source event expires. An observed copy or extraction requires an event that establishes that relationship. A read followed by a write or an equal hash is an inference, not proof of derivation. Unknown revisions and gaps remain explicit; the engine never assigns an earlier read the hash of a later write.

## 2. Identities and revisions

A file revision is keyed by `(device_uid, observation_namespace, file_incarnation, content_revision)`. The device uid prevents equal native identifiers on different devices from joining. The agent creates a random observation namespace when its durable identity state starts or is reset. An incarnation is a durable, never-reused local object uid; a revision is a monotonically increasing value within that incarnation. Native identifiers are lookup hints, not globally permanent file identities.

| Thing | Native hint and continuity rule |
|---|---|
| Linux file | File-system identity and inode, with a generation only where the qualified filesystem and sensor can obtain and validate it. `statx` is not assumed to expose an inode generation. BPF access to a useful generation is unproved per filesystem. |
| Windows file | Volume identity and 128-bit file id from a live handle. File ids can be reused after deletion, so the durable incarnation and qualified observation continuity distinguish lifetimes ([Microsoft file information](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information)). |
| macOS file | Volume identity and APFS inode from the qualified sensor. Neither value alone proves a lifetime after deletion or an observation gap; the incarnation persists only when continuity is established. |
| FAT, exFAT and a filesystem without proved continuity | Mount observation, path observations and content hash when known. Allocate distinct incarnations when continuity is uncertain. Path equality never proves identity or a move. |
| Process | Device and boot-session identity, pid and process start time; macOS also records the audit token's pid version. Boot-session continuity and start-time resolution must pass reuse fixtures on each OS. |
| Content | BLAKE3 over immutable observed bytes; TLSH is similarity evidence. Equal hashes can identify equal bytes but do not prove a shared origin. ssdeep is not used (GPL-2.0). |
| User, device | Immutable directory principal and device-record identities, with their issuing authority. |

The durable index maps a qualified native hint to its incarnation. A confirmed delete ends the incarnation only after its final link and open-handle lifetime end. A later create using the same hint receives another incarnation. A rename, move or remount retains an incarnation only with proved continuity; otherwise the engine creates a separate candidate and records the uncertainty. Reboot recovery never joins objects from native ids alone when intervening operations could have gone unobserved.

An in-place write advances the content revision before a changed-byte result can be used. Earlier reads still refer to their earlier revision. A save by replacement creates a new incarnation; a derivation edge to the old revision requires observed or inferred evidence and the corresponding confidence. A descriptor still open on an unlinked object refers to that old incarnation, not a replacement at the same path. Hard-link paths are aliases of one qualified incarnation, not separate source objects.

A revision's hash names only an immutable snapshot of that revision. Concurrent writes, mappings or lost events produce an unknown or pending revision until the native snapshot and mutation fence proves the association (`dlp.md` section 6.4). An operation that cannot select its revision reports unknown evidence; the engine never fills the gap from a subsequent scan. Exact sensor capture, native-id reuse detection and recovery continuity for every supported filesystem remain implementation blockers. Cross-device joins require revision-bound evidence and explicit inference confidence, not an equality join on native ids.

## 3. Durable sensitivity floor

A derived content revision inherits the highest source label when its derivation confidence reaches the configured threshold, 0.8 by default (`dlp.md` section 5.3). The materializer stores that label as a durable sensitivity floor keyed by the revision identity, with a compact justification: source revision or bounded summary, source hash when known, category and catalogue version, supporting event or summary uid, confidence, and inference or pressure state. The effective classification is the higher of the scan result and this floor.

The floor lives in `state.db` with `FULL` synchronous durability, independently of the batched graph in `lineage.db`. The floor commits before an affected transfer can use the new classification. A missing or failed floor commit is a classification error under the existing DLP fail-mode contract; it is never a lower or empty label. Graph retention, roll-up, spool loss, cache eviction, detector upgrades and rescanning cannot remove or lower a committed floor. The server maintains the same revision-qualified floor and compact justification independently of its edge partitions.

A lower label requires an approved reclassification bound to the exact revision, current floor and catalogue, proposed label and supporting evidence. A detector rescan or a policy edit alone is not that approval. A new content revision carries the predecessor's floor until a justified reclassification lowers it; an unknown rewrite cannot clear a label. A lineage `tag` can raise the floor. Its reduction uses the same protected reclassification. The signed reclassification authorization, local materialization transaction and server-to-endpoint convergence contract remain implementation blockers; there is no unapproved floor-reset path.

Keep the current floor while a revision remains accessible through a path, alias or live handle. Keep a surviving derivative's compact justification even after its source or provenance expires. A confirmed inaccessible revision may release its own state only after every surviving derivative holds its independent floor; removing a pathname is not proof that the revision is inaccessible. Floor state is bounded separately from the graph, 64 MiB per endpoint by default. Safe compaction merges justifications to the highest label and an explicit summary; it never discards the label. At the cap, preserve existing floors, report pressure and fail any affected classification update rather than treating an unrecorded floor as public. Native lifecycle proofs and safe floor compaction remain required qualification work.

## 4. Transport and graph storage

- Endpoint: `lineage.db` in SQLite (`agent.md` section 5), indexed nodes and edges with revision endpoints. Graph writes retain the existing batched durability contract; the floor's stronger durability is separate. Default detailed-edge retention is 90 days. Retention compacts evidence into bounded summaries where useful; summaries expire at four times the detailed age. Neither operation controls sensitivity floors.
- Upload: `ricevanta/lineage_activity` events (`../specs/ocsf-profile.md` section 2) use their own spool class, dropped after context and before detections. The compact floor justification survives a graph-upload drop locally; the server shows the resulting provenance gap.
- Ingest: `events` hands lineage to this module inside its ingest transaction (`events.md` section 3.6). Edge ingestion is idempotent by device and event uid. Edges are not duplicated into ordinary event tables.
- Server: PostgreSQL `lineage` schema, indexed by device and revision and partitioned by month on edge time. Detailed-edge retention defaults to 180 days and summaries to four times that age. Floor state is separate from partition retention.
- Holds: lineage producers and pruning acquire the shared capture fence through the `events` interface before reading holds or writing a source. The module registers committed edge batches and exposes idempotent held-copy, verification and retention interfaces under `events.md` section 5. Pending capture pins source partitions; a hold becomes active only after verified capture, and interrupted copy or cleanup resumes from durable tasks. Held evidence counts against a declared separate quota; reaching it halts admission or retention with an alert, never deletes held data or grows storage without a bound. The cross-store hold specification remains an implementation blocker.

## 5. Storage and work bounds

Age and query depth do not bound burst size, fan-out or intermediate work. These defaults are policy budgets in the signed bundle and server configuration; measurements must qualify them before release. Byte caps include database pages, indexes, WAL and compaction scratch space, with space reserved before work starts.

| Bound | Endpoint default | Server default |
|---|---|---|
| Live graph storage | 256 MiB, 250,000 nodes, 1,000,000 edges; first cap reached wins | 32 GiB per organization, 10,000,000 nodes, 100,000,000 edges; first cap reached wins |
| Active derivation state | 64 process windows, 1,000 source revisions and 1,000 destination revisions per window, 4 MiB total | Same per-device admission caps; 16 MiB per materializer worker |
| Candidate derivation work | 10,000 candidate checks per process window and per second per device | 10,000 checks per device per second; bounded fair queues |
| Path-query output | Depth 8, 500 nodes, 2,000 edges | Depth 8, 500 nodes, 2,000 edges |
| Path-query expansion | Frontier 500, 10,000 adjacency visits, 4 MiB memory, 100 ms monotonic deadline | Frontier 500, 10,000 adjacency visits, 16 MiB memory, 1 s statement deadline |
| Concurrent path queries | 1, queue 8 | 4 per organization, queue 32 |

Reads may link to later writes only in observation order within a 10-minute process-instance window. The engine does not materialize a source-by-destination Cartesian product. Before any degree, candidate, memory or active-window cap is exceeded, it replaces the detailed candidate set with a bounded process-window summary carrying maximum source sensitivity, confidence state, counts and evidence digest. Each affected destination references that summary. Continuing work updates the summary instead of adding pairwise edges. Summary evidence is inferred and marked pressure-derived; reduced provenance confidence cannot lower the durable sensitivity floor. Once a classified source participates, pressure preserves its maximum label even if a particular source-to-destination edge can no longer be retained. A pressure interval that cannot retain even bounded summary state reports a gap and applies the classification-error contract, never an unlabelled derivation.

Compaction reserves scratch and WAL capacity inside the byte cap, preserves floors first, and coalesces oldest unheld detailed edges into bounded summaries before admitting more detail. At most one compaction batch of 1,000 edges runs at a time; a batch that exceeds its work budget yields and retries. If no safe summary fits, detailed-edge admission stops and emits counted gaps while floor updates continue under their separate bound. Orphan nodes may be reclaimed only after no edge, floor justification or hold needs them. Summary nodes and edges count against every graph cap; recursive summary creation cannot evade the limit. A sustained graph or floor cap raises detection and health with affected interval, counts, bytes and gap reason.

Path traversal uses an iterative frontier with a visited set and bounded indexed adjacency fetches, or an equivalent query proven to enforce the same intermediate bounds. An outer SQL `LIMIT`, depth check or PostgreSQL `CYCLE` clause alone does not prove bounded expansion. On a deadline or work cap the response is explicitly partial, with its covered frontier and truncation reason; the console never presents missing paths as proof of no relation. Display aggregation above 50 same-type edges is separate from storage compaction. Traversal and compaction fixtures must prove the hard bounds with cyclic and wide graphs before implementation hand-off.

## 6. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: device-qualified incarnations and revisions keep old evidence from changing with a new file or write; floors preserve classification independently of provenance retention; finite storage and work caps protect the core; every pressure reduction appears in evidence and health.

Trade-offs: uncertain continuity can split one physical file into multiple candidate incarnations; conservative floors and process summaries can overclassify a derivative until approved reclassification; compaction loses per-source detail; query caps return partial exploration rather than exhaustive paths.

Dependencies: `blake3`, `tlsh2` (`../licensing.md`), SQLite and PostgreSQL, native sensor and snapshot contracts, W3C PROV-DM vocabulary, the DLP catalogue and protected reclassification. No new graph database is required.

Limits: incarnation continuity, immutable revision capture, confidence calibration, cross-device provenance, durable floor transactions and bounded compaction are unqualified. The numerical budgets are targets to measure, not evidence of support. FAT, exFAT and observation gaps retain explicit uncertainty. A hostile local administrator can remove endpoint state under the tamper limits of `agent.md` section 9.

Alternatives considered: a graph database adds a storage service or extension; `ltree` represents trees rather than multi-parent provenance; closure tables add writes per path; native file ids alone merge reused lifetimes; mutable file nodes misattribute prior reads; age-only retention and confidence-only fan-out controls leave work unbounded; erasing inherited labels with edge retention creates an evasion.
