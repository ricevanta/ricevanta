# Events design

How a security event travels from a sensor to PostgreSQL, the raw store and every external destination, and what is guaranteed on the way: the agent pipeline from OCSF construction to acknowledged upload, server ingestion in the `events` module, deduplication, enrichment, per-destination filtering, retention with holds and archives, the administrative audit log in the `audit` module, and the pipeline's own health. Classes, the `ricevanta` extension, the envelope, telemetry profiles and validation are in `../specs/ocsf-profile.md`; storage, partitions, `COPY` batching and the raw store in `backend.md` section 5; the spool directory layout and its cap in `agent.md` section 5; the agent protocol in `../architecture.md` section 3.4; the `export-destination` connector contract in `extensions.md` section 6; the `ExportDestination` resource and each destination adapter in `../specs/event-export.md`. Decisions: EV-01 to EV-03, EV-04 to EV-07, AG-04, AG-05, AG-08, BE-03, BE-04, BE-06, BE-07, EXT-05 and SH-01 in `../decisions.md`; C9 in `../analysis.md` stays resolved by EV-01. Export consumption uses the commit-order contract in section 4.1. Audit integrity depends on the unresolved authority-journal protocol of `backend.md` section 6.1 and is not ready for implementation hand-off.

## 1. Pipeline and delivery guarantee

```
sensor ─> core events: OCSF construction ─> profile filter ─> lookback ring / class selection
  ─> spool append (sequence, CRC32C) ─> seal (zstd NDJSON) ─> POST /agent/v1/events ─> delete on ack
server agent role: admit ─> ledger check ─> validate ─> bind device ─> enrich ─> route
  ─> capture fence ─> raw store insert (dedup token = batch id)
  ─> transaction: events, quarantine, lineage and detection inboxes, export-log index, ledger
  ─> current-primary acknowledgement fence ─> ack after durable commit
server jobs role: export log ─> per-destination filter, projection, encoding ─> destination ─> cursor
```

Guarantee (EV-04): an event is delivered **at least once** from its durable spool append to its store commit, and stored **once** per store, when all of the following hold: its spool record was synced, its class was not dropped by the spool cap, its segment passed its checksums, and the device uploaded before it was retired or wiped. Ingest is idempotent by `(device, batch id)` and by `metadata.uid`, so a retried batch never creates a second row; the residual duplicates are a batch whose acknowledgement was lost and that is retried after the 30-day batch ledger window (section 3.3), and a raw batch retried after the ClickHouse deduplication window (section 3.5). Export is at least once to every destination whose filter matches, within the export-log window (section 4); duplicates carry the same `metadata.uid`, which every adapter maps to the destination's identity or deduplication key (`../specs/event-export.md` section 2).

| Failure | What is lost | Where it is recorded |
|---|---|---|
| Agent crash or power loss | Records appended after the last active-segment sync (at most 500 ms) and events still in construction | Nothing to record: those records never received a durable sequence number, so no gap appears |
| Corrupt record in an active segment at start | The records after the first bad record in that segment | A `drop` event with reason `corrupt` and the sequence range between the last good record and the next segment |
| Spool cap reached | The oldest sealed segment of the lowest class (AG-05) | A `drop` event and per-class drop counters in `state.db` that travel in every check-in, so the record survives even when the audit class itself is dropped |
| Corrupt sealed segment (zstd checksum failure) | The segment | A `drop` event with reason `corrupt` |
| Device retired or wiped with an unsent spool | The unsent spool | The server compares the per-class high-water marks from the last check-in with the stored sequences |
| Acknowledgement lost in transit | Nothing | A duplicate batch, answered from the ledger |
| Server or PostgreSQL crash | Nothing acknowledged on the primary: the acknowledgement waits for the commit's WAL flush, even for asynchronous-commit classes (section 3.5). Failover to any standby can lose acknowledged context and raw batches, because `synchronous_commit = off` never waits for a standby; operators who need failover durability for those classes set `synchronous_commit = remote_write` for them, at the throughput cost section 9 names | Failover loss of context and raw batches is not recorded; the other classes commit synchronously and lose at most the lag of an asynchronous standby, an operator choice (`synchronous_standby_names`) |
| PostgreSQL slow or down, raw store down | Nothing while the spool has room | `503` with `Retry-After`; spool depth in health |
| Event fails OCSF validation | Nothing | Quarantine (section 3.2) |
| Destination down longer than the export-log window | That destination's events older than the window; PostgreSQL classes can be backfilled (section 4.3) | A `gap` event and an alert per destination |
| Destination rejects one event permanently | Nothing | The dead-letter table (section 4.2) |
| Syslog over TLS connection break; syslog over UDP | Up to one socket send buffer; any datagram | Syslog has no acknowledgement (`../specs/event-export.md` section 6); the console labels UDP destinations lossy |

Ordering: there is no global order. Within a device, each spool class uploads first in, first out with one batch in flight, and every record carries a per-class sequence; across classes, `metadata.uid` is a UUIDv7 generated with the monotonic counter of RFC 9562 section 6.2, so `(time, uid)` orders a device's events. Consumers order by `time`, then `uid`; the server records `metadata.logged_time` at receipt (`../architecture.md` section 7).

## 2. Agent pipeline

The pipeline lives in the core's `events` module (`agent.md` section 1) and behaves the same on the three v1.0.0 targets except where the table in section 2.6 says otherwise.

### 2.1 Construction, profile filter and context capture

Domain modules hand normalized telemetry to `events`, which builds the OCSF 1.9.0 object with the envelope of `../specs/ocsf-profile.md` section 3 and assigns `metadata.uid`. The telemetry profile in force for the device's scope (`../specs/ocsf-profile.md` section 4) then routes the event to one spool class: raw telemetry (full profile only), context, lineage edges, findings and state, or audit, in the drop order of `agent.md` section 5. The agent's audit class holds the agent's own security records (`policy_activity`, tamper findings, command refusals, pipeline `drop` events); the administrative audit log is server-side (section 6).

Under the default profile, telemetry that is neither a finding nor an event carrying a `metadata.rule_matches` entry for a correlation's base rule (`policy.md` section 4) goes to the lookback ring, a fixed-size file (default 32 MB, counted inside the spool cap) that is never uploaded, with an in-memory index of time and process key capped at 65,536 entries. When a finding is created, `events` copies the ring's events that fall inside the profile's context selection and window before the finding to the context class, and routes matching events to context for the window after it. A burst that overwrites the ring faster than the window shortens the context and emits a `drop` event with reason `lookback_overrun` on the finding's `correlation_uid`.

### 2.2 Repeated findings

A detector that fires repeatedly on the same object would flood every store. The agent aggregates findings with the same key within a window: the key is the analytic or policy uid plus the policy's `dedup` fields (default: actor process uid and target object identity), the window defaults to 60 s, and the table holds at most 4,096 keys. The first occurrence is emitted at once, so alerting is never delayed; when the window closes with more than one occurrence, a summary finding with the same `correlation_uid` carries the OCSF base attributes `count`, `start_time` and `end_time`. A key that does not fit in the table is emitted without aggregation, never dropped. The window state is in memory, so a core restart can emit one extra first occurrence, which the server's content fingerprint catches (section 3.3).

### 2.3 Spool record format

Each class directory holds append-only segment files (`agent.md` section 5). A segment starts with a 32-byte header: magic `RVSP`, format version (u16), spool class (u8), stream epoch (u64, random, created when the spool is initialized), segment id (u64, monotonic per class) and first sequence (u64). Each record is:

| Field | Size | Content |
|---|---|---|
| Length | u32, little-endian | Payload length in bytes |
| Checksum | u32 | CRC32C (Castagnoli) over sequence and payload, from the `crc32c` crate |
| Sequence | u64 | Per-class sequence, contiguous within the stream epoch, also written to `metadata.sequence` |
| Payload | Length bytes | The OCSF event as UTF-8 JSON, without a line terminator |

The sequence is assigned at append. On start the core truncates each active segment at its first record whose length runs past the end of the file or whose checksum fails, and resumes the class sequence after the last good record. A reinstall or re-enrollment that loses the spool creates a new stream epoch, so the server starts new per-class streams instead of reporting a gap. The format version is read by the next agent release, so an updated core uploads the segments its predecessor wrote.

### 2.4 Sealing, upload and acknowledgement

A segment is sealed when it reaches 4 MiB uncompressed, 5,000 records, or its class's age limit (audit and findings 1 s, context 10 s, lineage and raw 30 s; policy values), and only when it holds a record, so an idle device has no sealing wakeups. Sealing re-reads the records, verifies every checksum, and writes `<segment id>.ndjson.zst`: a zstd skippable frame (RFC 8878 section 3.1.2) holding the batch descriptor (class, stream epoch, segment id, first and last sequence, record count), then one zstd frame of NDJSON with the content checksum and content size flags set. A 4 MiB input stays under the 5 MB request limit of `../architecture.md` section 3.4 after zstd's worst-case expansion (verify `ZSTD_compressBound` on the pinned version). The raw segment is deleted after the sealed file is synced.

Upload: `POST /agent/v1/events` with `Content-Type: application/x-ndjson`, `Content-Encoding: zstd` and a `Ricevanta-Batch` header carrying the descriptor; the batch id is `<stream epoch>-<class>-<segment id>`, so a retry after a crash reuses it. Classes upload in reverse drop order (audit, findings and state, lineage, context, raw), oldest segment first, with one request in flight per class and at most two in flight in total. The agent deletes a sealed file only after a `200` response, whose body is `{ batch_id, result: stored | duplicate, stored, quarantined }`.

`../specs/core-primitives.md` fixes the first internal Go contracts for lowercase UUIDv7 event ids and validation of a decoded batch descriptor and batch id. Those leaf packages do not define or decode the `Ricevanta-Batch` header, zstd descriptor frame or NDJSON body. The machine-readable wire contract and compiled OCSF types remain absent, so the primitives do not make upload or ingest ready.

| Response | Agent action |
|---|---|
| `200` | Delete the sealed file |
| `429` or `503` with `Retry-After` | Pause that class for `Retry-After`, capped at 10 minutes, with ±20 % jitter |
| Other `5xx`, timeout, connection error | Exponential backoff with full jitter per class: base 1 s, cap 5 minutes, reset on success |
| `400` (malformed batch) | Move the file to `rejected/`, emit a `drop` event with reason `rejected`; the file counts against the cap and is the first deleted under pressure |
| `401` or `403` | Stop uploading and keep the spool; the identity module renews or recovers (`pki.md` section 2) |
| `403` with `update_only` | Keep spooling under the cap until the update installs (`../architecture.md` section 3.4) |

### 2.5 Offline behaviour

The cached policy stays in force without expiry (AG-05), sensors keep producing, and the spool absorbs events up to its cap, dropping whole segments from the lowest class first. On reconnect, the backlog uploads in class order through a token bucket (default 2 MB/s per device, a policy value), and the server's `503` answers spread the fleet's backlog after a mass outage. An outage therefore costs raw telemetry first and the audit class last, and every loss is counted.

### 2.6 Footprint and per-OS behaviour

Memory added to the core: a 64 KiB write buffer per class (320 KiB), the lookback index (at most 1.5 MiB), the repeated-finding table (at most 400 KiB), one zstd compression context while sealing (level 3; its size is measured in the footprint gate, expected under 3 MiB, verify), and a 256 KiB upload buffer: under 6 MiB of the core's 44 MB budget (`agent.md` section 6), measured by the footprint benchmark and metered by the self-watchdog as the `events` unit (AG-08). Disk is bounded by the spool cap of `agent.md` section 5, which includes the lookback ring and rejected files. The active segment is synced every 500 ms only while it holds unsynced records.

| | macOS | Windows | Linux |
|---|---|---|---|
| Spool location | `/Library/Application Support/Ricevanta/spool`, root only | `%ProgramData%\Ricevanta\spool`, LocalSystem only | `/var/lib/ricevanta/spool`, root only |
| Durable sync | `File::sync_all`, which issues `F_FULLFSYNC` (verify on the pinned Rust release) | `FlushFileBuffers` through `File::sync_all` | `fdatasync` through `File::sync_data` |
| Volume for the 5 % rule | The data volume | The system volume | The file system holding `/var/lib/ricevanta` |

## 3. Server ingestion

Ingestion runs in the `events` module on the `agent` role (BE-03), writes only with that role's insert-only credentials, and follows the handler rules of `backend.md` section 3.

### 3.1 Admission and limits

The device uid comes from the mTLS certificate cache (`backend.md` section 3). Limits, each answered with `400` or `413` and a metric: request body 5 MB compressed; decompression streamed with a 64 MiB ceiling, so a zstd bomb fails early; 10,000 lines per batch; 1 MiB per line. A batch from a device in update-only mode gets `403` with `update_only`.

### 3.2 Validation and binding

Each line is decoded strictly into the generated Go types and checked against the compiled schema (`../specs/ocsf-profile.md` section 6). An event also fails when `device.uid` differs from the authenticated device, `metadata.uid` is not a UUIDv7, `metadata.sequence` falls outside the batch descriptor's range, or `metadata.extension_origin` fails to bind the granted package and component digests, `recovery_epoch` and `grant_generation` for that device's scope. Fresh collector inventory and compliance require the committed current extension epoch and generation. Historical security telemetry may retain older provenance, but that provenance grants no current authority (`extensions.md` section 3). A failing event goes to `events.quarantine` with the device, batch id, error and raw line, and is counted; the rest of the batch is stored and acknowledged, so one bad event never blocks a device. Quarantine keeps 30 days; the console lists it, and after a schema or mapping fix an operator re-validates and promotes events from it. A device-binding failure is a security finding, not only a quarantine entry.

### 3.3 Deduplication

- Batch: `events.batch_ledger` holds `(device, batch id)` with the result for 30 days, day-partitioned. A ledger hit avoids the event-table write, but answers `200 duplicate` only after the same current-primary durability barrier as a new batch (section 3.5). Visibility of a ledger row is not proof of durable commit.
- Event: event tables carry a unique index on `(metadata.uid, partition day)`; partitions are by server receipt day (`metadata.logged_time`), because the server is the clock of record and a skewed or long-offline agent clock must not select a partition. Since `COPY` aborts on a unique violation, ingest copies a batch into a transaction-local staging table and moves it with `INSERT ... SELECT ... ON CONFLICT DO NOTHING`, counting the skipped rows.
- Content: for finding classes, ingest computes `fingerprint = SHA-256(class_uid, device uid, analytic or policy uid, dedup key values)` (section 2.2) into a typed column. A finding whose fingerprint matches a stored one inside the window is stored with `repeat_of` set, raises no new alert in `detection` or `dlp`, and is exported according to the destination's `repeats` setting (`../specs/event-export.md` section 1).
- Sequence: `events.device_stream` is append-only. Each accepted batch inserts a row with device, stream epoch, spool class and the batch's first and last sequence, so the contiguous high-water mark is the newest row's last sequence and no row is updated. Because a class uploads first in, first out with one batch in flight, a batch whose first sequence skips ahead inserts a gap row for the missing range; a `drop` event covering the range inserts a closing row, and a gap unexplained after 24 hours raises an alert. `jobs` prunes rows older than 30 days except the newest per device, epoch and class.

### 3.4 Enrichment

Enrichment reads only in-process caches refreshed by `NOTIFY` on the low-rate channels (`backend.md` section 3); no network call sits on the ingest path. It adds:

- `metadata.logged_time` and the server `metadata.processed_time`.
- `device.groups`, `device.owner` and `device.org` from the device record, overriding agent-supplied values.
- The directory user behind an OS account (`actor.user.uid` resolved through the device-to-user links of BE-01) with `email_addr`, `groups` and `org`.
- `location` on public `src_endpoint` and `dst_endpoint` addresses, only when the operator configures a MaxMind DB-format file; none is bundled, because the common free databases carry their own terms. Read with `maxminddb-golang`.
- `osint` marks from the `detection` module's in-memory indicator index (feeds are the EDR design's) on hashes, domains and addresses in findings and context.

Connector `enricher` calls are pull-based on detection and device views (`extensions.md` section 6.1) and never run on ingest.

### 3.5 Write and acknowledgement

One batch is one spool class. Every producer first acquires the organization's shared capture fence through the `events` interface, before reading holds or writing any source, and retains the fence through its database commit (section 5). In order:

1. Raw-class batches go to the raw store first: ClickHouse inserts carry `insert_deduplication_token` set to the batch id, with `non_replicated_deduplication_window` set on the table, since its default of 0 deduplicates nothing on a plain MergeTree. The window counts insert operations, one per raw batch, and equals the peak raw-batch inserts per second times 900 s, the worst-case retry horizon (a `Retry-After` of 10 minutes with 20 % jitter, or the 5-minute backoff cap, rounded up to 15 minutes): 600,000 for 20,000 devices at one batch per device per 30 s, the raw class's age limit (section 2.4). The installer sets it from the full-profile device count, the operator raises it when the measured batch rate is higher, and the raw-store benchmark measures its memory cost (`backend.md` section 5). The bounded PostgreSQL investigation set (EV-01) takes the PostgreSQL path below.
2. When an export destination's class selection matches the batch, the enriched NDJSON is written to the blob store as an export-log object, create-only, under `export-log/<batch id>/<attempt id>` with a random attempt id, and its SHA-256 is kept for the index row (section 4.1).
3. The same fenced PostgreSQL transaction runs `COPY` into staging and moves rows into the event and quarantine tables (section 3.3), inserts lineage edges and findings into the `lineage` and `detection` inboxes through those modules' Go interfaces (section 3.6), the export-log index row with the object key and SHA-256, a correlation inbox row where needed under section 4.1, the device-stream rows and the ledger row. Context and raw batches commit with `SET LOCAL synchronous_commit = off` (`backend.md` section 5), or with `remote_write` when the operator configures failover durability for those classes; every other class commits synchronously.
4. Every `200 stored` and `200 duplicate` waits for a new acknowledgement fence on the current writable primary. In a fresh transaction, the narrow `events` acknowledgement function re-reads the exact device, batch id and ledger result, then inserts a new WAL-logged marker into `events.ack_fence`. The marker must write a fresh row, not a read-only transaction or a no-op conflict. Commit with `local` for primary-only context and raw durability, `remote_write` when that is the configured class guarantee, and `on` for other classes. A marker committed after observing the ledger also flushes the preceding ledger commit. A replica may group waiting acknowledgements for at most 100 ms; the group uses the strongest required commit mode. Respond only after the marker's successful commit response.

A duplicate on another replica goes through that primary transaction; a cached result or a standby read never authorizes an acknowledgement. A lost connection or uncertain commit leaves the request unacknowledged. Reconnect, re-read the ledger on the current primary and create a new fence, or return `503` when the ledger or barrier is unavailable. Never reuse a WAL position or a completion from a previous primary across promotion. The guarantee remains subject to section 1's configured standby boundary; asynchronous failover can lose an already acknowledged primary-only batch. PostgreSQL documents that asynchronous rows can become visible before flush, and that a later synchronous commit preserves earlier commits ([asynchronous commit](https://www.postgresql.org/docs/17/wal-async-commit.html), [commit modes](https://www.postgresql.org/docs/17/runtime-config-wal.html#GUC-SYNCHRONOUS-COMMIT)).

A retry after a failure between steps finds the raw store deduplicating by token inside the window and the ledger absent, so the batch is written once; it writes a new export-log object under a new attempt id, because the `agent` role can create but never overwrite. `jobs` deletes objects without an index row, left by failed attempts, after one hour.

### 3.6 Bus facts and consumers

The in-process bus (BE-04) does not cross replicas or roles, so consumers that must not miss an event receive it durably:

| Consumer | Delivery | What it receives |
|---|---|---|
| `lineage` | In the ingest transaction, through its Go interface, into its own schema | `ricevanta/lineage_activity` edges, which are stored there and not in the event tables (`lineage.md` section 4) |
| `detection` and `dlp` | In the ingest transaction, into their inbox tables, processed by `jobs` | Findings, with fingerprint and `repeat_of`, for alerts and server-side correlation |
| Exporters | `jobs` polls the export-log index every second | Export-log objects (section 4) |
| Correlation input | The producing transaction inserts one `events.correlation_inbox` batch under the commit-order protocol of section 4.1; `jobs` follows that sequence and reads the named event uids through the `events` interface | Events carrying `metadata.rule_matches` for a correlation's base rule or policy (`policy.md` section 4) |
| Live console views | Per-module change watermarks in PostgreSQL, read by each `api` replica every 2 s (BE-10) | Topic invalidations; metrics stay on the bus |

The `agent` role's credentials insert, and never update or delete, in exactly these places: in PostgreSQL, the event tables of the `events` schema, `events.quarantine`, `events.batch_ledger`, `events.export_log`, `events.correlation_inbox`, `events.device_stream`, `events.held_events` while a hold is `capturing` or `active`, the `lineage` edge tables, `detection.finding_inbox` and `dlp.finding_inbox`; in ClickHouse, the raw telemetry tables; in the blob store, create-only objects under the `export-log/` prefix, which only `jobs` can read. The role reads the batch ledger, `events.device_stream` and the published holds, and nothing else. It may execute the narrow capture-fence and capture-registration functions in section 5, the acknowledgement function in section 3.5 and the allocation-and-insert functions in section 4.1. Only those functions may lock protected coordination rows or insert acknowledgement markers; the role never updates a capture state or commit head directly.

### 3.7 Backpressure

Each `agent` replica keeps a bounded ingest queue (default 64 MB of compressed batches) and a bounded pool of ingest connections (default 8). A batch is answered `503` with `Retry-After` (5 to 60 s, from the queue's drain estimate, jittered) when the queue is full, when PostgreSQL commit latency exceeds its threshold (default 2 s at the 95th percentile), or when PostgreSQL is unreachable; raw-class batches are refused first and alone when only the raw store is unavailable. A quarter of the queue is reserved for audit and findings batches, so a raw backlog cannot delay detections. Check-ins and command polls are separate handlers and keep working while events are refused, so a device under backpressure keeps its policy and commands while its spool absorbs events.

### 3.8 Server-side events

Server modules emit through the `events` interface, including section 5's capture fence and registration before a source write. Low-rate events that carry authority (PKI issuance, approvals, policy publish, extension actions) are written inside the producing transaction, so the action and its event commit together. RADIUS accept decisions commit through a group commit of at most 10 ms before the accept is sent (RAD-05); other high-rate events (RADIUS rejects, accounting events, server health) go through a per-process buffer flushed every 500 ms or 1,000 events, and a crash loses at most that buffer. Server-side events are validated and enriched like agent events and carry `metadata.sequence` from a per-replica stream.

## 4. Export

### 4.1 Export log

Exporters run in `jobs` (BE-03) and read one export log, not the event tables, because events routed to an external destination under the full profile are not in PostgreSQL (EV-01) and because partition retention must not depend on a slow destination (EV-05). The log is zstd NDJSON objects, one per ingested batch and per flush of server-side events, written to the blob store and indexed in `events.export_log` by a bigint `commit_sequence`, class, receipt-time range, event count, size, object key and SHA-256 digest. An object is durable under a request uid before its database transaction allocates a sequence; an orphaned object from a rollback is never indexed and a job removes it after one hour (section 3.5).

`events.export_commit_head` has one row per organization. A transaction that will index an object updates that row to `last_sequence + 1`, uses the returned value for its index row, and keeps the row lock until commit. A rollback rolls back the increment. The next writer cannot allocate its value until the prior writer commits or rolls back, so a visible value has every lower value visible and there are no abandoned numbers. The same pattern with `events.correlation_commit_head` orders `correlation_inbox` batches in the transaction that stores their event uids. PostgreSQL ordinary sequences do not provide gapless transactional values, while row locks are held until transaction end ([sequence functions](https://www.postgresql.org/docs/17/functions-sequence.html), [explicit locking](https://www.postgresql.org/docs/17/explicit-locking.html#LOCKING-ROWS)). Allocation and index insertion happen only through two narrow `SECURITY DEFINER` functions owned by the migration role. Serving roles have `EXECUTE` and no direct `UPDATE` on either head and no direct `INSERT` on the index or correlation inbox. Each function updates its head and inserts the matching immutable row in the caller's transaction; it accepts no caller-selected sequence. If one transaction uses both functions, it allocates export first and correlation second, and takes no other head lock afterwards. Fix `search_path` to the owning schema and `pg_temp`, schema-qualify every relation, revoke `PUBLIC` execution and validate object ownership, receipt fields and event references before insertion ([security definer](https://www.postgresql.org/docs/17/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY)). This preserves insert-only exposed-role authority while allowing the functions to update private coordination rows. Consumers use one consistent snapshot for the head and rows; log pruning writes an explicit retained floor and per-destination loss record in the same transaction, so a pruned prefix is never mistaken for an unfinished writer.

An object is written only when an enabled destination selects its class. The log is bounded by age (default 7 days) and size (default 20 GB or 10 % of the blob volume); a segment leaves the log when every destination's cursor has passed it or when it crosses a bound. Objects hold DLP evidence snippets and script content until each destination's projection applies, so the blob store encrypts them at rest (`backend.md` section 5). The exporter recomputes the SHA-256 of every object it reads and refuses one that differs from its index row: it sends nothing from that object, raises a critical alert and a security finding, emits a `gap` event for the destination and advances past the sequence; PostgreSQL classes can be backfilled (section 4.3).

### 4.2 Exporter semantics

Each `ExportDestination` (`../specs/event-export.md` section 1) is one `jobs` job with its own lease row (`backend.md` section 3), cursor row and acknowledgement rows for its current window. The worker selects committed objects above the cursor by `commit_sequence`, applies the destination's filter and projection, encodes with the destination adapter and sends with at most `inflight` batches outstanding (default 2). It records each acknowledgement and advances the cursor only across the contiguous acknowledged prefix. Because allocation is commit ordered and gapless, observing sequence N proves no lower transaction can appear later. A crash or leader change reloads the acknowledgement rows and resends only unacknowledged batches. S3 workers also reload the immutable plan, frozen configuration revision and exact staged output bytes; they never reapply current projection or compression settings to an existing plan (`../specs/event-export.md` section 10). Memory per destination is bounded by `inflight` times `batch.maxBytes`.

Failures fall into three kinds, which every adapter maps from its protocol:

- Retryable (network error, timeout, throttling, server errors): exponential backoff with full jitter, base 1 s, cap 5 minutes, honouring `Retry-After`; the batch keeps its place.
- Permanent for one event (mapping error, an item the destination rejects as invalid): the event goes to `events.export_dead_letter` with destination, `metadata.uid`, export-log sequence and line, error and attempts, so it never blocks the destination; dead letters keep 30 days and replay from the console after a fix.
- Permanent for the destination (authentication or authorization failure, missing index, table, stream or bucket, or a planned-object integrity conflict): the worker pauses, keeps its cursor, and alerts.

A destination is `healthy`, `degraded` (retrying for more than 5 minutes, or a dead-letter rate above 0.1 %), `failed` (retrying for more than 30 minutes, or paused), or `lagging` (cursor more than 15 minutes behind, or within 20 % of the export-log bound). Transitions emit `pipeline_activity` events and notify through the `notifier` connectors and the console; recovery is an event too.

### 4.3 Filtering, replay and backfill

The filter selects classes, minimum severity, device groups, origin (agent, server, extension component) and an optional condition in the `ricevanta-cel-1` profile (POL-03) evaluated by `cel-go` with its cost limit; the projection removes fields (for example `unmapped`, `script.script_content` or the DLP snippet in `data_security.pattern_match`). Filters and projections only remove: what the endpoint redacted under DLP-02 never reaches the server. An operator can rewind a cursor inside the export log, or backfill a destination from the PostgreSQL event tables for a time range, which covers a new destination and an outage longer than the log for every class stored in PostgreSQL. An S3 replay freezes the selected configuration revision and gets a new replay namespace; retrying an interrupted delivery uses the original stored plan (`../specs/event-export.md` section 10).

### 4.4 Destinations

Every target integration of blueprint section 3.7 has an adapter; protocol, authentication, batching, acknowledgement, failure mapping, OCSF mapping and the Go client are in `../specs/event-export.md`.

| Destination | Transport | Acknowledged when | Duplicate key |
|---|---|---|---|
| Elasticsearch, OpenSearch | `_bulk` `create` into a data stream | Per-item status; `409` on an existing `_id` counts as delivered | `_id` = `metadata.uid` |
| Splunk HEC | `/services/collector/event` or `/raw` | Indexer acknowledgement returns `true` for the batch's `ackID` | `metadata.uid` in the event |
| Syslog | RFC 5424 over TLS (RFC 5425, octet counting); UDP (RFC 5426) as a lossy option | Write completes; no application acknowledgement exists | `metadata.uid` in structured data |
| OpenTelemetry Collector | OTLP logs over gRPC or HTTP | Export response, with `partial_success` rejections dead-lettered | `log.record.uid` attribute |
| Grafana Loki | Push API, JSON, gzip | `204` | Loki drops identical timestamp and line in one stream at query time (verify) |
| Microsoft Sentinel | Logs Ingestion API into a custom table through a data collection rule | `204` from the ingestion endpoint | `EventUid` column |
| Kafka | Produce with `acks=all`, idempotent producer (`franz-go`) | Every record of the batch acknowledged | Record header and key option |
| S3-compatible storage | Frozen-plan objects per class and hour, NDJSON zstd, with a manifest | Exact stored bytes and complete manifest verified, including on `412` | Destination revision, replay uid, plan uid and planned object key |
| `export-destination` connector | Contract of `extensions.md` section 6.1 | Contract acknowledgement | Batch id and `metadata.uid` |

No external destination is required: PostgreSQL, the optional raw store and the console serve every feature without one (blueprint section 3.7).

## 5. Retention, holds and archive

Retention runs in `jobs` by partition drop (`backend.md` section 5) per store and class (EV-07). Defaults, configurable per class:

| Store | Class | Default |
|---|---|---|
| PostgreSQL events | Findings, remediation outcomes, context, policy activity | 30 days (EV-01 target) |
| PostgreSQL events | Inventory, configuration state, compliance and vulnerability findings | 30 days; current state lives in the `devices` and `mdm` modules |
| PostgreSQL events | Agent health, pipeline activity | 14 days |
| PostgreSQL events | Raw telemetry for the bounded investigation set | 7 days (EV-01) |
| ClickHouse | Raw telemetry | 7 days (EV-01), by fenced retention jobs per day partition; no autonomous source-table TTL |
| PostgreSQL `lineage` | Edges and summary edges | `lineage.md` section 4 |
| PostgreSQL `audit` | Administrative audit records | 365 days, monthly partitions (section 6) |
| PostgreSQL events | Quarantine, dead letters, batch ledger | 30 days |
| Blob store | Export log | 7 days or the size bound (section 4.1) |

A hold copies matching events, raw rows and lineage edges into held tables that ordinary retention never touches. The hold freezes device and user uids, classes and a time range, including any future interval. Its states are `capturing`, `active`, `capture_failed`, `releasing` and `released`; a creation response means `capturing`, not a claim that historical capture has finished.

1. The `events` module owns one capture-gate row per organization. Its narrow database functions use `FOR SHARE` for every event, raw and lineage producer before the producer reads holds or writes a source. The caller keeps that transaction and lock until the source registration and database commit finish. Activation and retention use `FOR UPDATE` through the same interface. Use `READ COMMITTED` and read holds in a separate statement after acquiring the lock, so a wait cannot reuse a snapshot from before activation. This is a PostgreSQL lock contract, not a lock supplied by the blob store or ClickHouse.
2. Activation waits for prior producers and retention operations, then pins the source partitions and immutable committed source-batch ids that intersect the frozen hold scope. Every producer registers its batch ids, source locations and digests through the interface in its producing transaction, independently of whether export is enabled. Activation durably records that capture boundary and idempotent backfill tasks before releasing the gate. A producer admitted afterward observes `capturing` and `active` holds and, in the same transaction as its source registration, records matching capture tasks and source pins, or inserts PostgreSQL held copies. No ingest path may read holds before acquiring the fence.
3. A backfill task names the hold, source batch or lineage range, frozen predicate, source digest and destination. PostgreSQL copies commit with their task completion. ClickHouse copies use stable event and hold ids and durable per-task receipts; a retry verifies the copied ids, count and digest before marking completion in PostgreSQL. A crash between stores leaves the task pending and its source pinned. `lineage` exposes the same fenced registration, copy, verification and retention interfaces. A lease loss cannot clear a pin or declare capture complete.
4. Retention may drop a source only after its durable retention intent proves that no pending hold capture needs it. Source pins cover both `capturing` and `active` holds until each matching copy is verified. ClickHouse source tables have no autonomous TTL or unfenced mutation path. An uncertain external drop or copy blocks affected capture and retention until reconciliation verifies the source and destination; a missing source makes the hold `capture_failed` with a critical alert, never `active`. A hold cannot recover data already expired before its fence.
5. The hold becomes `active` only after all tasks through its recorded boundary have verified durable copies and the future-capture path is armed. Releasing or narrowing a hold is protected and audited (BE-02); use the same exclusive fence and durable cleanup tasks. Delete only that hold's references and copies that no other `capturing` or `active` hold needs. A failed cleanup stays `releasing`; ordinary retention cannot sweep its evidence.

Implementation blocker: the capture-gate functions, source catalogue, task and receipt schemas, ClickHouse copy and retention recovery protocol, and `lineage` interface still need an independently reviewed specification and fault-injection fixtures. Until those exist, legal-hold activation and retention cannot be handed to implementation as a proven cross-store protocol. PostgreSQL row locks supply only the database fence ([explicit locking](https://www.postgresql.org/docs/17/explicit-locking.html#LOCKING-ROWS)); they do not make ClickHouse and PostgreSQL atomic.

Archive before drop: when an `ExportDestination` of type `s3` sets `archive: true`, the retention job writes each PostgreSQL partition due for drop, from the `events`, `lineage` and `audit` schemas, to that bucket as day and class objects with a manifest (`../specs/event-export.md` section 10), verifies the stored checksums, and only then detaches and drops the partition. The archive applies the destination's projection but not its filter, so it keeps every row of the partition and omits only the fields the operator drops for that destination; ClickHouse raw rows are not archived by this PostgreSQL archive path; their fenced retention jobs obey the capture pins above (EV-01). A failed archive holds the drop and raises an alert; a held partition costs PostgreSQL disk, which the disk alert of section 8 covers, and an operator may release the hold explicitly, which is audited.

## 6. Administrative audit log

The `audit` module records every administrative action (EV-06). It is distinct from agent audit-class events (section 2.1), which follow the event pipeline.

Recorded: every `/api/v1` write, whether from the console, the CLI, GitOps or the extension bridge, including denied attempts; logins, failed logins, break-glass use and second-factor events (BE-01); approval requests, approvals, rejections and expiries with the frozen targets (BE-02); protected-action dispatch; policy, rule-pack and extension publication; CA key operations; destination, retention and hold changes; audit exports, checkpoint failures and verification results; reads of DLP evidence snippets and raw-telemetry investigation queries; and server lifecycle. Each record holds the requester (user or API token, session, source address, user agent, authentication method), the approver and approval id where one applies, the targets, the outcome, the request uid as `correlation_uid` and, for every change to a stored resource and always for protected actions, the canonical resource state before and after, with secret values replaced by their SHA-256 fingerprint. The exported form is OCSF per `../specs/ocsf-profile.md` section 1; the before and after state maps to the `entity` and `updated_entity` attributes of `entity_management` (3004; `../specs/ocsf-profile.md` section 1, Administration row).

Integrity requires an authenticated commitment to every prepared tail, not only the hourly checkpoint. The independent journal uses the storage, head, fencing and recovery contract of `backend.md` section 6.1 and `../specs/authority-journal-protocol.md`; audit evidence has a separate namespace and sequence under the same coordinator. Ordinary blob write access does not grant journal write access. The journal still lacks a proved cross-store gate, and the specification does not yet define the full typed audit payload, outcome, chain, sequence, replay model or fixtures, so audit remains blocked.

1. Before an action transaction can commit, the coordinator serializes the organization's audit writes and stores a signed, immutable prepare containing the full canonical record, request uid, audit sequence, previous record hash and record hash. Advance the authenticated live head before returning the prepare receipt. Failed and denied attempts, sensitive reads and lifecycle records use the same journal without a resource mutation. Secrets remain fingerprints or ciphertext, never plaintext.
2. The acting module inserts the identical prepared record inside its action transaction with synchronous commit. After commit, the coordinator publishes an immutable commit binding the prepare and result and advances the live head before answering the caller or publishing an authority change. The prepare records the intended action; only its commit or resolution supplies the final outcome. Retries use the original request uid and hashes. `api` and `jobs` have `INSERT` and `SELECT` on audit records; the migration role owns the schema, and serving credentials cannot change records, remove a rejecting trigger or detach partitions.
3. A prepare without a commit or resolution keeps its sequence and blocks later administrative writes. Exact database record and action evidence can complete its commit. Otherwise the offline recovery quorum signs an `aborted` or `tampered` resolution after inspecting the named action and target. A missing row alone is ambiguous and never permits an unsigned abort. Every resolution remains in the independent chain. Denies, consumptions and reserved counters remain effective under the recovery contract.
4. Record hashes use `SHA-256(previous hash || JCS(record))`, with RFC 8785 Appendix B fixtures. `jobs` signs checkpoints binding organization, epoch, resolved audit sequence, record hash and journal head every hour and every 10,000 resolved records. Prepare records, commits, resolutions and checkpoints go to every destination with `audit: true`. Export timing is not the live-tail integrity boundary: the independent journal already holds each accepted prepare. A local journal protects against a database-only writer; a qualified Object Lock destination also retains independent immutable versions under its configured retention.
5. Before each administrative write, the coordinator compares the database projection with the authenticated live head. The daily verifier checks the independent chain and each retained database row and fetches the newest checkpoint and tail proof from every `audit: true` destination. Changed records, deleted suffixes, replayed heads, altered resolutions and missing evidence alert at critical severity and seal authority writes. `ricevanta audit verify --anchor <url>` checks an exported range against its named trusted head; a supplied old checkpoint alone cannot prove that no newer tail existed. Verification results use the same protocol, so database changes cannot forge a passing result.

The required guarantee covers an uncheckpointed suffix that already has a durable journal prepare. A database writer cannot silently delete that suffix or have a later checkpoint validate a rewritten record. The guarantee depends on the independent live head, complete journal evidence and the publication barrier. A writer controlling the journal and every trusted copy is outside that boundary; host root can alter a local journal. The design does not claim that Object Lock prevents a storage administrator from hiding a current object behind a new version or delete marker. Required fault-injection cases are in `../specs/platform-qualification.md` sections 4 and 6; they have not run.

Retention drops whole monthly partitions after 365 days by default (PCI DSS 4.0 requirement 10.5.1 asks for 12 months, verify); before detaching an audit partition the retention job writes and signs a checkpoint at that partition's last record and exports it to every `audit: true` destination, and verification restarts from that checkpoint; the drop is itself a journaled record. A dedicated retention credential may execute only the migration-owned detach function after the required checkpoint and published retention authorization pass; serving roles cannot detach directly. Shortening audit retention is a protected action (BE-02).

Query and export: the console's audit view (`console.md` section 5.12) uses `listAuditEvents` and `getAuditEvent`, filtered by actor, action, target, outcome and time with keyset pagination, under the `audit.events.read` permission. `exportAuditBundle` returns a signed bundle of records and checkpoints for a sequence range, which `ricevanta audit verify` checks offline; each export is itself recorded.

## 7. Events per domain

Classes are defined in `../specs/ocsf-profile.md` section 1; this table assigns emitters, spool classes and default stores.

| Domain | Emitting component | Classes | Agent spool class | Default store |
|---|---|---|---|---|
| MDM | Agent `mdm`; server `mdm` for Apple MDM and OMA-DM results | Inventory, software, configuration change, compliance, vulnerability | Findings and state | PostgreSQL events |
| EDR telemetry | Agent `edr` | Process, file, network, DNS, registry, module, scheduled job, event log, script | Context (default profile) or raw (full profile) | Context in PostgreSQL; raw in ClickHouse, an external destination or the bounded PostgreSQL set (EV-01) |
| EDR detection | Agent `edr` (single-event Sigma); server `detection` (correlation) | Detection finding | Findings and state | PostgreSQL events, `detection` inbox |
| EDR response | Agent `edr` | Remediation classes | Findings and state | PostgreSQL events |
| DLP | Agent `dlp`, from file, clipboard, removable-media and browser decisions | Clipboard, peripheral and HTTP triggers; data security finding | Context for triggers; findings and state for findings | PostgreSQL events, `dlp` inbox |
| Lineage | Agent `lineage`; server `lineage` for cross-device edges | Lineage activity | Lineage edges | PostgreSQL `lineage` schema |
| PKI | Server `pki` in `jobs` | Certificate lifecycle | None | PostgreSQL events |
| RADIUS | Server `radius` | Authentication, network activity (accounting), network remediation (Disconnect and CoA) | None | PostgreSQL events |
| Policy | Agent `policy`; server `policy` | Policy activity | Audit | PostgreSQL events |
| Agent health | Agent `runtime` | Agent health activity | Findings and state | PostgreSQL events |
| Pipeline | Agent `events`; server `events` | Pipeline activity (drop, gap, quarantine, destination state, archive) | Audit | PostgreSQL events |
| Administration | Server `audit` | API activity, user and role management, entity management | None | PostgreSQL `audit` schema |
| Server | Server `platform` | Application lifecycle | None | PostgreSQL events |

## 8. Pipeline metrics and health

Agent: spool bytes, oldest unsent age, dropped segments, records and bytes, upload errors and the last acknowledged sequence, each per class, travel in the check-in health and in `agent_health_activity` (AG-09).

Server, as Prometheus metrics on `/metrics` (`../architecture.md` section 5) without device labels: `ricevanta_events_ingested_total{class}`, `ricevanta_events_quarantined_total{reason}`, `ricevanta_events_duplicate_total{level}` (batch, uid, content), `ricevanta_ingest_batch_seconds`, `ricevanta_ingest_queue_bytes`, `ricevanta_ingest_refused_total{class}`, `ricevanta_events_reported_dropped_total{class,reason}`, `ricevanta_events_sequence_gaps_open`, `ricevanta_export_lag_seconds{destination}`, `ricevanta_export_inflight_batches{destination}`, `ricevanta_export_errors_total{destination,kind}`, `ricevanta_export_dead_letter_total{destination}`, `ricevanta_export_log_bytes`, `ricevanta_retention_dropped_partitions_total{store}`, `ricevanta_archive_held_partitions`, `ricevanta_audit_verified_sequence`, `ricevanta_audit_checkpoint_age_seconds`.

Alerts: destination failed or lagging; quarantine above 0.1 % of an hour's events; a gap unexplained after 24 hours; fleet spool drops above a threshold; an audit chain mismatch or a checkpoint older than two hours (critical); an archive hold; PostgreSQL disk above 80 %. The console's events and export view (`console.md` section 5.16) reads destination state through `getExportStatus` and adds the pipeline summary, dead letters, holds and archive state through `getPipelineStatus`, `listDeadLetters`, `replayDeadLetters`, `listHolds` and `createHold`; the device view shows the per-class spool state from the check-in health.

## 9. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: every loss is either impossible under the stated conditions or counted where it happens; batch, uid and content deduplication keep the stores single-copy without a distributed transaction; a synchronous acknowledgement fence protects both new and duplicate acknowledgements from an unflushed ledger commit; one export log serves every destination, including raw telemetry that never enters PostgreSQL, without a message queue (BE-07); a slow destination never holds PostgreSQL retention; the independent audit tail extends the intended integrity boundary to uncheckpointed records, with range exports checked against a trusted current head.

Trade-offs: export and correlation commit-head locks serialize the final ingest commit stage, so their latency and throughput must be measured at the fleet target; every acknowledgement writes a fresh WAL marker and waits for its configured durability, with at most 100 ms of grouping delay before the database wait; capture gates can delay producers during hold activation or retention, and pending copies pin source storage; the export log stores enriched events a second time in the blob store, encrypted at rest, for up to 7 days; `synchronous_commit = remote_write` for context and raw classes adds a standby round trip to each of their commits, which lowers the batch throughput `backend.md` section 5 budgets by that latency; partitions by receipt day mean an investigation by event time scans the partitions after that time, not before; the independent audit journal serializes administrative writes and adds synchronous storage operations; copying held events duplicates storage for the hold's life.

Dependencies: `crc32c` and `zstd` on the agent; `klauspost/compress`, `pgx`, `clickhouse-go`, `minio-go` and `cel-go` on the server; `maxminddb-golang` for optional geolocation; the destination clients in `../specs/event-export.md`; all with rows in `../licensing.md` or proposed with this design.

Limits: syslog delivers without acknowledgement and UDP is lossy by protocol; a destination outage longer than the export-log window loses raw-only events for that destination; a wiped device loses its unsent spool; a failover to an asynchronous standby can lose acknowledged context and raw batches under the default primary-only acknowledgement fence; the legal-hold protocol in section 5 remains an implementation blocker; a raw batch whose ClickHouse insert succeeded but whose PostgreSQL commit failed is stored twice in ClickHouse when it is retried after the deduplication window, so consumers deduplicate on `metadata.uid`; audit integrity remains blocked on the authority-journal protocol; a host or storage administrator controlling the independent journal and every trusted copy can rewrite local evidence; geolocation needs an operator-supplied database.

Alternatives considered: exporters reading the PostgreSQL event tables by cursor (rejected: raw telemetry sent only to an external destination is not there, and partition drops would race slow destinations); an embedded Kafka, NATS or Vector as the export buffer (rejected: a second stateful service, against BE-07); acknowledging batches on receipt before commit (rejected: a server crash would lose acknowledged events); synchronous commit for every class (rejected: costs the throughput `backend.md` section 5 budgets for context and raw rows); exactly-once export with destination transactions (rejected: only Kafka offers them, and only to `read_committed` consumers; the event uid makes at-least-once safe everywhere); partitioning by agent event time (rejected: a skewed or offline clock would select partitions that do not exist); audit immutability by database permissions alone (rejected: a superuser rewrites history undetected); an external transparency log or RFC 3161 timestamping authority as the required anchor (rejected: an online dependency for every installation; the local journal keeps self-hosting possible, while only a qualified independent immutable destination extends protection to journal-volume tampering).

## 10. Sources

- PostgreSQL: [asynchronous commit](https://www.postgresql.org/docs/17/wal-async-commit.html), [`synchronous_commit`](https://www.postgresql.org/docs/17/runtime-config-wal.html), [WAL location functions](https://www.postgresql.org/docs/17/functions-admin.html), [row locks](https://www.postgresql.org/docs/17/explicit-locking.html#LOCKING-ROWS), [sequence functions](https://www.postgresql.org/docs/17/functions-sequence.html), [`CREATE FUNCTION`, security definer](https://www.postgresql.org/docs/17/sql-createfunction.html).
- ClickHouse: [deduplicating inserts on retries](https://clickhouse.com/docs/guides/developer/deduplicating-inserts-on-retries), [autonomous TTL deletion](https://clickhouse.com/docs/concepts/features/operations/delete/ttl).
- OCSF 1.9.0: [metadata](https://schema.ocsf.io/1.9.0/objects/metadata), [device](https://schema.ocsf.io/1.9.0/objects/device), [entity management](https://schema.ocsf.io/1.9.0/classes/entity_management); base attributes `count`, `start_time`, `end_time` and `osint` checked on [detection finding, 1.6.0](https://schema.ocsf.io/1.6.0/classes/detection_finding) (verify in 1.9.0).
- [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562) (UUIDv7), [RFC 8878](https://www.rfc-editor.org/rfc/rfc8878) (zstd frames), [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) (JSON canonicalization).
- `crc32c` crate license: [crates.io API](https://crates.io/api/v1/crates/crc32c).
- Destination sources: `../specs/event-export.md` section 14.
