# Lineage design

How data lineage is stored and keyed: the graph model, the identities it keys on, how edges reach the server, where the graph lives, and how it is bounded. Confidence scoring, cross-device joins and the console's exploration views are open (`analysis.md` section 3) and belong in this file. Decision: LIN-01 in `decisions.md`.

## 1. Model

Nodes are entities and activities in the W3C PROV sense: files (by stable identity, section 2), content (by hash), processes, users, devices, and destinations (removable volume, cloud sync folder, browser upload target, network peer). Edge types are the PROV-DM relations (`used`, `wasGeneratedBy`, `wasDerivedFrom`, `wasAttributedTo`) plus Ricevanta file-operation types in the `io.ricevanta` namespace (`copy`, `move`, `rename`, `compress`, `extract`, `upload`), since neither PROV nor OpenLineage defines those. Every edge carries a confidence, a timestamp, and evidence: the UID of the OCSF event it came from plus a compact summary (event class, time, process identity, path) so the edge stands alone once the event has expired. Observed edges come from a single event; inferred edges (content match between two files, a read followed by a write in one process) are marked as such, per blueprint section 3.4.

## 2. Identities

Every key must stay valid across reboots and remounts, since edges outlive both.

| Thing | Key |
|---|---|
| File, Linux | file-system UUID, inode, inode generation (read through the BPF program, since `statx` exposes no generation; verify per file system) |
| File, Windows | volume GUID and the 128-bit file ID |
| File, macOS | volume UUID and APFS inode |
| Process | boot session ID (`boot_id` on Linux, `kern.bootsessionuuid` on macOS, the boot time on Windows) plus pid and process start time; on macOS the audit token's pid version is recorded as well |
| Content | BLAKE3 hash; TLSH similarity hash for partial matches (verify license); ssdeep is not used (GPL-2.0) |
| User, device | Directory identity and device record |

A save-by-replacement on any OS creates a new file identity and is recorded as a `wasDerivedFrom` edge from the old one. FAT and exFAT volumes have no stable file identity across moves, so files on them are keyed by path and content hash and their edges carry lower confidence.

## 3. Transport and storage

- Endpoint: `lineage.db` in SQLite (`design/agent.md` section 5), one node table with integer IDs and one edge table (source, target, type, confidence, evidence, time) indexed on (source, type) and (target, type). Path queries are recursive queries bounded by an explicit depth limit, which is also the cycle guard. Retention: edges older than the configured age (default 90 days) are deleted and the paths through them rolled up into summary edges between the surviving ends; summary edges age out at four times the edge age.
- Upload: edges are events of the `io.ricevanta` lineage class in their own spool class, dropped after context and before detections (`design/agent.md` section 5), so the server receives lineage under the default telemetry profile without the raw events behind it.
- Server: the same edge model in the `lineage` schema in PostgreSQL, partitioned by month on edge time with a device index, so retention drops partitions; default server retention is 180 days for edges and the same four-times rule for summary edges. Path queries are recursive queries with the `CYCLE` clause. No graph database (section 4).
- Fan-out control: a process that touches thousands of files (a backup, a build, an indexer, a browser over its lifetime) would make every file a descendant of every other through that process node. Reads link to a later write only within a window (default 10 minutes) and in order; degree is counted per process instance per window (default 1,000); above it, inheritance continues at reduced confidence and a detection is raised, never a silent drop, so a user cannot clear a classification by opening many files.

## 4. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: one storage technology on each side; identities that survive renames, moves and reboots; every edge carries its own evidence summary; a bounded graph on both sides.

Trade-offs: recursive SQL is slower than a native graph engine on deep paths, accepted because paths are depth-bounded; roll-up summaries lose per-step detail after retention; evidence summaries duplicate a few fields of the event.

Dependencies: the `blake3` crate (CC0-1.0, Apache-2.0 or Apache-2.0 with LLVM exception), a TLSH crate (verify), SQLite and PostgreSQL as already chosen; vocabulary from W3C PROV-DM and OpenLineage (Apache-2.0).

Limits: no sourced benchmark covers 10^7 edges per device or 10^9 fleet-wide, so the sizing is a design target to measure; content matching across devices needs the content hash on both sides, which the DLP scanner computes only for classified files; FAT and exFAT volumes give path-keyed, lower-confidence edges.

Alternatives considered: a server graph database (rejected: Neo4j Community is GPLv3 and single-node, Memgraph is source-available, Apache AGE is Apache-2.0 but an extension in every image for what recursive queries cover); an embedded graph engine (rejected: KuzuDB is archived, no maintained MIT engine fits the memory budget); `ltree` (rejected: one path per node fits trees, not multi-parent provenance); closure tables (rejected: O(depth) writes on a write-heavy graph); keeping every edge forever (rejected: provenance research reports edges outgrowing nodes without bound, verify); dropping inheritance at a fan-out cut (rejected: an evasion).
