# Change stream

`GET /api/v1/changes` (`streamChanges`) is a Server-Sent Events stream that tells the console which topics changed, as opaque per-topic tokens, and never sends row data. Views then refetch through ordinary authorized operations (BE-10). This specification fixes the topics, the watermark store, the per-replica hub, the framing, the authorization lifecycle of a stream and the console reader.

Authorities: BE-04, BE-10, BE-17 and BE-18 in [decisions](../decisions.md), [console design](../design/console.md) section 4, [backend design](../design/backend.md) sections 1 and 3, [API foundation](api-foundation.md), [identity sessions](identity-sessions.md). The operation and event schemas are in [`schemas/openapi/v1/openapi.yaml`](../../schemas/openapi/v1/openapi.yaml); framing and subscription vectors are in `fixtures/sse.json`.

## 1. Boundary and dependencies

Included: topic grammar and permissions, the `platform.change_watermarks` table and its bump interface, the hub in every `api` replica, the stream handler, and the console reader with polling fallback. Excluded: the domain writes that bump topics, which each domain slice adds when it implements the change (a topic with no writer simply never advances), and row data of any kind.

The handler runs inside the BE-15 `api` listener and its per-handler deadlines. The store needs the PostgreSQL platform slice; until then the hub runs against an in-memory watermark source in tests. A stream is an authenticated stream under BE-12: once the authority read lease exists, the hub ends every stream when its replica's lease expires (backend design section 6.1). Every production stream and authenticated read waits for the unresolved BE-12 fence and typed reducers in [authority journal protocol](authority-journal-protocol.md) sections 5, 6 and 10. Only isolated models may use fixture authority. No notification or database watermark is authorization evidence.

## 2. Topics

A stream subscribes to 1 to 16 distinct topics given as repeated `topic` query parameters. A topic is an aggregate name or `<kind>/<uid>` for one entity, with a lowercase UUIDv7.

| Topic | Scope rows | Read permission | Advances when | Writer |
|---|---|---|---|---|
| `devices`, `device/<uid>` | Device group; entity | `mdm.devices.read` | Device record, lifecycle, labels, group membership, processed inventory or compliance state changes; never on a routine check-in | `devices` |
| `alerts`, `alert/<uid>` | Device group; entity | `edr.alerts.read` | Alert created or changed | `detection` |
| `dlp.findings` | Device group | `dlp.findings.read` | Finding created or changed | `dlp` |
| `commands/<device uid>` | Entity | `mdm.commands.read` | Command journal state of that device changes | `mdm` |
| `enrollments` | Device group | `mdm.enrollments.read` | Enrollment request created or decided | `pki` |
| `certificates` | Device group | `pki.certificates.read` | Device certificate issued, renewed or revoked | `pki` |
| `certificates.infrastructure` | Organization | `pki.infrastructure.read` | Service, gateway, signing or CA certificate changes | `pki` |
| `rollouts` | Device group | `mdm.rollouts.read` | Rollout created, advanced, paused or rolled back | `mdm` |
| `extensions` | Organization | `extensions.packages.read` | Package, grant or enabled state changes | `extensions` |
| `exports` | Organization | `events.destinations.read` | Destination configuration or status changes, at most once per 30 seconds per destination | `events` |
| `approvals` | User; organization | None (subject) | A request the user made or may decide changes; the organization row for holders of `authz.approvals.read` | `authz` |

Two internal topics are never subscribable: `identity.sessions`, one row per user, advanced on any revocation, disable, re-authentication or token revocation of that user; and `authz.grants`, one row, advanced on any role, assignment, group-membership or access-policy change. The hub uses them to recheck streams (section 6).

Device-group topics have one row per device group plus one `~ungrouped` row. A change bumps the row of every group the entity belongs to before and after the change, so moving a device between groups advances both. An operator with scope `all` sees every row; an operator scoped to groups sees exactly those rows. For `commands/<uid>`, the uid is a device uid. Each topic resolves its own permission-specific scope, never the union of scopes from other grants. Organization topics require scope `all`; `approvals` uses the visibility rules of identity sessions section 6, so tokens cannot inherit interactive decision eligibility. Entity topics are authorized at subscription against the entity's current groups through the owning module's interface, and an entity outside the caller's scope is `not_found`, the same answer as an unknown uid, so the stream reveals no existence (console design section 4). Validation order is grammar and count (`validation_failed`), then permissions in request order (`permission_denied`), then entity scope (`not_found`); `sse.json` fixes the decisions.

## 3. Watermark store

The `platform` module owns one table and the interface that writes it (BE-04: modules call the callee's interface inside their own transaction):

```sql
platform.change_watermarks (
  topic      text   NOT NULL,   -- topic kind, e.g. 'devices', 'device', 'identity.sessions'
  scope_key  text   NOT NULL,   -- group uid, '~ungrouped', entity uid, user uid or '*'
  counter    bigint NOT NULL,
  bumped_xid xid8   NOT NULL,
  PRIMARY KEY (topic, scope_key)
)  -- plus an index on bumped_xid
```

`platform/changes.Bump(ctx, tx, keys)` runs `INSERT … ON CONFLICT DO UPDATE SET counter = counter + 1, bumped_xid = pg_current_xact_id()` once per key at the end of the caller's transaction, so the row lock is held only until that commit and the counter of each row only increases. Only the `api` and `jobs` roles have the function's grant; the agent-facing roles never bump, because their inserts are untrusted until `jobs` processes them (BE-03). A module bumps each key at most once per transaction. Counters start at 1, never decrease or wrap, and overflow refuses the domain transaction and raises an alert. Entity deletion bumps a retained tombstone; remove it only after no stream references it and the next subscription would resolve `not_found`. Aggregate/scope rows are not deleted or reset during ordinary operation. A serialization/deadlock retry repeats the whole domain transaction; it never publishes a bump without the committed domain change.

## 4. Hub

Each `api` replica runs one hub. A successful tick every 2 seconds reads aggregate rows and currently subscribed entity rows in one consistent PostgreSQL statement. It selects changes with `bumped_xid >= previous_horizon` and also returns `pg_snapshot_xmin(pg_current_snapshot())` independently of the row set, including when it is empty. The initial/reconnection horizon is zero. PostgreSQL defines snapshot xmin as the lowest still-active transaction ID and `xid8` as non-wrapping over an installation ([system information functions](https://www.postgresql.org/docs/17/functions-info.html), table 9.83). A transaction that commits after an observation has an ID at or above that horizon, so the next query can find it; repeated rows are harmless.

The first scan initializes all aggregate rows, including `~ungrouped`; absent keys mean counter zero. One statement has a one-second deadline, a 100,001-row detection limit and a 16 MiB decoded-result limit. More than 100,000 rows or either byte/memory cap fails the tick; never advance the horizon after partial results. A long transaction may hold xmin back and increase scan work; exceeding the budget makes live updates unavailable and the console polls. This is a capacity limit, not permission to silently drop changes. The hub retains only subscribed entity rows and necessary aggregate rows, capped at 64 MiB.

Subscription installs its interest under the hub mutex before taking its initial snapshot, buffers matching tick updates while that snapshot is read, then merges counters by maximum and emits the snapshot before later changes. A slow initial read has the same one-second bound. Removing the final interest releases entity memory. Normal database cost is one bounded watermark statement per replica per tick, plus subscription snapshots and authority/entity checks; those additional checks are not counted as free.

A token is the first 16 digest bytes encoded as 22 base64url characters of SHA-256 over UTF-8 `ricevanta/change/v1\n` followed by canonical sorted-key JSON `[hub_instance, generation, topic, pairs]`. `hub_instance` is 32 lowercase hex characters from 16 random bytes at process start; generation is a positive decimal string, incremented on every reconnection; pairs are `[scope_key, decimal_counter]` arrays sorted by UTF-8 scope-key bytes, with no duplicates. Counters and generation are strings to avoid numeric precision loss. Tokens are equality markers, never credentials or authority. Missing rows use zero so empty topics have defined tokens.

Restart, connection loss, a lower observed counter or any recovery/epoch signal discards the cache, increments generation and closes streams before a fresh full scan. Generation overflow replaces the hub instance. A database restore must enter sealed recovery, never continue an existing connection as trusted. This gives reconnecting clients a new snapshot even with lower counters; it does not prove that a database writer cannot hide an invalidation. The independent reconciliation poll in section 7 bounds that residual for honest clients.

## 5. Stream protocol

The handler applies the request guard of [identity sessions](identity-sessions.md) section 4 (class `none`, credentials session or token), validates topics (section 2), then answers `200` with `Content-Type: text/event-stream`, `Cache-Control: no-store` and the API response headers, and writes UTF-8 frames as [WHATWG HTML](https://html.spec.whatwg.org/multipage/server-sent-events.html) section 9.2.5 requires:

| Frame | When |
|---|---|
| `retry: 5000` | First line, setting the client's reconnection delay |
| `event: snapshot` with `{stream_uid, topics:[{topic, token}]}` | Immediately after, with every subscribed topic |
| `event: change` with `{topic, token}` | At most once per topic per tick, when the stream's token for that topic differs from the last one sent |
| `event: session` with `{state: "changed"}` or `{"ended"}` | Before the server closes the stream for an authorization change or the end of the session (section 6) |
| `event: reconnect` with `{reason}` | Before closing for `shutdown`, `lifetime` or `database` |
| `: keepalive` | After 15 seconds without a frame |

Data is compact JSON with sorted keys, one line per event; the encoder vectors in `sse.json` fix the bytes. No frame carries an `id`, so a client sends no `Last-Event-ID` and a reconnection always begins with a full snapshot. The heartbeat follows the specification's advice to send a comment "every 15 seconds or so" because "legacy proxy servers are known to … drop HTTP connections after a short timeout" (section 9.2.7), and keeps the stream under the 60-second proxy idle timeout of the deployment (architecture section 3.4).

Each write sets a write deadline 10 seconds ahead through `http.ResponseController`, matching the BE-15 rule that handlers bound their own writes; a client that stops reading loses its stream. A stream lives at most one hour, then receives `reconnect` with `lifetime`. `http.Server.Shutdown` waits for active requests, so the runtime's stop request ends every stream with `reconnect` and `shutdown` through a function registered with `Server.RegisterOnShutdown`, which Go documents for starting protocol-specific shutdown of long-lived connections ([net/http](https://pkg.go.dev/net/http#Server.RegisterOnShutdown)). A failed tick closes streams with `reconnect` and `database` if writing is still authorized, otherwise closes without a frame; new streams return `503 unavailable` until a complete scan succeeds. The independent authority timer closes streams even when a tick or write blocks. Shutdown never waits for a final frame beyond the runtime deadline.

## 6. Authorization during a stream

A stream binds its credential uid and credential generation, user, epoch, per-permission scope, subscribed entities and current authorization deadline. Before opening and on each tick, check current committed authority independently of the watermark rows. `identity.sessions` and `authz.grants` are acceleration hints only: a database writer can delete them. Recompute the dependency closure and entity visibility before emitting a snapshot or change. No frame may be emitted from an expired, mismatched or unavailable authority lease. Activity-only record-generation changes do not close a stream; the credential generation changes only on rotation, revocation or changed authentication provenance.

A revoked/expired credential, disabled user, changed credential generation or epoch ends the stream. Re-authentication rotation therefore closes the old stream. Changed permissions, topic scope or entity visibility ends it with `session: changed` when a still-valid authorization permits that terminal notice; otherwise close without data. Do not emit the now-forbidden topic's name or token. Credential/authority loss yields `session: ended` only when safe to send, then closure. Token streams use token expiry and current owner/grant intersection; they have no session idle timer.

Live deadlines are at most five seconds from the start of the last successful authority observation, never from completion of a slow read. Independent timers cancel the handler and pending writes on expiry even if PostgreSQL or journal reads stall. Idle/absolute deadlines may be earlier; other requests can extend idle only after a fresh authoritative reread. The stream itself cannot extend activity. Normal notification latency is a tick plus a bounded check, but the required security cutoff is the five-second lease, not an approximate three-second promise. BE-12 must prove admission/publication ordering and this cutoff before production streams are registered.

## 7. Console reader

The console reads the stream with `fetch` and a streaming body parsed by the WHATWG event-stream algorithm, not with `EventSource`. `EventSource` cannot add the `X-Ricevanta-Background` marker, and when a response "status is not 200, or … Content-Type is not text/event-stream", the specification says "fail the connection" (section 9.2.2) without exposing the status, so the console could not tell an expired session from a forbidden topic. The parser handles `CRLF`, `CR` and `LF` across chunk boundaries and discards an unterminated final event (`sse.json`).

- A snapshot marks every visible view stale once; `useResource` refetches each, which also covers changes made while the stream was connecting.
- A `change` for a topic refetches the visible views on that topic, at most once every 5 seconds per view.
- `session` `changed` drops protected cached data, refetches `getSession` and rebuilds authorized subscriptions. `ended` and `401` return to login. A `403` or `404` identifies no offending topic: recheck session/route visibility and probe the requested topics individually, at most 16 bounded requests, dropping only refused topics. CLI token clients instead re-evaluate their token and never call session-only `getSession`.
- Topics follow the visible views; a route change reconnects with the new set after a 1-second debounce.
- Reconnection waits the `retry` delay with ±20 % jitter. After three failed attempts the console polls each visible view every 30 seconds and shows that live updates are paused; it keeps trying the stream every 60 seconds. A tab hidden for 5 minutes closes its stream and refetches when shown.
- Even while SSE is healthy, visible views perform an authorized background reconciliation fetch every 30 seconds, with up to five seconds of positive jitter, so a missing watermark cannot hide stale state indefinitely. These fetches never renew idle time. The console opens one stream per tab; MDN describes browser connection limits (verify), but this design assumes no fixed HTTP/2 stream count.

## 8. Resource bounds

At most 16 topics per stream, 4 streams per session, 8 per user and 1,000 per replica; beyond them the answer is `429 rate_limited`. Session/user counts are deployment-wide atomic expiring reservations, renewed only by a successful authority check and released on close; token streams share the eight-per-user cap and have at most four per token. A failed reservation store refuses admission. Each stream has a 64 KiB output queue, coalesces changes per topic, and closes on overflow or frames/lines over 16 KiB; snapshot size stays below that bound. The client rejects oversized lines, invalid UTF-8/JSON, unknown event types and invalid event shapes, then reconnects with backoff. Per stream the hub keeps the credential, the subscribed topics and their last tokens. Per tick the hub runs one watermark query plus the checks of section 6, and per change it recomputes tokens only for streams subscribed to that topic. Entity scope and grant checks must not depend solely on mutable change rows. Batch checks per credential/dependency closure where possible without extending the lease.

## 9. Security trace

Path: domain transaction → `Bump` in the same transaction → hub tick → token digest per stream → frame → console refetch through authorized operations.

| Attacker | What the attacker gets |
|---|---|
| Stolen enrollment token | Nothing; it is not a session or API credential |
| Compromised agent host | Agent-facing roles cannot bump watermarks, so a flood of agent uploads advances topics only as fast as `jobs` processes them; the host gets no stream |
| Compromised console session | The topics and change timing the operator may read, never row data; refetches stay under per-request authorization; revocation/authority loss closes the stream within the five-second lease; a stalled check cannot extend it |
| Rogue extension publisher | Modules receive change notices only through the bridge's safe catalogue (`approval.pending`), never the stream or its credential (EXT-04) |
| Network position between agent and server | Not this channel; the stream rides the console's TLS connection |
| Database writer without signing keys | Can bump/delete rows, force bounded refetch traffic or hide an invalidation until the independent 30-to-35-second reconciliation fetch. Tokens prove no data integrity. Current authorization is checked outside these rows; ordinary reads must separately reject forged authority under BE-12 |
| Server restored from backup | Serving seals before recovery. Epoch transition invalidates credentials; reconnect after fresh login starts a new generation and complete snapshot. A snapshot cannot unseal the server or establish current authority |

The `approvals` organization row reveals to holders of `authz.approvals.read` when approval activity happens, which they can already list; per-user rows reveal nothing beyond the user's own and decidable requests.

## 10. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: one normal watermark query per replica per tick, plus bounded authorization and subscription work; no row data crosses the stream, so authorization stays in the ordinary operations; snapshot-on-connect and independent polling reconcile restarts, failovers and missing invalidations; agent-facing roles cannot drive the stream.

Trade-offs: every reconnection refetches the visible views; a 2-second tick plus a 5-second view throttle bounds freshness at about 7 seconds; topic rows add one row update per changed key to domain transactions; the `fetch` reader is console code that `EventSource` would otherwise provide.

Dependencies: PostgreSQL 17 `xid8` functions and the PostgreSQL platform slice; BE-15 for the listener and shutdown hook; BE-12 for the read-lease integration; Go standard library; no console dependency.

Limits: freshness is seconds, not milliseconds; aggregate tokens reveal change timing within the reader's own scope; a topic without a domain writer never advances; snapshot and reconciliation reads still refresh it. Domain writer wiring is required before its live-data feature is complete at v1.0.0.

Alternatives considered: WebSocket (rejected by BE-10: bidirectional and its own handshake checks); `LISTEN`/`NOTIFY` per change (rejected: backend design section 3 keeps `NOTIFY` off high-rate paths, and per-operator listeners would scale with operators); sequence-numbered changes with `Last-Event-ID` replay (rejected: sequences are assigned before commit and can become visible out of order, and replay after a restore would need retained history); `EventSource` (rejected above); row data in events (rejected: it would bypass per-request authorization and field omission).

## 11. Unresolved questions

- Which reviewed BE-12 authority reader and independent timer prove stream revocation despite stalled reads and writes?
- Which deployment-scale measurements qualify the 100,000-row, 16 MiB result and 64 MiB hub budgets alongside the required authority checks?

`exports` remains one topic with its 30-second status throttle; separating it is not necessary to implement this contract.
