# Change stream

`GET /api/v1/changes` (`streamChanges`) is a Server-Sent Events stream that tells the console which topics changed, as opaque per-topic tokens, and never sends row data. Views then refetch through ordinary authorized operations (BE-10). This specification fixes the topics, the watermark store, the per-replica hub, the framing, the authorization lifecycle of a stream and the console reader.

Authorities: BE-04, BE-10, BE-17 and BE-18 in [decisions](../decisions.md), [console design](../design/console.md) section 4, [backend design](../design/backend.md) sections 1 and 3, [API foundation](api-foundation.md), [identity sessions](identity-sessions.md) and [the implementation plan](../plans/change-stream.md). The operation and event schemas are in [`schemas/openapi/v1/openapi.yaml`](../../schemas/openapi/v1/openapi.yaml); framing and subscription vectors are in `fixtures/sse.json`.

## 1. Boundary and dependencies

Included: topic grammar and permissions, the `platform.change_watermarks` table and its bump interface, the hub in every `api` replica, the stream handler, and the console reader with polling fallback. Excluded: the domain writes that bump topics, which each domain slice adds when it implements the change (a topic with no writer simply never advances), and row data of any kind.

The handler runs inside the BE-15 `api` listener and its per-handler deadlines. The store needs the PostgreSQL platform slice; until then the hub runs against an in-memory watermark source in tests. A stream is an authenticated stream under BE-12: once the authority read lease exists, the hub ends every stream when its replica's lease expires (backend design section 6.1). That integration waits for BE-12; nothing else in this slice does.

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

Device-group topics have one row per device group plus one `~ungrouped` row. A change bumps the row of every group the entity belongs to before and after the change, so moving a device between groups advances both. An operator with scope `all` sees every row; an operator scoped to groups sees exactly those rows. Entity topics are authorized at subscription against the entity's current groups through the owning module's interface, and an entity outside the caller's scope is `not_found`, the same answer as an unknown uid, so the stream reveals no existence (console design section 4). Validation order is grammar and count (`validation_failed`), then permissions in request order (`permission_denied`), then entity scope (`not_found`); `sse.json` fixes the decisions.

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

`platform/changes.Bump(ctx, tx, keys)` runs `INSERT … ON CONFLICT DO UPDATE SET counter = counter + 1, bumped_xid = pg_current_xact_id()` once per key at the end of the caller's transaction, so the row lock is held only until that commit and the counter of each row only increases. Only the `api` and `jobs` roles have the function's grant; the agent-facing roles never bump, because their inserts are untrusted until `jobs` processes them (BE-03). A module bumps each key at most once per transaction. Entity rows of deleted entities are removed by the owning module's retention.

## 4. Hub

Each `api` replica runs one hub. Every 2 seconds it runs one query:

```sql
SELECT topic, scope_key, counter, pg_snapshot_xmin(pg_current_snapshot()) AS horizon
FROM platform.change_watermarks WHERE bumped_xid >= $1
```

`$1` is the horizon returned by the previous tick. PostgreSQL defines a snapshot's `xmin` as the "lowest transaction ID that was still active", with every lower ID either committed and visible or rolled back, and `xid8` values that "do not wrap around during the life of an installation" ([system information functions](https://www.postgresql.org/docs/17/functions-info.html), table 9.83). A transaction that commits after one tick therefore has an ID at or above that tick's horizon and appears in the next tick's result, which may also repeat rows already seen; the hub compares counters and ignores repeats. A long-running transaction holds the horizon back and makes the result larger, never incomplete. The first tick after start or after a database reconnection reads every aggregate row (horizon zero). Entity rows are kept in memory only while some stream subscribes to them; a new subscription reads its rows once. The database cost is one query per replica per tick, independent of the number of operators.

A token is the first 16 bytes, as 22 base64url characters, of SHA-256 over the hub instance id (128 random bits drawn at process start), the hub generation (incremented at every database reconnection), the topic, and the sorted `(scope_key, counter)` pairs visible to the stream. Tokens are compared only for equality. They differ across replicas, restarts and database reconnections, which costs one refetch and never hides a change; a database restored from backup or failed over to a standby with fewer commits forces a reconnection and so a new generation, so a lower counter cannot reproduce a token the client already holds.

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

Each write sets a write deadline 10 seconds ahead through `http.ResponseController`, matching the BE-15 rule that handlers bound their own writes; a client that stops reading loses its stream. A stream lives at most one hour, then receives `reconnect` with `lifetime`. `http.Server.Shutdown` waits for active requests, so the runtime's stop request ends every stream with `reconnect` and `shutdown` through a function registered with `Server.RegisterOnShutdown`, which Go documents for starting protocol-specific shutdown of long-lived connections ([net/http](https://pkg.go.dev/net/http#Server.RegisterOnShutdown)). After three consecutive failed ticks the hub ends every stream with `reconnect` and `database`, and new streams answer `503 unavailable` until a tick succeeds, because sessions can no longer be checked.

## 6. Authorization during a stream

A stream records its credential (session uid or token uid), user, effective permissions and scope at open. A tick that shows a change of the user's `identity.sessions` row makes the hub recheck that stream's credential: revoked, expired or disabled ends the stream with `session` `ended`; a re-authentication changes nothing. A change of `authz.grants`, or of an entity row whose entity may have left the stream's scope, makes the hub recompute that stream's permissions and scope; any difference ends the stream with `session` `changed`, and the client refetches `getSession` and reconnects with the topics it may still read. Idle and absolute expiry are timers per stream; when one fires, the hub rereads the session, because operator activity on other requests may have extended the idle window, and ends the stream if it expired. The stream itself never extends the session (identity sessions section 3). Revocation therefore ends a stream within one tick plus the recheck, at most about 3 seconds.

## 7. Console reader

The console reads the stream with `fetch` and a streaming body parsed by the WHATWG event-stream algorithm, not with `EventSource`. `EventSource` cannot add the `X-Ricevanta-Background` marker, and when a response "status is not 200, or … Content-Type is not text/event-stream", the specification says "fail the connection" (section 9.2.2) without exposing the status, so the console could not tell an expired session from a forbidden topic. The parser handles `CRLF`, `CR` and `LF` across chunk boundaries and discards an unterminated final event (`sse.json`).

- A snapshot marks every visible view stale once; `useResource` refetches each, which also covers changes made while the stream was connecting.
- A `change` for a topic refetches the visible views on that topic, at most once every 5 seconds per view.
- `session` `changed` refetches `getSession` and reconnects with the topics of the visible views; `ended` and a `401` go to the login page with the current route as return path; `403` and `404` drop the offending topic and reconnect.
- Topics follow the visible views; a route change reconnects with the new set after a 1-second debounce.
- Reconnection waits the `retry` delay with ±20 % jitter. After three failed attempts the console polls each visible view every 30 seconds and shows that live updates are paused; it keeps trying the stream every 60 seconds. A tab hidden for 5 minutes closes its stream and refetches when shown.
- Over HTTP/2 a stream is one of up to 100 concurrent streams on one connection; over HTTP/1.1 a browser opens at most six connections per host (MDN, verify), so the console opens one stream per tab.

## 8. Resource bounds

At most 16 topics per stream, 4 streams per session, 8 per user and 1,000 per replica; beyond them the answer is `429 rate_limited`. Per stream the hub keeps the credential, the subscribed topics and their last tokens. Per tick the hub runs one query, and per change it recomputes tokens only for streams subscribed to that topic. Entity-scope rechecks run only for streams subscribed to a changed entity.

## 9. Security trace

Path: domain transaction → `Bump` in the same transaction → hub tick → token digest per stream → frame → console refetch through authorized operations.

| Attacker | What the attacker gets |
|---|---|
| Stolen enrollment token | Nothing; it is not a session or API credential |
| Compromised agent host | Agent-facing roles cannot bump watermarks, so a flood of agent uploads advances topics only as fast as `jobs` processes them; the host gets no stream |
| Compromised console session | The topics and change timing the operator may read, never row data; refetches stay under per-request authorization; revocation ends the stream within about 3 seconds |
| Rogue extension publisher | Modules receive change notices only through the bridge's safe catalogue (`approval.pending`), never the stream or its credential (EXT-04) |
| Network position between agent and server | Not this channel; the stream rides the console's TLS connection |
| Database writer without signing keys | Can bump or delete watermark rows, causing extra refetches or a missed refresh until the next snapshot or the 30-second polling of a paused view; cannot inject data, because the stream carries none |
| Server restored from backup | Lower counters after restore change tokens through the new hub generation and force refetches; no change is hidden |

The `approvals` organization row reveals to holders of `authz.approvals.read` when approval activity happens, which they can already list; per-user rows reveal nothing beyond the user's own and decidable requests.

## 10. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: one query per replica per tick regardless of operators; no row data crosses the stream, so authorization stays in the ordinary operations; snapshot-on-connect with equality-only tokens never misses a change across restarts, failovers or restores; agent-facing roles cannot drive the stream.

Trade-offs: every reconnection refetches the visible views; a 2-second tick plus a 5-second view throttle bounds freshness at about 7 seconds; topic rows add one row update per changed key to domain transactions; the `fetch` reader is console code that `EventSource` would otherwise provide.

Dependencies: PostgreSQL 17 `xid8` functions and the PostgreSQL platform slice; BE-15 for the listener and shutdown hook; BE-12 for the read-lease integration; Go standard library; no console dependency.

Limits: freshness is seconds, not milliseconds; aggregate tokens reveal change timing within the reader's own scope; a topic without a domain writer never advances, so views fall back on snapshot refetches until their domain slice lands.

Alternatives considered: WebSocket (rejected by BE-10: bidirectional and its own handshake checks); `LISTEN`/`NOTIFY` per change (rejected: backend design section 3 keeps `NOTIFY` off high-rate paths, and per-operator listeners would scale with operators); sequence-numbered changes with `Last-Event-ID` replay (rejected: sequences are assigned before commit and can become visible out of order, and replay after a restore would need retained history); `EventSource` (rejected above); row data in events (rejected: it would bypass per-request authorization and field omission).

## 11. Unresolved questions

- Should `exports` status changes have their own topic so that configuration views do not refetch on delivery progress? Until decided, the 30-second per-destination throttle bounds that cost.
