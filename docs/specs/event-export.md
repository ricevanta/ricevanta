# Event export

The `ExportDestination` resource and one adapter per export destination: protocol, authentication, batching, acknowledgement, failure mapping, OCSF mapping and the Go client. The export log, cursors, retries, dead letters, alerting and the delivery guarantee these adapters implement are in `../design/events.md` section 4; the event format is `ocsf-profile.md`; the `export-destination` connector contract is `../design/extensions.md` section 6. Decisions: EV-04, EV-05 and EXT-05 in `../decisions.md`.

## 1. `ExportDestination`

A GitOps kind under `apiVersion: ricevanta.io/v1alpha1` (`policy-envelope.md` sections 1 and 8), also written through `/api/v1`; its required JSON Schema, `schemas/export/v1alpha1/export-destination.json`, is absent and blocks destination validation (`../analysis.md` section 3).

```yaml
apiVersion: ricevanta.io/v1alpha1
kind: ExportDestination
metadata:
  name: soc-splunk
spec:
  type: splunk_hec          # elasticsearch, opensearch, splunk_hec, syslog, otlp, loki, sentinel, kafka, s3, connector
  enabled: true
  endpoint: https://splunk.example.com:8088
  credentialRef: soc-splunk-token       # a server-held secret (design/backend.md section 6); values never appear in YAML
  tls: { caRef: soc-ca, pinSha256: null, clientCertificateRef: null, serverName: splunk.example.com }
  filter:
    classes: [detection_finding, data_security_finding, authentication]   # empty selects every class
    minSeverity: informational
    deviceGroups: []                    # empty selects every group
    origins: [agent, server, extension]
    condition: ""                       # optional ricevanta-cel-1 expression over the event
  projection: { drop: [unmapped] }
  repeats: first_and_summary            # or: all
  audit: false                          # also receive audit records and checkpoints
  archive: false                        # s3 only: archive partitions before retention drops them
  batch: { maxEvents: 1000, maxBytes: 1048576, maxDelay: 5s }
  inflight: 2
  splunk_hec: { mode: event, sourcetype: "ricevanta:ocsf", index: security, requireAck: true }
```

Rules:

- The projection cannot remove `metadata.uid`, `metadata.version`, `class_uid` or `time`, which every adapter needs for identity and time.
- `repeats: first_and_summary` (default) exports the first occurrence and the agent's summary of a repeated finding and suppresses findings the server marked `repeat_of` (`../design/events.md` section 3.3); `all` exports every stored finding.
- Creating, enabling, disabling and deleting a destination, changing its filter or projection in either direction, changing its endpoint or credentials, and any change to a destination with `audit: true` or `archive: true` are protected actions (BE-02). A new, enabled or widened destination, or one whose projection drops fewer fields, streams events to a host the administrator chooses, and a deleted, disabled, narrowed or more heavily projected one silences the SIEM, so a compromised administrator needs a second account for either.
- Validation refuses unknown class names, a condition outside the CEL profile or over its cost limit, and a type block that does not match `type`.

## 2. Common adapter rules

- Body: the enriched OCSF 1.9.0 JSON after projection, field names unchanged. No adapter maps OCSF to another schema; where a destination needs extra fields (`@timestamp`, `TimeGenerated`, HEC metadata), the adapter adds them beside the OCSF object.
- Identity: `metadata.uid` is in every body and is the duplicate key each destination's search or ingest can use.
- Batch: an adapter flushes at `maxEvents`, `maxBytes` or `maxDelay`, always at a whole event, and never across export-log objects of different classes for S3.
- Oversize: an event above the destination's per-event limit is re-projected without `unmapped`, `script.script_content` and `raw_data`; if it is still too large it is dead-lettered with reason `oversize`.
- Isolation of a rejected event: when a destination rejects a batch as a whole without naming the event, the adapter halves the batch until the rejection names one event, which is dead-lettered.
- Transport security: TLS 1.2 or later, TLS 1.3 preferred, server verified against `caRef` or a pinned SHA-256 certificate fingerprint, an optional client certificate; plain text is refused except for syslog over UDP, which the console labels unencrypted and lossy.

| Outcome | Kind (`../design/events.md` section 4.2) |
|---|---|
| Network error, timeout, `429`, `502`, `503`, `504`, other `5xx` | Retryable, honouring `Retry-After` |
| An item or request rejected as invalid (`400`, mapping or size error) | Permanent for the event, dead-lettered after isolation |
| `401`, `403`, missing index, table, stream, topic or bucket | Permanent for the destination: pause and alert |

## 3. Elasticsearch

- Target: data stream `logs-ricevanta.ocsf-<namespace>` (default namespace `default`). `deploy/elastic/` ships an index template and component templates generated from the compiled OCSF export (`ocsf-profile.md` section 6): `time` as `date` with `epoch_millis`, `metadata.uid` as `keyword`, and `unmapped` as `flattened`.
- Request: `POST /<data stream>/_bulk`, NDJSON pairs `{"create":{"_id":"<metadata.uid>"}}` and the OCSF document with `@timestamp` added in ISO 8601 from `time`, since every data stream document needs `@timestamp` and data streams accept only `create`. Defaults: 1,000 events or 5 MB, well under the 100 MB `http.max_content_length` default.
- Acknowledgement: per-item `status` in the response; `201` is delivered, `409` (a document with that `_id` already exists) is delivered, an item `429` is retried alone, any other item `4xx` is dead-lettered; a whole-request `429` or `5xx` is retried with randomized exponential backoff, as Elastic advises.
- Duplicates: `_id` is unique within one backing index; whether a retry after a rollover can create a second document is unconfirmed (verify), so searches collapse on `metadata.uid`.
- Authentication: API key (`Authorization: ApiKey`), basic, or a client certificate through the PKI realm. The API key needs `create_doc` and `auto_configure` on the data stream (verify the privilege names).
- Client: `go-elasticsearch` (Apache-2.0), low-level `Bulk` calls with bodies built by the adapter, not `esutil.BulkIndexer`, because the cursor needs each batch's per-item outcome.
- Schema: OCSF unchanged; Elastic's Amazon Security Lake integration reads OCSF 1.1.0 and maps it to ECS (verify), which operators can use as reference but which Ricevanta does not apply.

## 4. OpenSearch

As section 3, with these differences: data stream `ricevanta-ocsf-<namespace>` from an index template with `data_stream` enabled in `deploy/opensearch/`; an existing `_id` returns `version_conflict_engine_exception` for that item, which is delivered; item `429` handling is unconfirmed in OpenSearch's pages and follows section 2 (verify). Authentication: basic, a client certificate through the security plugin (`clientauth_mode`), or AWS Signature Version 4 for Amazon OpenSearch Service and Serverless through the `opensearch-go` signer with `aws-sdk-go-v2` credentials. Client: `opensearch-go` (Apache-2.0), low-level bulk calls.

## 5. Splunk HTTP Event Collector

- Endpoint `event` (default): `POST /services/collector/event` with concatenated JSON objects, one per event: `time` (epoch seconds with millisecond fraction from `time`), `host` (`device.hostname`, or the server name for server events), `source` `ricevanta`, `sourcetype` (default `ricevanta:ocsf`), `index` (optional), `fields` (flat: `class_uid`, `severity_id`, `device_uid`) and `event` (the OCSF object).
- Endpoint `raw` (option): `POST /services/collector/raw?sourcetype=...&index=...` with the NDJSON lines; `host` is the server, and event time comes from the operator's sourcetype settings (`deploy/splunk/props.conf` with `TIME_PREFIX` and `TIME_FORMAT` for `"time":` in epoch milliseconds).
- Batch: 1,000 events or 1 MB; Splunk's `max_content_length` is far larger.
- Authentication: `Authorization: Splunk <token>`; default port 8088.
- Acknowledgement (`requireAck: true`, default): the token has indexer acknowledgement enabled; each worker generation uses one GUID channel in `X-Splunk-Request-Channel`; a request returns `{"ackID": n}`; the adapter polls `POST /services/collector/ack` with `{"acks": [...]}` every 10 s and acknowledges a batch when its `ackID` reads `true`, which Splunk defines as replicated at the configured replication factor, not as surviving parsing. An `ackID` not `true` after 5 minutes is resent on the same channel, as Splunk recommends. Splunk deletes an `ackID`'s status once read as `true`. Splunk Cloud supports indexer acknowledgement only for Amazon Data Firehose (verify); with `requireAck: false`, a `200` means HEC received the batch and the console labels the destination "received only".
- Failure mapping: codes 9, 18, 23 (`503`), 26, 27 (`429`) and 8 (`500`) are retryable; code 6 (`400` invalid data format) isolates and dead-letters the event; codes 1, 2, 3, 4 and 21 (token missing, invalid or disabled) pause the destination.
- Duplicates: HEC does not deduplicate; searches use `dedup metadata.uid`.
- Schema: OCSF unchanged; Splunk's OCSF-CIM add-on maps OCSF events to the Common Information Model at search time (verify that it applies to the `ricevanta:ocsf` sourcetype).
- Client: the Go standard library `net/http`; no Splunk library.

## 6. Syslog

Message (RFC 5424), one per event:

| Field | Value |
|---|---|
| PRI | `facility × 8 + severity`; facility configurable, default 16 (`local0`) |
| Severity | From OCSF `severity_id`: Fatal 6 to 1 (alert), Critical 5 to 2, High 4 to 3, Medium 3 to 4, Low 2 to 5, Informational 1 to 6, Unknown 0 and Other 99 to 6 |
| VERSION, TIMESTAMP | `1`; RFC 3339 UTC with milliseconds from `time` |
| HOSTNAME | `device.hostname`, or the server's name for server events, with characters outside `PRINTUSASCII` replaced and cut to 255 |
| APP-NAME, PROCID | `ricevanta`; `-` |
| MSGID | The class name without the extension prefix, at most 32 characters (every profile class name fits) |
| STRUCTURED-DATA | `-` (NILVALUE); the OCSF event in MSG carries its own uid, class, severity and device |
| MSG | UTF-8 byte order mark, then the OCSF JSON on one line |

- TLS (default): RFC 5425 on port 6514 with octet-counting framing (`MSG-LEN SP SYSLOG-MSG`); TLS 1.2 is mandatory and TLS 1.3 is preferred when offered (RFC 9662). The server is verified by certification path or by end-entity certificate fingerprint, the two methods RFC 5425 requires; a client certificate is recommended, since RFC 5425 calls one-sided authentication not recommended. Non-transparent framing (RFC 6587) is not offered, because a trailer character inside a message splits it.
- Size: RFC 5425 receivers must accept 2,048 octets and should accept 8,192, and many OCSF events are larger, so `maxMessageBytes` defaults to 65,536 and the operator sets it to the receiver's configured maximum.
- Acknowledgement: none exists; RFC 5425 section 6.3 states the sender cannot always know which messages were delivered. The adapter treats a batch as delivered after its bytes are written and flushed; on any write or connection error it reconnects and resends the whole in-flight batch, accepting duplicates. Messages the kernel accepted before an undetected connection loss can still be lost, which `../design/events.md` section 1 lists.
- UDP (option): RFC 5426 on port 514, one message per datagram, `maxMessageBytes` default 1,180 (the IPv6 size every receiver must accept), no fragmentation, no retransmission; the destination is labelled lossy.
- Client: in-project formatter on `crypto/tls` and `net`; Go's `log/syslog` is frozen, absent on Windows and not documented as RFC 5424 or RFC 5425.

## 7. OpenTelemetry Collector

- Transport: OTLP/gRPC `LogsService/Export` (default port 4317) or OTLP/HTTP `POST /v1/logs` (default port 4318) with binary protobuf; gzip on both.
- Batch: 1,000 records or 4 MB, below the collector's default gRPC receive limit (verify).
- Mapping, one `LogRecord` per event:

| OTLP | Value |
|---|---|
| Resource | One per device (or the server) in the batch: `service.name` `ricevanta-agent` or `ricevanta-server`, `service.version` from `metadata.product.version`, `host.name` from `device.hostname`, `os.type` `darwin`, `windows` or `linux`, `ricevanta.device.uid` |
| InstrumentationScope | Name `io.ricevanta.events`, version `1.9.0` (the OCSF version) |
| Timestamp, ObservedTimestamp | `time` and `metadata.logged_time`, converted to nanoseconds |
| SeverityNumber | Informational 9, Low 10, Medium 13, High 17, Critical 21, Fatal 24, Unknown and Other 0 |
| SeverityText | OCSF `severity` |
| EventName | `ocsf.` plus the class name as in the profile (`ocsf.process_activity`, `ocsf.ricevanta/lineage_activity`) |
| Body | The OCSF event as an `AnyValue` map: objects to `kvlist_value`, arrays to `array_value`, integers to `int_value`, other numbers to `double_value`; option `body: json_string` |
| Attributes | `log.record.uid` (`metadata.uid`, the semantic-conventions key for deduplication), `ocsf.class_uid`, `ocsf.category_uid`, `ocsf.type_uid`, `ocsf.severity_id` |

- Acknowledgement: a successful export. A `partial_success` with `rejected_log_records` above zero does not name the records: the adapter dead-letters the batch's uids as one partial entry with `error_message` and does not retry it (verify that OTLP forbids retrying a partial success).
- Failure mapping: gRPC `CANCELLED`, `DEADLINE_EXCEEDED`, `ABORTED`, `OUT_OF_RANGE`, `UNAVAILABLE` and `DATA_LOSS`, and `RESOURCE_EXHAUSTED` only with `RetryInfo`, are retryable; HTTP `429`, `502`, `503` and `504` are retryable with `Retry-After`; others follow section 2.
- Authentication: mutual TLS, a bearer token, or configured headers.
- Client: `go.opentelemetry.io/proto/otlp` (Apache-2.0) with `google.golang.org/grpc` (Apache-2.0) and `google.golang.org/protobuf` (BSD-3-Clause); the OpenTelemetry SDK's log exporter is not used, because it buffers and retries internally while the cursor needs each request's outcome.

## 8. Grafana Loki

- Request: `POST /loki/api/v1/push`, `Content-Type: application/json`, `Content-Encoding: gzip`, streams of `[timestamp_ns, line, structured_metadata]`.
- Labels, fixed and low-cardinality: `service_name="ricevanta"`, `source` (`agent` or `server`), `ocsf_class` (the class name) and `severity` (the caption), at most about 40 × 7 × 2 streams, far below Grafana's 100,000 active streams per tenant; an operator may add `ocsf_category` or `os`, never a device, user, host or uid.
- Structured metadata: `event_uid`, `device_uid`, `device_hostname`, `user_uid`, `correlation_uid`, which Grafana recommends for high-cardinality values.
- Line and time: the OCSF JSON; the entry timestamp is `metadata.logged_time` by default (option: `time`), because Loki rejects entries older than `reject_old_samples_max_age` (default one week), which an offline backlog would exceed; the event time stays in the line.
- Batch and limits: 1,000 lines or 1 MB; `max_line_size` defaults to 256 KB, so larger events follow section 2's oversize rule.
- Acknowledgement and duplicates: `204` acknowledges. A resent batch carries the same receipt timestamps and lines, and Loki removes lines with an identical stream, nanosecond timestamp and content from query results (verify: stated in a maintainer's issue, not the documentation).
- Failure mapping: `429` retryable; `400` (line too long, too old, invalid labels) isolates per stream and dead-letters; `413` halves the batch; `401` pauses.
- Authentication: basic or bearer, with `X-Scope-OrgID` for multi-tenant Loki.
- Client: `net/http`, `encoding/json`, `compress/gzip`. Loki's own Go packages are not imported: the repository is AGPL-3.0 and only the `clients/` directory carries an Apache-2.0 license file (verify per file).

## 9. Microsoft Sentinel

- API: Azure Monitor Logs Ingestion API, `POST {endpoint}/dataCollectionRules/{DCR immutable id}/streams/Custom-RicevantaOCSF?api-version=2023-01-01` with a JSON array, gzip-encoded. The endpoint is the data collection rule's own logs ingestion endpoint (`kind: Direct`); a data collection endpoint is needed only for a workspace behind Private Link.
- Table: the custom table `RicevantaOCSF_CL` with `TimeGenerated` (datetime, from `time`, sent explicitly), `EventUid`, `ClassUid`, `ClassName`, `CategoryUid`, `ActivityId`, `TypeUid`, `SeverityId`, `DeviceUid`, `DeviceHostname`, `CorrelationUid`, `OcsfVersion` and `Event` (dynamic, the OCSF object); the rule's `transformKql` is `source`. `deploy/sentinel/` ships the table, rule and role assignment as an ARM template. A custom table is used because Microsoft Learn documents no OCSF table for Sentinel (searches found none, verify), and the ASIM tables the API accepts (`ASimProcessEventLogs`, `ASimFileEventLogs`, `ASimNetworkSessionLogs` and others) cover a subset of the profile's classes with a lossy column mapping.
- Limits: 1 MB per call, which Microsoft states for compressed and uncompressed data, so batches stop at 1 MB before compression; 2 GB and 12,000 requests per minute per rule.
- Authentication: a Microsoft Entra application with client credentials, a certificate preferred over a secret, token scope `https://monitor.azure.com//.default` (`monitor.azure.us` and `monitor.azure.cn` for sovereign clouds), and the Monitoring Metrics Publisher role on the rule. Role propagation can take 30 minutes; a `403` during setup shows as a failed destination with that reason.
- Acknowledgement: `204` means accepted for ingestion; there is no indexed confirmation (verify). Duplicates: Log Analytics does not deduplicate; queries use `summarize arg_max(TimeGenerated, *) by EventUid`.
- Failure mapping: `429` with `Retry-After` retryable; `413` halves the batch; `400` isolates and dead-letters; `401` and `403` pause; `5xx` retryable.
- Client: `azure-sdk-for-go` `sdk/monitor/ingestion/azlogs` with `sdk/azidentity` (MIT); whether `azlogs` compresses the body itself decides who gzips (verify).

## 10. S3-compatible storage

The adapter persists an immutable export plan before sending any object. The plan binds its uid, destination uid and approved configuration revision and hash, endpoint, bucket and prefix, secret-reference revision, export-log range and source-object digests, filter, projection, repeat policy, format and compression parameters, and a `replay_uid`. A configuration change invalidates unsent work under the old revision; the worker pauses that plan until the current authorization explicitly permits its frozen revision, or cancels it and creates a new plan. It never substitutes the new configuration into an old plan.

- Namespace: `<prefix>/destination=<uid>/revision=<n>/replay=<uid>/plan=<uid>/`. A retry reuses the stored plan and namespace. Every intentional replay, including a cursor rewind with a changed projection, gets a new `replay_uid` and new plan. Destination or configuration names alone never identify output bytes.
- Layout: under that namespace, `ocsf/v1.9.0/class=<class>/dt=<YYYY-MM-DD>/hr=<HH>/part-<n>.ndjson.zst`, partitioned by event `time` in UTC. `/` in an extension class name becomes `.`. The Hive-style `key=value` paths suit readers that support this layout; qualification must verify each configured reader.
- Preparation: take whole export-log objects until 64 MiB or 5 minutes, apply the frozen filter and projection, and split by class, day and hour. Stage the exact compressed bytes as private, durable blob objects. Persist ordered output keys, staging references, SHA-256, size, record count, class, partition, time and event-uid bounds, and the exact canonical manifest bytes and digest before any external upload. Temporary files are not recovery state. A retry loads these bytes, checks their digest and never reprojects or recompresses with the current binary. Retain source and staging objects until the plan completes or cancellation records its partial deliveries.
- Writing: require a qualified endpoint with create-only `PutObject` using `If-None-Match: *` and authenticated read-back verification. Send the plan's SHA-256 checksum. A successful write has to prove the exact planned bytes through a verified full-object checksum or a complete `GetObject` whose body hashes to the planned SHA-256 and size; multipart or encrypted ETags are not content SHA-256 values. Record the returned version id when available and bind verification to that version.
- Conflict: `412` means only that a current object exists. Read and verify the object at the planned key against the stored size and SHA-256, using its exact version when available. Only an exact match counts as delivered. Missing read permission, an unknown checksum, a changed object or mismatched bytes pauses the plan and alerts; never overwrite the conflict, dead-letter it as one bad event or advance the cursor. Retry a `409` through the same conditional-write and verification protocol. Registration tests conditional writes and conflicting-byte read-back; an endpoint that cannot prove the contract is not admitted.
- Manifest: publish `ocsf/v1.9.0/_manifest.json` only after every planned data object has a verification receipt. The manifest binds destination uid, configuration revision and hash, replay and plan uids, source range and digests, and every output key, SHA-256, size, count and bounds. Its conditional write and any `412` use the same exact-byte check. Advance the plan's cursor only after manifest verification; a crash resumes from stored bytes and receipts.
- Archive (`archive: true`, `../design/events.md` section 5): use the same plan and verification protocol, under `archive/<store>/class=<class>/dt=<day>/`, with a frozen partition identity and projection revision. `<store>` is `events`, `lineage` or `audit`; `<class>` is the table name for the last two. The filter does not apply. Retention drops the source only after verifying the exact planned manifest and every object, and after the legal-hold fence permits the drop.
- Audit anchor (`audit: true`): records under `<prefix>/audit/records/` and checkpoints under `<prefix>/audit/checkpoints/<sequence>.dsse.json`, under the independent journal contract of `../design/backend.md` section 6.1. An anchor bucket uses Object Lock in compliance mode with a default retention at least the audit retention. Store and verify exact version references; a newer object or delete marker cannot replace the trusted journal head. The export plan does not resolve that journal's implementation blocker.
- Authentication: access key and secret, or the environment's workload identity as `minio-go` supports it (verify per provider); optional SSE-S3 or SSE-KMS. Credentials need read-back permission as well as conditional write permission.
- Failure mapping: `5xx` and `SlowDown` retryable; `AccessDenied`, `NoSuchBucket` and integrity conflicts pause.
- Client: `minio-go` (Apache-2.0). AWS documents conditional conflicts and checksum verification; S3-compatible endpoints must pass the registration and recovery fixtures rather than inherit an AWS support claim.

## 11. Kafka

- Record: one per event; value the OCSF JSON; key `device.uid` by default, which keeps one device's events in order within a partition, or `metadata.uid` as an option for even spread; headers `ocsf.uid`, `ocsf.class_uid`, `ocsf.version` and `content-type: application/json`; record timestamp `time`.
- Topic: `ricevanta.ocsf` by default, or a template over category or class (`ricevanta.ocsf.{category}`); topics are created by the operator, never auto-created.
- Producer: `franz-go` with the idempotent producer (its default) and `RequiredAcks(AllISRAcks())` set explicitly, since its documentation and source disagree on the default (verify); zstd compression by default, with lz4, snappy and gzip as options.
- Acknowledgement: a batch is acknowledged when every record's produce result succeeds; a record that still fails after the client's retries sends the batch back to the exporter's retry, and records already written appear twice, since producer idempotence covers one producer session only. `MESSAGE_TOO_LARGE` (the broker's `message.max.bytes`) follows section 2's oversize rule.
- Authentication: TLS with a client certificate, SASL SCRAM-SHA-256 or SCRAM-SHA-512, SASL PLAIN over TLS, or OAUTHBEARER (verify each in `franz-go`'s `sasl` packages).
- Transactions are not used: exactly-once needs every consumer to read `read_committed`, and `metadata.uid` already lets consumers deduplicate.
- Client: `franz-go` (BSD-3-Clause, pure Go). `sarama` (MIT) was not chosen: idempotence is off by default and its default acknowledgement is the leader only.

## 12. `export-destination` connector

Anything else is a `connector` destination calling a registered service connector under the contract of `../design/extensions.md` section 6.1, authenticated as in its section 6.2. The request is the filtered and projected batch as zstd NDJSON with batch id `<destination>-<first>-<last>`, identical across retries; the connector's acknowledgement advances the cursor; a contract-level rejection of one event dead-letters it, and a connector whose health probe fails (section 6.3 there) is a failed destination. The request timeout defaults to 30 s, and retries follow section 2. A connector receives only what its destination's filter and projection leave, and holds no callback token.

## 13. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: every destination receives OCSF unchanged, with `metadata.uid` as its duplicate key; each adapter maps its protocol onto the same three failure kinds, so the exporter's cursor, retry and dead-letter logic is shared; destinations with real acknowledgement (bulk item status, HEC indexer acknowledgement, Kafka `acks=all`, OTLP export results, S3 writes) give end-to-end at-least-once.

Trade-offs: no schema translation means a SIEM's own normalization (ECS, CIM, ASIM) runs at search time or in its own pipeline; Loki's receipt-time timestamps trade event-time ordering for acceptance of offline backlogs; indexer acknowledgement adds a polling loop and up to 10 s of acknowledgement latency.

Dependencies: `go-elasticsearch`, `opensearch-go`, `aws-sdk-go-v2` for Signature Version 4, `go.opentelemetry.io/proto/otlp`, `grpc-go`, `protobuf-go`, `azlogs` and `azidentity`, `franz-go`, `minio-go`; the standard library for HEC, syslog and Loki.

Limits: syslog has no acknowledgement and UDP is lossy; Splunk Cloud's HEC acknowledgement restriction (verify); Sentinel and Loki confirm acceptance, not indexing; Elasticsearch and OpenSearch `_id` deduplication may not span a data stream rollover (verify); S3 delivery requires a qualified conditional-write and exact-byte read-back contract; the immutable plan schema and recovery fixtures must exist before implementation.

Alternatives considered: a schema translation per destination (rejected: one mapping per SIEM to keep in step with every OCSF minor release; the SIEMs ship their own normalization); `esutil.BulkIndexer` and the OpenTelemetry SDK exporters (rejected: they own retries and hide the per-batch outcome the cursor needs); RELP or RFC 3195 for acknowledged syslog (not offered: neither is in the blueprint's target list, and an acknowledged path exists through every other destination); `sarama` and `confluent-kafka-go` (rejected: idempotence off by default; cgo and `librdkafka`); Loki's Go client packages (rejected: AGPL-3.0 repository); ASIM tables as the Sentinel target (rejected: a subset of classes and a lossy mapping).

## 14. Sources

- Elasticsearch: [bulk API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-bulk), [create API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-create), [data streams](https://www.elastic.co/docs/manage-data/data-store/data-streams), [indexing speed and 429](https://www.elastic.co/guide/en/elasticsearch/reference/current/tune-for-indexing-speed.html), [networking settings](https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/networking-settings), [authentication](https://www.elastic.co/docs/api/doc/elasticsearch/authentication), [PKI realm](https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/pki), [Amazon Security Lake integration](https://www.elastic.co/docs/reference/integrations/amazon_security_lake), [go-elasticsearch](https://github.com/elastic/go-elasticsearch).
- OpenSearch: [bulk API](https://docs.opensearch.org/latest/api-reference/document-apis/bulk/), [data streams](https://docs.opensearch.org/latest/im-plugin/data-streams/), [network settings](https://docs.opensearch.org/latest/install-and-configure/configuring-opensearch/network-settings/), [client certificate authentication](https://docs.opensearch.org/latest/security/authentication-backends/client-auth/), [opensearch-go signer](https://github.com/opensearch-project/opensearch-go/blob/main/signer/doc.go).
- Splunk: [HEC endpoints](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.6/get-data-with-http-event-collector/http-event-collector-rest-api-endpoints), [event format](https://help.splunk.com/en/splunk-cloud-platform/get-started/get-data-in/10.6/get-data-with-http-event-collector/format-events-for-http-event-collector), [indexer acknowledgment](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.4/get-data-with-http-event-collector/about-http-event-collector-indexer-acknowledgment), [HEC error codes](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.4/get-data-with-http-event-collector/troubleshoot-http-event-collector), [OCSF-CIM add-on](https://help.splunk.com/en/splunk-cloud-platform/common-information-model/8.5/introduction/overview-of-the-ocsf-cim-add-on).
- Syslog: [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424), [RFC 5425](https://www.rfc-editor.org/rfc/rfc5425), [RFC 9662](https://www.rfc-editor.org/rfc/rfc9662), [RFC 6587](https://www.rfc-editor.org/rfc/rfc6587), [RFC 5426](https://www.rfc-editor.org/rfc/rfc5426), [RFC 3195](https://www.rfc-editor.org/rfc/rfc3195), [Go log/syslog](https://pkg.go.dev/log/syslog).
- OpenTelemetry: [logs data model](https://opentelemetry.io/docs/specs/otel/logs/data-model/), [OTLP](https://opentelemetry.io/docs/specs/otlp/), [service](https://opentelemetry.io/docs/specs/semconv/resource/service/), [host](https://opentelemetry.io/docs/specs/semconv/resource/host/) and [OS](https://opentelemetry.io/docs/specs/semconv/resource/os/) resource conventions, [log attributes](https://opentelemetry.io/docs/specs/semconv/registry/attributes/log/), [opentelemetry-proto-go](https://github.com/open-telemetry/opentelemetry-proto-go), [grpc-go](https://github.com/grpc/grpc-go), [protobuf-go](https://github.com/protocolbuffers/protobuf-go).
- Loki: [HTTP API](https://grafana.com/docs/loki/latest/reference/loki-http-api/), [label best practices](https://grafana.com/docs/loki/latest/get-started/labels/bp-labels/), [configuration](https://grafana.com/docs/loki/latest/configure/), [rate limits and validation](https://grafana.com/docs/loki/latest/operations/request-validation-rate-limits/), [multi-tenancy](https://grafana.com/docs/loki/latest/operations/multi-tenancy/), [duplicate lines, issue 18760](https://github.com/grafana/loki/issues/18760), [license](https://github.com/grafana/loki/blob/main/LICENSE).
- Microsoft: [Logs Ingestion API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview), [service limits](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/service-limits#logs-ingestion-api), [portal tutorial](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-portal), [code tutorial](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-code), [data collection endpoints](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-endpoint-overview), [transformations](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-transformations-create), [ASIM ingest-time normalization](https://learn.microsoft.com/en-us/azure/sentinel/normalization-ingest-time), [azlogs](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/monitor/ingestion/azlogs), [azure-sdk-for-go license](https://github.com/Azure/azure-sdk-for-go/blob/main/LICENSE.txt).
- Kafka: [franz-go](https://github.com/twmb/franz-go), [franz-go config.go](https://github.com/twmb/franz-go/blob/master/pkg/kgo/config.go), [sarama](https://github.com/IBM/sarama).
- S3: [AWS conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html), [object integrity](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html), [GetObject version and checksum fields](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html), [MinIO S3 compatibility](https://docs.min.io/aistor/developers/s3-api-compatibility/), [minio-go](https://github.com/minio/minio-go).
