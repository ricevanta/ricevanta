# Ingest decode admission

Bound how many event batch bodies one `agent` replica decodes at once, charge each by the memory it can occupy, and tie the total to the process memory ceiling. This specifies the pure Go limiter package `server/internal/events/admission`, the additive frame split and the allocation-lean key walk of `server/internal/events/body`, and what the future `POST /agent/v1/events` handler must call. [The wire spec](event-upload-wire.md) owns the request and response contract; [the body spec](event-batch-body.md) owns decoding (EV-09); [events section 3.7](../design/events.md#37-backpressure) summarizes backpressure. Decision: [EV-11](../decisions.md#ev-11-ingest-decode-admission-budget).

## 1. Measurements

Every number here is a measurement of the `body` decoder, not an estimate. Host: Linux 6.18 x64, 4 vCPU Intel Xeon 2.10 GHz, 16 GiB, Go 1.27.1 (module toolchain), `github.com/klauspost/compress` v1.20.1. Method: a throwaway test generates one frame per shape with the pinned module's encoder (level 3, checksum, 4 MiB window or single segment), then runs one child process per case. The child loads only the compressed frame, forces `runtime.GC()`, reads its baseline, optionally calls `debug.SetMemoryLimit(baseline + N × Weight)` itself, runs `body.Decode` N times concurrently, samples `HeapInuse` and `/memory/classes/total:bytes − /memory/classes/heap/released:bytes` every millisecond, and reads `VmHWM` from `/proc/self/status` after return with the lines kept alive. `GOGC=100`. Retained live and peak `HeapInuse` are deltas over the child's baseline; `VmHWM` is the child's absolute peak resident size.

Shapes: `flat` is `"kN":0` members with distinct keys; `nested` is `"kN":{"a":0}`; `dense` is 3-byte keys, 131,064 members per 1 MiB line; `densenested` is 3-byte keys holding `{"a":0}`; `arrayobjs` is one array of `{"":0}`, 149,787 members per line; `singlechar` is arrays of objects holding all 94 one-byte names, about 174,000 members per line, the densest valid shape; `random3` is one object of about 131,000 distinct 3-byte names in a fixed pseudo-random order; `prefix` is 1,041 keys sharing a 1,000-byte prefix; `numbers` is one array of zeros; `strings` is one long string; `round` lines are 32,769 or 5,377 bytes, the worst allocator rounding (section 2); `badid` is 10,000 lines of 68 bytes whose `metadata.uid` fails `eventid.Parse`, each retaining a wrapped error; `minok` is 10,000 valid minimal lines of 103 bytes; `realistic` is an OCSF `process_activity` event of about 1.76 KB with 70 members.

Current decoder, `encoding/json` token walk, one decode, no memory limit:

| Shape | Decoded bytes, lines | Window | Compressed | Wall, CPU | Allocations | Allocated | Retained live | Peak `HeapInuse` | `VmHWM` |
|---|---|---|---|---|---|---|---|---|---|
| flat 64 × 1 MiB, single segment | 67,108,864, 64 | 64 MiB | 40,686 | 3,211 ms, 3,613 ms | 15,341,670 | 834.6 MB | 67.1 MB | 264.6 MB | 270.3 MB |
| flat 64 × 1 MiB | 67,108,864, 64 | 4 MiB | 61,095 | 2,903 ms, 3,288 ms | 15,341,446 | 771.8 MB | 67.1 MB | 141.1 MB | 150.9 MB |
| nested 64 × 1 MiB, single segment | 67,108,864, 64 | 64 MiB | 32,760 | 3,769 ms, 4,239 ms | 21,870,130 | 1,831 MB | 67.2 MB | 270.5 MB | 282.5 MB |
| dense 64 × 1 MiB, single segment | 67,108,864, 64 | 64 MiB | 96,737 | 4,101 ms, 4,647 ms | 18,526,979 | 1,333 MB | 67.1 MB | 264.6 MB | 270.5 MB |
| densenested 64 × 1 MiB, single segment | 67,108,864, 64 | 64 MiB | 37,287 | 4,440 ms, 4,961 ms | 24,965,099 | 2,063 MB | 67.2 MB | 270.1 MB | 281.4 MB |
| arrayobjs 64 × 1 MiB, single segment | 67,108,864, 64 | 64 MiB | 8,156 | 4,827 ms, 4,846 ms | 28,763,185 | 2,750 MB | 67.2 MB | 273.3 MB | 283.2 MB |
| numbers 64 × 1 MiB, single segment | 67,108,864, 64 | 64 MiB | 8,536 | 2,893 ms, 3,247 ms | 33,558,253 | 679.3 MB | 67.2 MB | 242.3 MB | 258.0 MB |
| strings 64 × 1 MiB, single segment | 67,108,864, 64 | 64 MiB | 8,176 | 822 ms, 904 ms | 4,515 | 343.1 MB | 67.2 MB | 223.5 MB | 224.9 MB |
| round 2,047 × 32,769 B, single segment | 67,080,190, 2,047 | 64 MiB | 41,375 | 2,484 ms, 2,390 ms | 16,081,102 | 888.4 MB | 84.1 MB | 261.6 MB | 267.2 MB |
| flat 10,000 × 6,710 B, single segment | 67,100,000, 10,000 | 64 MiB | 107,993 | 2,707 ms, 3,042 ms | 17,234,702 | 1,050 MB | 68.9 MB | 267.3 MB | 272.7 MB |
| flat 4 × 1 MiB | 4,194,304, 4 | 4 MiB | 30,346 | 172 ms, 209 ms | 958,974 | 59.1 MB | 4.2 MB | 32.6 MB | 34.7 MB |
| realistic 2,000 | 3,512,453, 2,000 | 4 MiB | 111,636 | 123 ms, 125 ms | 629,384 | 43.6 MB | 3.8 MB | 25.5 MB | 32.0 MB |
| realistic 5,000 | 8,789,453, 5,000 | 4 MiB | 273,409 | 253 ms, 280 ms | 1,574,650 | 91.7 MB | 9.3 MB | 36.7 MB | 39.6 MB |
| realistic 10,000 | 17,588,454, 10,000 | 4 MiB | 558,069 | 581 ms, 713 ms | 3,150,272 | 171.8 MB | 18.5 MB | 51.7 MB | 60.5 MB |

Lean walker of section 7, allocated once per `Decode` call, same frames, one decode, no memory limit:

| Shape | Wall, CPU | Allocations | Allocated | Retained live | Peak `HeapInuse` | `VmHWM` |
|---|---|---|---|---|---|---|
| flat 64 × 1 MiB, single segment | 3,128 ms, 3,282 ms | 3,225 | 145.5 MB | 67.2 MB | 145.6 MB | 145.2 MB |
| flat 64 × 1 MiB, 4 MiB window | 2,991 ms, 3,286 ms | 3,191 | 82.6 MB | 67.1 MB | 82.5 MB | 88.3 MB |
| nested, single segment | 3,131 ms, 3,013 ms | 2,606 | 145.5 MB | 67.2 MB | 145.6 MB | 145.3 MB |
| dense, single segment | 1,975 ms, 2,180 ms | 2,161 | 145.5 MB | 67.1 MB | 145.5 MB | 150.4 MB |
| densenested, single segment | 2,777 ms, 2,904 ms | 2,488 | 145.5 MB | 67.2 MB | 145.6 MB | 145.5 MB |
| arrayobjs, single segment | 1,664 ms, 1,731 ms | 2,032 | 145.3 MB | 67.2 MB | 145.4 MB | 145.3 MB |
| singlechar, single segment | 1,553 ms, 1,513 ms | 1,079 | 145.2 MB | 67.2 MB | 145.3 MB | 145.5 MB |
| random3, single segment | 4,188 ms, 3,990 ms | 1,893 | 145.8 MB | 66.9 MB | 145.5 MB | 146.6 MB |
| prefix, single segment | 665 ms, 655 ms | 1,042 | 145.2 MB | 67.2 MB | 145.2 MB | 144.3 MB |
| numbers, single segment | 1,460 ms, 1,509 ms | 1,496 | 145.3 MB | 67.2 MB | 145.3 MB | 147.8 MB |
| strings, single segment | 630 ms, 666 ms | 1,079 | 145.2 MB | 67.2 MB | 145.3 MB | 143.3 MB |
| round 2,047 × 32,769 B | 2,507 ms, 2,580 ms | 17,137 | 162.5 MB | 84.1 MB | 162.3 MB | 160.1 MB |
| round 10,000 × 5,377 B | 1,951 ms, 1,980 ms | 74,021 | 128.6 MB | 62.4 MB | 128.0 MB | 126.3 MB |
| flat 10,000 × 6,710 B | 2,438 ms, 2,622 ms | 74,725 | 148.4 MB | 68.8 MB | 148.8 MB | 146.2 MB |
| flat 4 × 1 MiB, 4 MiB window | 193 ms, 206 ms | 332 | 19.4 MB | 4.2 MB | 19.5 MB | 23.9 MB |
| dense 4 × 1 MiB, 4 MiB window | 129 ms, 131 ms | 304 | 19.4 MB | 4.2 MB | 19.5 MB | 19.5 MB |
| badid 10,000 lines, 688,890 B, single segment | 40 ms, 41 ms | 102,670 | 14.1 MB | 3.1 MB | 14.2 MB | 12.5 MB |
| minok 10,000 lines, 1,038,890 B, single segment | 31 ms, 32 ms | 72,644 | 15.4 MB | 2.1 MB | 15.5 MB | 12.3 MB |
| realistic 2,000 | 67 ms, 71 ms | 38,517 | 19.6 MB | 3.8 MB | 19.7 MB | 15.9 MB |
| realistic 5,000 | 181 ms, 192 ms | 96,547 | 26.3 MB | 9.3 MB | 26.3 MB | 24.5 MB |
| realistic 10,000 | 350 ms, 363 ms | 192,969 | 37.4 MB | 18.4 MB | 35.6 MB | 34.6 MB |

Concurrency, no limit: the current decoder peaks at 511.5 MB `HeapInuse` for 2 maximal flat decodes and 1,001.5 MB for 4 (CPU 12,244 ms), and at 1,232.2 MB for 32 realistic 5,000 decodes; the lean walker peaks at 580.9 MB for 4 maximal flat decodes (wall 5,451 ms, CPU 10,527 ms), 309.0 MB for 16 realistic 2,000 and 308.4 MB for 16 largest legitimate batches (dense, 4 MiB window). Peaks add linearly, so a byte-weighted budget models concurrency.

CPU depends on name order. In one paired run on the same host, random3 took 3,826 and 3,990 ms of CPU against 2,540 and 2,875 ms for flat and 2,443 and 2,694 ms for densenested: 1.4 to 1.5 times flat, because a random order is the sort's average case while generated keys arrive nearly sorted. Scaling the highest flat figure (3,282 ms) by 1.5 gives the planning maximum used below: 5.0 s of CPU per maximal batch, 78 ms per MiB.

With the limit set by the child as above, every case kept `/gc/limiter/last-enabled:gc-cycle` at 0, so the GC CPU limiter never engaged. The first twelve rows used a `T` constant of 3 MiB, 1 MiB below section 2; the rest use the section 2 weight:

| Case, lean walker | N | Limit | Peak used / limit | GC cycles | Wall, limited vs unlimited |
|---|---|---|---|---|---|
| flat 64 × 1 MiB, single segment | 1 | 172.1 MB | 0.882 | 3 | 2,547 vs 3,128 ms |
| densenested, single segment | 1 | 172.1 MB | 0.884 | 3 | 3,210 vs 2,777 ms |
| arrayobjs, single segment | 1 | 172.0 MB | 0.883 | 3 | 2,052 vs 1,664 ms |
| round 2,047 × 32,769 B | 1 | 172.1 MB | 0.984 | 20 | 2,620 vs 2,507 ms |
| round 10,000 × 5,377 B | 1 | 142.1 MB | 0.950 | 4 | 1,962 vs 1,951 ms |
| flat 10,000 × 6,710 B | 1 | 172.2 MB | 0.901 | 4 | 2,195 vs 2,438 ms |
| realistic 10,000 | 1 | 48.3 MB | 0.879 | 4 | 360 vs 350 ms |
| flat 4 × 1 MiB, 4 MiB window | 1 | 30.5 MB | 0.848 | 3 | 181 vs 193 ms |
| flat 64 × 1 MiB, single segment | 4 | 671.8 MB | 0.874 | 6 | 4,366 vs 5,451 ms |
| round 2,047 × 32,769 B | 4 | 671.3 MB | 0.964 | 8 | 8,006 vs 5,250 ms |
| realistic 5,000 | 8 | 253.6 MB | 0.838 | 5 | 640 vs 750 ms |
| dense 4 × 1 MiB, 4 MiB window | 16 | 405.8 MB | 0.781 | 5 | 1,405 vs 958 ms |
| badid | 1 | 20.4 MB | 0.981 | 8 | 74 vs 40 ms |
| badid | 8 | 124.7 MB | 0.958 | 5 | 278 ms |
| minok | 1 | 21.8 MB | 0.970 | 6 | 103 vs 31 ms |
| minok | 8 | 148.3 MB | 0.855 | 4 | 359 ms |
| random3, single segment | 1 | 173.9 MB | 0.879 | 3 | 4,596 vs 4,188 ms |
| random3, single segment | 4 | 677.7 MB | 0.869 | 6 | 8,266 vs 7,448 ms |
| singlechar, single segment | 1 | 173.4 MB | 0.874 | 3 | 1,702 vs 1,553 ms |
| singlechar, single segment | 4 | 675.8 MB | 0.865 | 5 | 2,964 ms |
| singlechar 4 × 1 MiB, 4 MiB window | 16 | 421.1 MB | 0.745 | 5 | 497 vs 636 ms |

The current decoder under its own weight (`S = s`, `T = 2 MiB + 12 × min(s, 1 MiB)`) also held the limiter at 0, with ratios of 0.988 (maximal flat, 38 GC cycles), 1.000 (arrayobjs, 124 cycles) and 1.001 (4 maximal flat). The soft limit removes garbage above the live set; it cannot remove the live set, which the runtime documents as the limit's floor ([`debug.SetMemoryLimit`](https://pkg.go.dev/runtime/debug@go1.27.1#SetMemoryLimit)). The round shapes show why `S` carries allocator rounding: 2,047 lines of 32,769 bytes retain 84.1 MB for 67.1 MB of content. The badid shape shows why the `T` constant is 4 MiB: with 3 MiB it peaked at 1.001 of its limit, because each failing line retains a wrapped error.

## 2. Cost model

Weight is a live-byte bound for one admitted request, computed from facts known before decompression. Let `w` be the effective window the body preflight computes (content size for a single-segment frame, else the Window_Descriptor value) and `s` the declared Frame_Content_Size, both at most 67,108,864 (EV-09).

| Term | Value | Covers |
|---|---|---|
| `C` | 5,000,000 | Compressed buffer, `wire.MaxCompressedBytes` |
| `H(w)` | `v + min(v, 2 MiB)` with `v = max(w, 1 KiB)` | Decoder history. The pinned decoder raises a single-segment window to its 1 KiB `MinWindowSize`, then allocates twice the window below 2 MiB minus one and the window plus 1 MiB above it under `lowMem` ([framedec.go](https://github.com/klauspost/compress/blob/v1.20.1/zstd/framedec.go)) |
| `S(s)` | `s + s/4` | Cloned raw lines with allocator rounding. Go rounds each allocation up to a size class, and above 32 KiB to whole 8 KiB pages, so a line of `L` payload bytes occupies at most `1.25 × (L + 1) + 7` bytes, worst at `L = 32,769` ([size classes](https://github.com/golang/go/blob/go1.27.1/src/internal/runtime/gc/sizeclasses.go)) |
| `T(s)` | `4 MiB + 5 × min(s, 1 MiB)` | The constant: line scratch (1,048,577 bytes), the result slice (at most 10,000 × 96 bytes), the 7-byte rounding remainder of at most 10,000 lines, one retained value per line (a wrapped `ErrEventID` of about 160 bytes after rounding, or the decoded `DeviceUID` string; at most 1,600,000 bytes), and about 0.3 MB of decoder block state. The factor: the lean walker's arena and entry slice (`3.4 × min(s, 1 MiB)`, section 7) and per-line garbage |

`Weight(w, s) = C + H(w) + S(s) + T(s)`. Maximal: `w = s = 64 MiB` gives 167,529,280 bytes (167.5 MB). Largest legitimate agent batch ([batch writer](agent-batch-writer.md#3-sealing-limits-and-error-precedence): window and content at most 4 MiB): 25,971,520 bytes (26.0 MB). A 10 KiB single-segment batch: 9,278,784 bytes. An attacker's maximal batch costs 6.5 times a legitimate maximal batch and 18 times a small one, so charging by declared size and window shifts refusals onto hostile shapes without changing the agent contract.

`T` is a constant of the decoder, not of the input; CI proves it (section 9). A decoder change that alters the walker's state, the scratch or the result slice changes `T` here and in `admission.Weight` in one reviewed change, never silently.

## 3. Admission protocol

One limiter per process serves every `agent` upload handler. Admission has two phases because the frame header lives inside the body: the window and content size are known only after the compressed bytes are read. `Reason` values are in code font.

| Phase | When | Charged | Immediate refusal |
|---|---|---|---|
| Receive | After authentication and header parsing, before any body byte | One in-flight slot, one per-device slot, `C` bytes, `M` from the device's rate bucket, also on a slot or in-flight refusal | Device slots full: 429, `device_concurrency`; bucket below `M`: 429, `device_rate`; in-flight slots full: 503, `inflight` |
| Decode | After `body.ReadFrame`, before `body.DecodeFrame` | `max(s, M) − M` from the device's rate bucket at once; `H(w) + S(s) + T(s)` bytes when the budget allows | Bucket deficit: 429, `device_rate`; wait expired: 503, `budget` or `reserve` |

Limits, all per replica:

- `budget` `B`: bytes charged across both phases, from section 4.
- `reserve` `R = B / 4`: a batch of class `raw`, `context` or `lineage` is admitted only while `available − weight ≥ R`; `findings` and `audit` batches use the whole budget. This is the quarter events section 3.7 keeps for detections. The class comes from the client's header and descriptor frame, so a compromised device can label any batch `findings`: the reserve keeps a legitimate raw backlog from delaying legitimate detections and is a fairness device, not a security boundary.
- `max_inflight`: requests between receive admission and release, default `floor((B − Weight_max) / (2 × C))` clamped to 4 through 256, so every in-flight request can hold its receive weight while one maximal decode and one more receive still fit.
- Per-device slots: at most 2 tickets per device, the agent's own limit of two uploads (events section 2.4). A third is refused and counted. It is not evidence of a modified agent, because a broken connection can leave the server holding a ticket while the agent retries.
- Per-device rate bucket: capacity 67,108,864 bytes (`body.MaxDecodedBytes`), in declared decoded bytes (Frame_Content_Size), refilled at 4,259,840 bytes per second, 1/64 faster than the agent's 4 MiB/s. The agent's upload bucket ([events section 2.5](../design/events.md#25-offline-behaviour)) meters the same quantity at 4 MiB/s with an 8 MiB burst, starts empty and charges every request, retries included. Every request is charged `max(s, M)` on both sides, where `M` = 131,072 bytes (128 KiB) is the minimum charge: the server takes `M` at receive, before any body byte, and the rest at decode, and the agent charges the same total before it sends. In any interval of length `t` the server charges an unmodified agent for at most four requests issued before the interval, each at most 4 MiB (the sealing limit): two the agent still has in flight and two the server still holds for requests the agent abandoned, because a broken connection can leave the server finishing a body it already has. Adding what the agent's bucket released during the interval (8 MiB + 4 MiB/s × `t`) gives at most 24 MiB + 4 MiB/s × `t`, inside the server's 64 MiB + 4.0625 MiB/s × `t`. The faster refill keeps two independent clocks from accumulating a deficit: a 500 ppm clock slew is about 31 times smaller than the 1/64 margin. An unmodified agent, including one draining a full spool, is therefore never refused for rate.
- `decode_wait` default 2 s: the longest a decode-phase request waits for budget, also bounded by its request context.

Charging and waiting. `Receive` checks in a fixed order: the device's slots, then its bucket, then the in-flight slots. With both device slots held it refuses with `device_concurrency` and charges `M` if the bucket holds it; otherwise a bucket below `M` refuses with `device_rate` and charges nothing; otherwise it charges `M` and then refuses with `inflight` if no in-flight slot is free, or admits. Every event upload that reaches `Receive` therefore costs its device `M`, whether it is admitted, refused for slots or in-flight capacity, or fails before decoding, for example with a malformed frame, unless the bucket is already empty. This stays conformant because the agent charges `max(s, M)` for every request it sends, retries included, so each server charge follows an agent charge at least as large. A device at its slot limit is refused for concurrency, not for rate, so a draining agent never counts toward the rate finding. `Ticket.Decode` charges the remaining `max(s, M) − M` when the bucket holds it, before any wait. Neither charge is refunded when the wait expires, the context ends, the budget refuses or the request fails, so a device cannot re-queue a large waiter or repeat failing requests for free; a deficit refuses at once and charges nothing.

The minimum charge bounds how many event uploads a device can make, admitted or refused: at most 512 after a full bucket and then 32 per second sustained; requests that find the bucket empty cost one limiter call each and count toward the rate finding. That rate compares with about 2.2 small batches per second from an agent whose classes seal at their age limits (events section 2.4). Each request has a fixed decode cost the bucket would otherwise not see: a minimal one-line batch takes about 1 ms of decode CPU and allocates 6.1 MB of zeroed memory, the compressed buffer and the line scratch. At 32 requests per second that is about 0.03 core of decode per device, below the 0.31 core of section 8. The handler slice measures the per-request cost of TLS, authentication, storage and the acknowledgement fence at that rate, including the garbage-collection cost of the allocations; if 32 requests per second cost more than 0.31 core, `M` rises in a reviewed change to this specification and to events section 2.5 together. Decode-phase waiters form two FIFO queues, `findings` and `audit` first, then the other classes. A new request is admitted at once only when its own queue is empty and its weight fits, above the reserve for the other classes; otherwise it joins the tail of its queue. On every release the limiter admits the priority head while it fits, then the other head while it fits above the reserve, and repeats until neither head fits. A head that does not fit blocks only its own queue: a large waiter is never overtaken within its queue, the other queue still moves, and no head waits longer than `decode_wait`. A canceled context or an expired wait removes the waiter; the caller then releases the ticket's receive charge. A waiting request holds its already-read compressed frame and reads nothing further.

Release. The ticket is released when the handler finishes, after the response is written or the request fails, so the budget covers the raw lines through validation and storage; the storage deadline of section 5 bounds that hold. The storage stage's own buffers (enriched NDJSON for the export-log object, `COPY` staging rows) are not part of `Weight`. The ingest slice measures their peak per batch, streams from the `Line` slice without a second full copy, and adds a storage term to `Weight` in a reviewed change if that peak exceeds 25 % of `S`.

`Retry-After` is a canonical decimal in 5 through 60 (wire section 5). Device-slot refusal: 5. Bucket refusal at receive or decode: `ceil(deficit / ServerRefill)` clamped, at most 16. In-flight refusal: `base = ceil(10 s / release rate)`, that is `ceil(100 / n)` for `n` tickets released during the last 10 s, kept in a second ring of ten one-second counters indexed like the drain ring; `n = 0` gives 60. Slots, not bytes, bind such a refusal, so its wait follows how fast slots free: ordinary churn gives 5, while slow uploads holding every slot push it toward 60 instead of letting the fleet retry every few seconds. Budget, reserve and handler-level 503 refusals: `base = ceil((ahead + weight − available) / drain)`, where `ahead` is the total weight waiting in both queues, `weight` is the request's current charge, and `drain` is the bytes released during the last 10 s, kept in a ring of ten one-second counters, divided by 10; `drain = 0` gives 60. For every refusal kind, multiply by a uniform factor in 0.8 through 1.2 from the injected random source, round half up and clamp again. The 429 and 503 bodies are the existing wire fixtures, and `fixtures/response.json` carries both `Retry-After` bounds for each status (`429`, `retry-upper-bound-429`, `503`, `retry-upper-bound`); this specification adds no response field and changes no status binding.

Security finding. Two signals prove a client that is not an unmodified agent, and the limiter owns both because it sees each with the authenticated device. First, a decode request whose declared content size or window exceeds `SealingLimit`, the largest content and window any agent release in AG-04's served window seals: 4 MiB, which a release that raises the writer's limit raises in the same release ([batch writer](agent-batch-writer.md#3-sealing-limits-and-error-precedence)). The frame is still admitted or refused on its normal terms, because EV-09 accepts it, but the evidence is recorded. Second, more than 20 `device_rate` refusals in the trailing ten minutes, counted in ten one-minute counters. The decision that first establishes either signal for a device carries `Finding` (`oversize_frame` or `rate`), and no further finding is raised for that device for ten minutes, so the detection inbox is not flooded. Suppression hides no volume: every oversize frame increments the device's oversize counters and `ricevanta_ingest_oversize_frames_total{class}`. The handler records a device-scoped security finding through the `detection` module's finding contract, a later gate shared with the device-binding finding of the body spec. No `pipeline_activity` event is emitted: that class's activities are a closed list ([OCSF profile section 1.1](ocsf-profile.md#11-foundation-scope-and-class-allocation)) and admission adds none.

Attribution. A compromised device that stays within the sealing limit and its bucket raises no finding, yet about 13 of them can consume a replica's CPU (section 8). Each device entry therefore also keeps ten one-minute counters of admitted declared bytes, of decode time in microseconds, which the handler reports with `Ticket.Decoded` without rounding a short decode to zero, and of oversize frames; `Snapshot().TopDevices` returns the ten devices with the most decode time in the trailing ten minutes, each with its oversize-frame count. While the capacity alert of events section 8 is active, the handler writes them as one structured log record per minute. Metrics keep no device label, so their cardinality stays fixed.

Every one-minute counter, the ten-minute finding suppression and the ten one-second drain counters are indexed by time elapsed since the limiter started, `now.Sub(start)` on the injected clock, which Go computes from the monotonic clock reading; a wall-clock step therefore neither freezes nor clears them early.

Device entries. An entry exists while the device holds a slot, its bucket is below capacity, a counter is nonzero or its finding suppression runs; every limiter call removes up to two idle entries from the head of a list ordered by last update. Memory is therefore bounded by the devices active in the last ten minutes, at most the enrolled fleet, at 384 bytes or less each: 7.7 MB at 20,000 devices.

## 4. Process memory ceiling and configuration

- `server.memory_limit` (bytes, decimal or IEC suffix) is applied with `debug.SetMemoryLimit` before any listener starts. When absent, the runtime's `GOMEMLIMIT` environment variable applies. A process that runs the `agent` role refuses to start with neither, because the budget below has no anchor without a limit.
- The container or service memory limit is `memory_limit / 0.9`: the GC guide recommends 5 to 10 % headroom for memory the runtime does not see ([Go GC guide, memory limit](https://go.dev/doc/gc-guide)). The limit is soft; it covers `/memory/classes/total:bytes − /memory/classes/heap/released:bytes` and the runtime promises effort, not a hard cap, with the GC CPU limiter at about 50 % preventing thrashing. The budget therefore bounds the live set and leaves the rest of the limit to the baseline, connections, caches and GC working room.
- `ingest.decode_budget` default: `0.5 × memory_limit` when the process runs only the `agent` role, else `0.25 × memory_limit`. Minimum 256 MiB, which satisfies `B − R ≥ Weight_max` (201.3 MB available against 167.5 MB). The smallest accepted `memory_limit` is therefore 512 MiB for an `agent`-only process and 1 GiB when other roles share the process, with container limits of 569 MiB and 1,138 MiB. Lower values are refused at startup with the computed values in the error.
- The 0.5 default assumes that connections, the authorization snapshot, TLS and HTTP/2 buffers, caches and GC working room fit in the other half at about 6,700 agent connections per replica. The transport slice measures per-connection memory and re-derives this fraction in a reviewed change before the handler slice ships.
- `ingest.decode_budget`, `ingest.max_inflight` and `ingest.decode_wait` override the defaults. A `decode_budget` override must lie between 256 MiB and the role's default fraction of `memory_limit` (0.5 for an `agent`-only process, else 0.25, or the fraction the transport slice re-derives); `New` receives the memory limit and refuses a larger value, so the budget always follows the memory limit. The per-device slots, the bucket capacity and rates and the sealing limit are protocol constants shared with the agent (section 3), not configuration.

| Shape | Container | `memory_limit` | `decode_budget` | `max_inflight` | Fits at once in the whole budget; other classes get three quarters |
|---|---|---|---|---|---|
| Docker Compose, all roles | 4 GiB | 3.6 GiB | 0.9 GiB (966 MB) | 79 | 5 maximal hostile batches, or 37 largest legitimate batches |
| Helm `agent` replica | 4 GiB | 3.6 GiB | 1.8 GiB (1,933 MB) | 176 | 11 maximal hostile batches, or 74 largest legitimate batches |
| Smallest `agent`-only process | 569 MiB | 512 MiB | 256 MiB (268 MB) | 10 | 1 maximal hostile batch, or 10 largest legitimate batches |
| Smallest process with all roles | 1,138 MiB | 1 GiB | 256 MiB (268 MB) | 10 | 1 maximal hostile batch, or 10 largest legitimate batches |

Decode CPU measured in section 1 is 19 to 23 ms per MiB for realistic events with the lean walker (32 to 43 ms with the current decoder) while hostile shapes reach 62 ms per MiB measured and 78 ms per MiB at the planning maximum (78 ms measured with the current decoder). A 4 vCPU replica spending half its CPU on decoding therefore handles about 87 MiB of realistic events per second, 21 largest legitimate batches per second. At 20,000 endpoints on three replicas (EV-01) each replica serves about 6,700 devices; the per-device bucket, the budget and the jittered `Retry-After` shape a mass reconnect into that rate while `findings` and `audit` keep their reserve (events section 2.5).

## 5. Handler obligations

The handler slice that consumes this package must do the following, in order, for `POST /agent/v1/events`; the limiter cannot enforce any of it from inside.

1. Serve on the `agent` listener configured as [architecture section 3.4](../architecture.md#34-agent-protocol) specifies, including the HTTP/2 stream cap and receive buffers; no server-wide `ReadTimeout` or `WriteTimeout`, which would cut long polls.
2. Authenticate under the authorization snapshot (backend section 3), reject `update_only` devices, then `wire.ParseHeader` for the tentative class. Reject a declared `Content-Length` above 5,000,000 with 413 before reading the body.
3. `Receive(device, class)`; on refusal write 429 or 503 with the decision's `RetryAfter` and read no body byte.
4. Read the body under a progress deadline: wrap the request body in a reader that calls [`ResponseController.SetReadDeadline`](https://pkg.go.dev/net/http@go1.27.1#ResponseController.SetReadDeadline) with the current time plus 20 s before the first read, and again each time 16 KiB more have arrived since the last extension; Go does not extend a deadline that has already passed. The minimum progress is 16 KiB per 20 s, about 820 bytes per second; a slower upload fails its read, and the request ends without a response status. A 5,000,000-byte body at that rate holds its receive slot for at most 6,104 s; a device holds at most two slots however long each lasts.
5. `wire.Decode`, then `body.ReadFrame` on the same reader; map errors per the body spec. Then clear the read deadline and call `SetWriteDeadline(now + 60 s)`, which bounds the wait, the decode, storage and the response written after the body.
6. `ticket.Decode(ctx, frame.Window(), frame.ContentSize())`; on refusal write the mapped status. Then check `ctx.Err()`: a canceled request (connection closed, HTTP/2 stream reset, per [Request.Context](https://pkg.go.dev/net/http@go1.27.1#Request.Context)) skips `body.DecodeFrame`, which is CPU-bound and not interruptible. One decode takes at most 5.0 s of CPU at the planning maximum (section 1); 11 maximal decodes sharing 4 vCPU finish in about 14 s.
7. `body.DecodeFrame`, then validation, storage, ledger and the acknowledgement fence under `context.WithTimeout(ctx, 20 s)`. On expiry answer 503 `unavailable` with `Limiter.Unavailable(storage_timeout, weight)`; an uncertain commit is never acknowledged (events section 3.5). The post-body path is thus at most 2 s of wait, about 14 s of contended decode and 20 s of storage, inside the 60 s write deadline. `ticket.Release()` is deferred from step 3, so every path releases exactly once.
8. Metrics: `ricevanta_ingest_admission_budget_bytes`, `ricevanta_ingest_admission_inuse_bytes`, `ricevanta_ingest_admission_waiting`, `ricevanta_ingest_admission_wait_seconds`, `ricevanta_ingest_inflight`, `ricevanta_ingest_decode_seconds{class}` and `ricevanta_ingest_refused_total{class,reason}` with the `Reason` values of section 6 plus `canceled`, and `ricevanta_ingest_oversize_frames_total{class}`, incremented for every decode request above `SealingLimit`. Report each decode's duration with `ticket.Decoded`. When a decision carries a `Finding`, record the security finding of section 3, and while the capacity alert is active log `Snapshot().TopDevices` once a minute. Sustained `inflight` or `budget` refusals for over one minute raise the capacity alert of events section 8.

Every path that ends without a final status, such as a failed or expired body read, a canceled request that skips the decode or an expired write deadline, ends with `panic(http.ErrAbortHandler)`, never a plain return: Go writes an implicit 200 when a handler returns without a header, while the panic resets the HTTP/2 stream or closes the HTTP/1.1 connection and still runs the deferred `Release` ([`ErrAbortHandler`](https://pkg.go.dev/net/http@go1.27.1#ErrAbortHandler)).

The agent's upload timeouts in [events section 2.4](../design/events.md#24-sealing-upload-and-acknowledgement) are derived from these bounds, so an unmodified agent abandons a request only after the server has ended it, or when the connection breaks.

## 6. Go API

```go
package admission

const (
    CompressedWeight int64 = 5_000_000
    MaxWeight int64 = 167_529_280
    PerDeviceInflight = 2
    BucketCapacity uint64 = 64 << 20
    AgentRate uint64 = 4 << 20 // bytes per second, the agent's upload bucket
    ServerRefill uint64 = AgentRate + AgentRate/64
    SealingLimit uint64 = 4 << 20
    MinCharge uint64 = 128 << 10 // bucket charge per request at least, taken at Receive
)

type Reason string  // device_concurrency, device_rate, inflight, budget, reserve, storage_timeout, commit_latency, store_unavailable
type Finding string // empty, oversize_frame, rate
type Config struct { MemoryLimit int64; AgentOnly bool; Budget int64; MaxInflight int; DecodeWait time.Duration }
type Clock interface { Now() time.Time; NewTimer(d time.Duration) Timer }
type Timer interface { C() <-chan time.Time; Stop() bool }
type Decision struct { Status int; RetryAfter int; Reason Reason; Finding Finding } // Status 0: admitted

func Weight(window, size uint64) (int64, error)
func Defaults(memoryLimit int64, agentOnly bool) (Config, error)
func New(c Config, clock Clock, random func() float64) (*Limiter, error)
func (l *Limiter) Receive(device string, class batch.SpoolClass) (*Ticket, Decision, error)
func (l *Limiter) Unavailable(reason Reason, weight int64) Decision
func (t *Ticket) Decode(ctx context.Context, window, size uint64) (Decision, error)
func (t *Ticket) Decoded(d time.Duration)
func (t *Ticket) Release()
func (l *Limiter) Snapshot() Snapshot // counters, oversize frames by class, TopDevices (at most 10)

var (
    ErrConfig = errors.New("ingest admission config")
    ErrArgument = errors.New("ingest admission argument")
    ErrDevice = errors.New("ingest admission device")
    ErrState = errors.New("ingest admission state")
)
```

`Weight` is pure; a window or size above 64 MiB, which EV-09 rejects first, returns `ErrArgument`, never a panic. `Defaults` returns `ErrConfig` for a memory limit below the section 4 minimums. `New` validates `256 MiB ≤ Budget ≤` the role's fraction of `MemoryLimit`, `MaxInflight ≥ 4`, `DecodeWait > 0` and the in-flight invariant, returning `ErrConfig` with the failing value. `Receive` never blocks and takes no context; it applies the section 3 check order, charging `MinCharge` on admission and on `device_concurrency` and `inflight` refusals whenever the bucket holds it, and a refusal returns a nil ticket and a `Decision` with a nonzero `Status`. `Decode` blocks at most `DecodeWait` or until `ctx` ends, returning `ctx.Err()` on cancellation; an argument above 64 MiB is `ErrArgument`; it returns a `Decision` whose `Status` is 0 on admission, and a refusal leaves the ticket in the receive phase for the caller to release. `Finding` can be set on an admitted or a refused decision. `Decoded` adds a decode's duration, in microseconds, to the device's attribution counters. `Unavailable` computes the 503 `Retry-After` of section 3 for handler-level refusals. Calling `Decode` twice, or `Decode` after `Release`, is `ErrState`; `Decoded` after `Release` is ignored. An empty device string is `ErrDevice`. `Release` is idempotent on the same ticket and never blocks. `Snapshot` returns the counters for metrics and the top devices without locking out admission for long. The package imports only `batch` and the standard library; it has no HTTP, logging or database code and holds no goroutines of its own.

`body` adds the frame split of [body spec section 2](event-batch-body.md#2-exact-go-api-and-ownership):

```go
type Frame struct { /* unexported compressed bytes, content size and window */ }
func (f Frame) ContentSize() uint64
func (f Frame) Window() uint64
func ReadFrame(r *io.LimitedReader) (Frame, error)
func DecodeFrame(f Frame, d batch.Descriptor, authenticatedDevice string) ([]Line, error)
```

Tests are deterministic: a fake clock, an injected random source and no sleeps. A test observes a waiter through `Snapshot().Waiting` before releasing budget, then reads the waiter's result from a channel; timer channels fire only when the test advances the fake clock.

## 7. Decoder allocation cost

Decision: bound concurrency and also replace the key walk. A maximal batch retains about 140 MB of live memory with any walker, because the compressed buffer, the decoder history and the cloned lines are intrinsic to EV-09's contract; no allocation work removes that floor, so admission is necessary regardless. The token walk is the only part whose cost grows with member and value density: 15 to 34 million allocations and 0.7 to 2.8 GB allocated per 64 MiB batch of dense lines, which the GC must sweep while other requests run. The lean walker removes more than 99.9 % of those allocations, lowers whole-batch CPU by up to 64 % on member-dense shapes and lowers the maximal peak `HeapInuse` from about 265 MB to 146 MB (section 1), with identical results on every body fixture and the parity cases.

The walker keeps the `validLineJSON` prepass and replaces the `encoding/json` token walk with a byte scanner over the validated line, as [body section 6](event-batch-body.md#6-strict-field-extraction-and-line-errors) describes. Its duplicate check sorts instead of hashing. For each line it appends one 12-byte entry (object number, offset and length of the decoded name) per member to an entry slice and the decoded name to an arena; at the end of the line it sorts the entries by object number, then name bytes, with `slices.SortFunc`, and compares neighbours. With `L = min(s, MaxLineBytes)`, the arena holds `L` bytes and the entry slice `L / 5 + 1` entries, because the shortest member, `"":0,`, takes 5 bytes; neither ever grows, and duplicates count against the same bound because they are found only after the line is collected. Both are allocated once per `Decode` call and released at return, never pooled across requests, so retained memory does not grow with the largest line a replica has seen; the 5-byte duplicate line fills 209,715 of 209,716 entries without growth.

No hash means no seed and nothing for an attacker to collide. The pinned `slices.SortFunc` is pattern-defeating quicksort that falls back to heapsort after `bits.Len(n)` bad pivots ([source](https://github.com/golang/go/blob/go1.27.1/src/slices/zsortanyfunc.go)), the algorithm whose O(n log n) comparisons [`sort.Sort`](https://pkg.go.dev/sort@go1.27.1#Sort) documents. A line therefore costs O(n log n) comparisons for at most `n = 209,715` entries, plus `n − 1` neighbour checks, and each comparison reads at most the shorter name, so the bytes compared are O(N log n) for at most `N = 1 MiB` of names; no input reaches the quadratic case a hash flood forces. Measured comparisons per 1 MiB line: 2,562,437 flat, 2,178,442 densenested, 149,811 arrayobjs, 209,726 for the 5-byte duplicate line and 5,239 for 1,041 names sharing a 1,000-byte prefix; whole batches decode in at most 4.0 s of CPU measured (random3) and 5.0 s at the planning maximum (section 1).

`T` covers the walker: arena `L`, entries `2.4 × L` and the line scratch, against the `5 × min(s, 1 MiB)` term and the 4 MiB constant of section 2, which CI proves on the densest, rounding and concurrent shapes (section 9).

The EV-09 ceilings. EV-09 admits 64 MiB of content and a 64 MiB window, 16 times the agent writer's 4 MiB sealing limit. That headroom sets the hostile cost: 167.5 MB of weight against 26.0 MB for the largest legitimate batch, up to 5.0 s of non-interruptible decode CPU per batch, and 11 hostile batches filling a Helm budget. Lowering both ceilings to 8 MiB, twice the sealing limit, would cut the hostile weight to 35.4 MB and the CPU per batch about eight times, and would let a Helm budget hold 54 hostile batches, without affecting any batch the agent writer produces. It would not change the sustained CPU of a compromised device, which the per-device rate sets. EV-09 keeps 64 MiB: admission charges every request its declared cost, so the headroom costs capacity under attack rather than memory safety; lowering it means revising the wire and body contracts, their reference fixtures and the implemented decoder, and would tie every change of the agent's sealing limit to a server contract revision. The `oversize_frame` finding of section 3 attributes every frame above the sealing limit to its device at no cost, which recovers most of the security value of lower ceilings.

Rejected: a hash set keyed per process with `hash/maphash`, faster on flat lines but with a worst case that rests on a secret seed and, pre-sized for 209,715 entries at half load, an 8 MiB table against 3.6 MB of arena and entries for sorting; an unkeyed hash, which a compromised agent can flood into quadratic probing; a streaming decoder that yields lines before the checksum, which EV-09 rejects; `GOGC` tuning alone, which cannot bound the live set.

## 8. Threat trace

| Attacker | What the mechanism yields and what remains |
|---|---|
| Stolen enrollment token | Uploads need the device certificate enrollment issues; the attacker is then one device: two concurrent uploads, a 64 MiB burst then about 4 MiB/s of declared decoded bytes per replica, at most 335 MB of budget and about 0.3 core of decode CPU sustained per replica (78 ms of CPU per hostile MiB at the planning maximum); many tiny requests are held to 32 per second by the 128 KiB minimum charge, about 0.03 core of decode. Any frame above the 4 MiB sealing limit, or more than 20 rate refusals in 10 minutes, raises a security finding. Token policy is PKI-02. |
| Compromised agent host sending maximal-cost batches in parallel | Same per-device bounds; each batch costs at most 167.5 MB of budget and 5.0 s of CPU, and its first frame above the sealing limit raises a security finding. It can label batches `findings` to draw on the reserve and connect to every replica to multiply its rate by the replica count. Staying within the sealing limit and its bucket, about 13 such devices at full rate consume all four cores of a 4 vCPU replica without a finding; the budget caps their memory at `B`, `findings` and `audit` keep the memory reserve but share the CPU, and raw, context and lineage from other devices receive 503 with jittered `Retry-After` and keep spooling. The per-device finding and the top-device log of section 3 are the hooks for response; isolating or suspending a device is an MDM-02 and EDR-04 protected action under BE-02, not an admission side effect. |
| Slow uploads | A receive slot holds only `C`, one in-flight count and one device slot, for up to 6,104 s at the minimum progress, under 16 streams per connection. A device holds at most two slots however long each lasts, so occupying every in-flight slot needs `max_inflight / 2` devices sending continuously. While it lasts other devices receive 503 with a `Retry-After` that follows the slot release rate, up to 60 s while no slot frees, and spool; each extra request the holding devices send costs them `M`; and the `inflight` alert fires. |
| 20,000 endpoints reconnecting | Each replica admits up to its budget, refuses the rest with 503 and 5 to 60 s jittered `Retry-After`, serves `findings` and `audit` first and shapes each device to 4 MiB/s, so the backlog drains at the measured decode rate instead of exhausting memory. Nothing acknowledged is lost: a refused batch stays in the spool (EV-04). |
| Compromised console session | Admission limits are process configuration and protocol constants, not API resources; the session cannot raise or lower them. Any later API for them must be a protected action (BE-02). |
| Rogue extension publisher | Publication gives no device certificate and no upload path; nothing to gain here. |
| Network position between agent and server | Cannot create admitted requests without the device key under mTLS. Can stall or cut connections it carries; a stalled request ends after 20 s without progress and never yields a 200, and the agent retries. |
| Database writer without signing keys | The limiter reads no database and persists nothing; no row changes a limit or grants capacity. Stalling the storage stage holds tickets for at most the 20 s storage deadline, after which requests answer 503 and release their budget. |
| Server restored from backup | Admission state is in memory and rebuilt at start; a restore grants no capacity and restores no counter. Server buckets start full, so each device may burst 64 MiB once after a restart. |

## 9. CI evidence

`server/internal/events/body` adds `TestDecodeCostModel`, built with `//go:build !race`, which generates the section 1 shapes with the pinned encoder at test time (these are measurement inputs, not contract fixtures, so the zstd CLI reference rule of body section 8 does not apply). The parent spawns one child per case with `GOGC=100` and `GOMEMLIMIT=off`. The child loads its frame, calls `runtime.GC()`, measures its baseline as `/memory/classes/total:bytes − /memory/classes/heap/released:bytes`, calls `debug.SetMemoryLimit(baseline + N × Weight(w, s))` and logs both values before decoding. A second child per case runs without a limit as the wall-time reference.

Cases: one decode of every section 1 shape (flat, nested, dense, densenested, arrayobjs, singlechar, random3, prefix, numbers, strings, both round shapes, badid, minok, flat 10,000 × 6,710, flat at 1, 4, 16 and 64 MiB in single-segment and 4 MiB-window variants, realistic at 2,000, 5,000 and 10,000 lines, and the largest legitimate batch, dense 4 × 1 MiB with a 4 MiB window; the 64 MiB single-segment flat variant is the flat shape, counted once), and concurrent decodes: 4 maximal flat, 4 round 2,047 × 32,769, 4 arrayobjs, 4 singlechar, 4 random3, 8 badid, 8 realistic 5,000 and 16 largest legitimate batches. A case passes when every decode returns the expected lines and `/gc/limiter/last-enabled:gc-cycle` is 0, which is the primary condition; the sampled peak of total minus released memory is at most 1.1 times the limit (at most 0.984 locally, and 0.981 under the section 2 weight, section 1); and the limited child's wall time is at most twice the reference when the reference takes at least 500 ms, and at most the reference plus 500 ms when it is shorter, since children of 25 to 100 ms vary by more than twice between identical runs on a shared host (section 1: minok 103 against 31 ms). The first `ubuntu-24.04` run records the largest memory ratio and the largest wall ratio; a case that breaks the wall rule there fails and is a question for design review about the harness or the model, never a reason to loosen the bound. The parent also divides the largest CPU of the hostile shapes by the largest CPU of the flat shapes in the same job and logs the ratio; the first run records it, and a ratio above 1.5, the factor behind the 5.0 s planning maximum of section 1, returns that maximum to design rather than failing the run, since absolute CPU varies between shared runners. Each child logs one `COST_MEASUREMENT` line with shape, N, window, size, weight, baseline, limit, allocations, CPU, wall, peak and `VmHWM`; the parent requires one line per expected case and ends with one `COST_MODEL_CASES n=34` line counting them.

`TestDecodeCostModel` runs its cases only when the environment variable `RICEVANTA_COST_MODEL=full` is set; otherwise it skips with a message, so ordinary `go test ./...` runs, including the `server-unit` check, never time short children against each other. With the variable set it runs exactly the 34 cases above from a fixed table, never a subset selected by `-run`. The CI step sets the variable and fails unless the log holds `COST_MODEL_CASES n=34` and 34 `COST_MEASUREMENT` lines, so the proof cannot shrink silently. `BenchmarkDecodeCost` reports time, bytes and allocations per shape.

CI runs both from `server/` in the `validate` job, writing the combined output to `$RUNNER_TEMP/ingest-measurements/cost-model.log` with `tee` and uploading it as `ingest-measurements-<runId>-<runAttempt>` with 30-day retention, outside the receipt directories, under the rules of [CI hardening](ci-hardening.md):

```sh
RICEVANTA_COST_MODEL=full GOGC=100 go test -count=1 -timeout=15m ./internal/events/body -run '^TestDecodeCostModel$' -v
go test -run '^$' -bench '^BenchmarkDecodeCost$' -benchmem -benchtime=3x -timeout=15m ./internal/events/body
```

The check id `ingest-cost-model` joins the `server-validate` receipt. A measured peak above the model, an engaged limiter or a ratio above 1.1 on the `ubuntu-24.04` runner fails the check; the fix is a model change in this specification and `admission.Weight`, reviewed, never a looser assertion.

## 10. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: memory under ingest load is bounded by configuration that follows from the process memory limit; hostile batch shapes pay for what they cost while the agent contract and response bodies stay as specified; detections keep a memory reserve; an unmodified agent is never refused for its own rate and never sends a frame above the sealing limit, so either is evidence attributed to a device; every refusal carries a bounded, jittered `Retry-After` the agent already honours; the model is proven on every CI run; the lean walker removes the allocation storm and cannot be hash-flooded.

Trade-offs: two admission phases and the additive `body` split; a request may wait up to 2 s before decoding; a maximal legitimate batch is charged 26.0 MB although realistic events retain under 10 MB, because `S` prices worst-case allocator rounding and `T` the walker's fixed state and per-line values; a process without a memory limit cannot run the `agent` role; the per-device rate is a protocol constant, so changing it changes agent and server together; the sort-based duplicate check spends about as much CPU as the token walk on flat key-dense lines.

Dependencies: the standard library, the existing `batch`, `wire` and `body` packages and the pinned `github.com/klauspost/compress` already in `licensing.md`. No new module: `golang.org/x/sync/semaphore` was considered and rejected because its single FIFO cannot express the class reserve and the per-device rules, and the limiter is about two hundred lines.

Limits: the weight bounds decoding, not the storage stage, whose buffers the ingest slice measures; CPU is bounded per device and by the budget, not by a scheduler, so about 13 compromised devices staying within the sealing limit and their buckets can consume a 4 vCPU replica's CPU, detections included, with only the top-device log to attribute them; per-device state is per replica; HTTP/2 receive buffers and per-connection memory sit outside the budget, so the transport slice caps connections at about eight per device certificate per replica and measures the exposure; a link that cannot carry 16 KiB in 20 s cannot deliver a batch (events section 2.4); numbers are from one Linux x64 host and CI reproduces them on x64 `ubuntu-24.04` runners only, while server images also ship for `linux/arm64`, where the model is unmeasured, including on kernels with 64 KiB pages; `DecodeFrame` is not interruptible once started.

Alternatives: a fixed concurrency count (rejected: a count admits either too few legitimate batches or too many hostile ones, since weights differ by 18 times); charging `Content-Length` (rejected: compressed size does not bound decoded size); charging the worst case for every request (rejected: admits six requests per gigabyte regardless of size); a queue of compressed bodies (rejected: it buffers 5 MB per queued request before knowing the decode cost and still needs this budget); per-device CPU accounting (rejected: it measures after the fact, while bytes are known before decoding and cost at most 78 ms per MiB at the planning maximum); metering the agent's bucket in compressed bytes (rejected: realistic events compress about 31 times, so the server could not bound decoded work without refusing unmodified agents); lowering EV-09's ceilings (rejected for this design, section 7).

## 11. Sources

- [Go garbage collector guide, memory limit](https://go.dev/doc/gc-guide); [`runtime/debug.SetMemoryLimit`](https://pkg.go.dev/runtime/debug@go1.27.1#SetMemoryLimit); [`runtime/metrics`](https://pkg.go.dev/runtime/metrics@go1.27.1) for `/gc/heap/live:bytes`, `/gc/heap/allocs:objects`, `/memory/classes/total:bytes`, `/memory/classes/heap/released:bytes` and `/gc/limiter/last-enabled:gc-cycle`; Go 1.27.1 [size classes](https://github.com/golang/go/blob/go1.27.1/src/internal/runtime/gc/sizeclasses.go) and their [generator's waste rules](https://github.com/golang/go/blob/go1.27.1/src/runtime/_mkmalloc/mksizeclasses.go).
- [`net/http`](https://pkg.go.dev/net/http@go1.27.1): `ResponseController.SetReadDeadline` and `SetWriteDeadline` (a passed deadline is not extended), `Request.Context`, `HTTP2Config`, `ErrAbortHandler`; Go 1.27.1 `net/http/server.go`, where a handler that returns without a header gets an implicit 200 (`finishRequest`) and `ReadHeaderTimeout` also bounds the TLS handshake (`tlsHandshakeTimeout`).
- [`slices`](https://pkg.go.dev/slices@go1.27.1#SortFunc) and its [pdqsort source](https://github.com/golang/go/blob/go1.27.1/src/slices/zsortanyfunc.go); [`sort.Sort`](https://pkg.go.dev/sort@go1.27.1#Sort) for the documented O(n log n) bound.
- [RFC 9110 section 10.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3) (`Retry-After`, delay-seconds), [section 15.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.6.4) (503), [section 15.5.14](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.14) (413); [RFC 6585 section 4](https://www.rfc-editor.org/rfc/rfc6585.html#section-4) (429).
- [RFC 8878 section 3.1.1.1.2](https://www.rfc-editor.org/rfc/rfc8878.html#section-3.1.1.1.2) (Window_Descriptor); [klauspost zstd v1.20.1 `framedec.go`](https://github.com/klauspost/compress/blob/v1.20.1/zstd/framedec.go) and [`history.go`](https://github.com/klauspost/compress/blob/v1.20.1/zstd/history.go) for the history allocation rule.
