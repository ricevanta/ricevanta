# Ingest decode admission

Bound how many event batch bodies one `agent` replica decodes at once, charge each by the memory it can occupy, and tie the total to the process memory ceiling. This specifies the pure Go limiter package `server/internal/events/admission`, the additive frame split and the allocation-lean key walk of `server/internal/events/body`, and what the future `POST /agent/v1/events` handler must call. [The wire spec](event-upload-wire.md) owns the request and response contract; [the body spec](event-batch-body.md) owns decoding (EV-09); [events section 3.7](../design/events.md#37-backpressure) summarizes backpressure. Decision: [EV-11](../decisions.md#ev-11-ingest-decode-admission-budget).

## 1. Measurements

These measurements cover the listed encoder-generated shapes only. They do not establish a CPU bound for arbitrary frames. Section 9 requires adversarial measurements and blocks handler integration until they pass; the CPU figures below are planning targets, not qualified worst cases.

The tables record measurements of the `body` decoder; the derived CPU maximum is a planning target. Host: Linux 6.18 x64, 4 vCPU Intel Xeon 2.10 GHz, 16 GiB, Go 1.27.1 (module toolchain), `github.com/klauspost/compress` v1.20.1. Method: a throwaway test generates one frame per shape with the pinned module's encoder (level 3, checksum, 4 MiB window or single segment), then runs one child process per case. The child loads only the compressed frame, forces `runtime.GC()`, reads its baseline, optionally calls `debug.SetMemoryLimit(baseline + N × Weight)` itself, runs `body.Decode` N times concurrently, samples `HeapInuse` and `/memory/classes/total:bytes − /memory/classes/heap/released:bytes` every millisecond, and reads `VmHWM` from `/proc/self/status` after return with the lines kept alive. `GOGC=100`. Retained live and peak `HeapInuse` are deltas over the child's baseline; `VmHWM` is the child's absolute peak resident size.

Shapes: `flat` is `"kN":0` members with distinct keys; `nested` is `"kN":{"a":0}`; `dense` is 3-byte keys, 131,064 members per 1 MiB line; `densenested` is 3-byte keys holding `{"a":0}`; `arrayobjs` is one array of `{"":0}`, 149,787 members per line; `singlechar` is arrays of objects holding all 94 one-byte names, about 174,000 members per line, the densest valid shape; `random3` is one object of about 131,000 distinct 3-byte names in a fixed pseudo-random order; `prefix` is 1,041 keys sharing a 1,000-byte prefix; `numbers` is one array of zeros; `strings` is one long string; `round` lines are 32,769 or 5,377 bytes, the worst allocator rounding (section 2); `badid` is 10,000 lines of 68 bytes whose `metadata.uid` fails `eventid.Parse`, each retaining a wrapped error; `minok` is 10,000 valid minimal lines of 103 bytes; `realistic` is an OCSF `process_activity` event of about 1.76 KB with 70 members.

Reference `encoding/json` token walk, one decode, no memory limit:

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

Concurrency, no limit: the reference token decoder peaks at 511.5 MB `HeapInuse` for 2 maximal flat decodes and 1,001.5 MB for 4 (CPU 12,244 ms), and at 1,232.2 MB for 32 realistic 5,000 decodes; the lean walker peaks at 580.9 MB for 4 maximal flat decodes (wall 5,451 ms, CPU 10,527 ms), 309.0 MB for 16 realistic 2,000 and 308.4 MB for 16 largest legitimate batches (dense, 4 MiB window). Peaks add linearly, so a byte-weighted budget models concurrency.

CPU depends on name order. In one paired run on the same host, random3 took 3,826 and 3,990 ms of CPU against 2,540 and 2,875 ms for flat and 2,443 and 2,694 ms for densenested: 1.4 to 1.5 times flat, because a random order is the sort's average case while generated keys arrive nearly sorted. Scaling the highest flat figure (3,282 ms) by 1.5 gives a candidate qualification ceiling: 5.0 s of CPU per 64 MiB of work charge, exactly 78.125 ms per MiB. The block-density, window and malformed cases in section 9 must meet it before it supports a CPU or handler-timing claim.

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

The reference token decoder under its own weight (`S = s`, `T = 2 MiB + 12 × min(s, 1 MiB)`) also held the limiter at 0, with ratios of 0.988 (maximal flat, 38 GC cycles), 1.000 (arrayobjs, 124 cycles) and 1.001 (4 maximal flat). The soft limit removes garbage above the live set; it cannot remove the live set, which the runtime documents as the limit's floor ([`debug.SetMemoryLimit`](https://pkg.go.dev/runtime/debug@go1.27.1#SetMemoryLimit)). The round shapes show why `S` carries allocator rounding: 2,047 lines of 32,769 bytes retain 84.1 MB for 67.1 MB of content. The badid shape shows why the `T` constant is 4 MiB: with 3 MiB it peaked at 1.001 of its limit, because each failing line retains a wrapped error.

## 2. Cost model

Weight is a live-byte bound for one admitted request, computed from facts known before decompression. Let `w` be the effective window the body preflight computes (content size for a single-segment frame, else the Window_Descriptor value) and `s` the declared Frame_Content_Size, both at most 67,108,864 (EV-09).

| Term | Value | Covers |
|---|---|---|
| `C` | 5,000,000 | Compressed buffer, `wire.MaxCompressedBytes` |
| `H(w)` | `v + min(v, 2 MiB)` with `v = max(w, 1 KiB)` | Decoder history. The pinned decoder raises a single-segment window to its 1 KiB `MinWindowSize`, then allocates twice the window below 2 MiB minus one and the window plus 1 MiB above it under `lowMem` ([framedec.go](https://github.com/klauspost/compress/blob/v1.20.1/zstd/framedec.go)) |
| `S(s)` | `s + s/4` | Cloned raw lines with allocator rounding. Go rounds each allocation up to a size class, and above 32 KiB to whole 8 KiB pages, so a line of `L` payload bytes occupies at most `1.25 × (L + 1) + 7` bytes, worst at `L = 32,769` ([size classes](https://github.com/golang/go/blob/go1.27.1/src/internal/runtime/gc/sizeclasses.go)) |
| `T(s)` | `4 MiB + 5 × min(s, 1 MiB)` | The constant: line scratch (1,048,577 bytes), the result slice (at most 10,000 × 96 bytes), the 7-byte rounding remainder of at most 10,000 lines, one retained value per line (a wrapped `ErrEventID` of about 160 bytes after rounding, or the decoded `DeviceUID` string; at most 1,600,000 bytes), and about 0.3 MB of decoder block state. The factor: the lean walker's arena and entry slice (`3.4 × min(s, 1 MiB)`, section 7) and per-line garbage |

`Weight(w, s) = C + H(w) + S(s) + T(s)`. Maximal: `w = s = 64 MiB` gives 167,529,280 bytes (167.5 MB). Largest legitimate agent batch ([batch writer](agent-batch-writer.md#3-sealing-limits-and-error-precedence): window and content at most 4 MiB): 25,971,520 bytes (26.0 MB). A 10 KiB single-segment batch: 9,278,784 bytes. An attacker's maximal batch costs 6.5 times a legitimate maximal batch and 18 times a small one, so charging by declared size and window shifts refusals onto hostile shapes without changing the agent contract.

`T` is a constant of the decoder, not of the input; the expanded CI gate must qualify it (section 9). A decoder change that alters the walker's state, the scratch or the result slice changes `T` here and in `admission.Weight` in one reviewed change, never silently.

### Codec work independent of output size

Memory weight and rate charge serve different bounds. Define `Q(w, s) = max(w, s, M)`, with `M = 128 KiB`. Both server and agent buckets meter `Q`; the agent computes it from the sealed frame before sending, including on retry. An agent release using output-only charging must qualify that its emitted windows never raise `Q` above its existing charge before the server serves it under this rule; otherwise the served-window upgrade needs a reviewed compatibility change. A 103-byte frame with a 64 MiB window therefore costs 64 MiB, not `M`. The memory formula is unchanged. A malformed frame rejected by `ReadFrame` pays only the receive charge `M`, so preflight and bounded input copying must qualify at that charge, regardless of the claimed window or output.

[Body section 4](event-batch-body.md#4-single-frame-preflight-and-codec-controls) caps block headers before decompression at `1 + ceil(max(s, 128 KiB) / 128 KiB)`: 2 for a minimal frame, 33 at 4 MiB and 513 at 64 MiB. Empty raw/RLE/compressed blocks count. Preflight inspects at most the cap plus one header and skips payloads by checked length. A 103-byte frame containing about 1.66 million empty blocks is rejected as `ErrFrame` before codec creation. The local pinned [`decoder.go`](https://github.com/klauspost/compress/blob/v1.20.1/zstd/decoder.go) (`nextBlockSync`) and [`blockdec.go`](https://github.com/klauspost/compress/blob/v1.20.1/zstd/blockdec.go) (`reset`) show why counting only output misses work: each block has a separate parse/decode iteration.

The cap allows a final empty block beyond one block per 128 KiB of declared output. It is a Ricevanta profile restriction, not an RFC rule. Verify that every served writer profile satisfies it using the live writer tests of section 9; no writer compatibility result is inferred from the output ceiling. The restriction bounds iterations; it does not alone prove CPU cost, because compressed-block parsing, window initialization, input copying and failure paths still need measurements. Qualification must cover these dimensions together, with the charge actually paid on each path.

## 3. Admission protocol

One limiter per process serves every `agent` upload handler. Admission has two phases because the frame header lives inside the body: the window and content size are known only after the compressed bytes are read. `Reason` values are in code font.

| Phase | When | Charged | Immediate refusal |
|---|---|---|---|
| Receive | After authentication and header parsing, before any body byte | One in-flight slot, one per-device slot, `C` bytes, `M` from the device's rate bucket, also on capacity refusals when credit exists | Device slots full: 429, `device_concurrency`; bucket below `M`: 429, `device_rate`; in-flight slots full: 503, `inflight`; priority slot floor: 503, `reserve`; bytes unavailable: 503, `budget` or `reserve` |
| Decode | After `body.ReadFrame`, before `body.DecodeFrame` | `Q(w, s) − M` from the device's rate bucket at once; `H(w) + S(s) + T(s)` bytes when the budget allows | Bucket deficit: 429, `device_rate`; wait expired: 503, `budget` or `reserve` |

Limits, all per replica:

- `budget` `B`: bytes charged across both phases, from section 4.
- Byte reserve `R = floor(B / 4)`: `raw`, `context` and `lineage` require `available − delta ≥ R` at **both** receive and decode admission. `delta = C` at receive and `Weight(w, s) − C` at decode, since the ticket already holds `C`. Priority classes `findings` and `audit` require only `available ≥ delta`. All tests and mutations occur atomically under the limiter lock. A request that cannot fit globally gets `budget`; one that fits globally but crosses the priority floor gets `reserve`.
- Slot reserve `P = ceil(max_inflight / 4)`: at receive, nonpriority requests also require `free_slots − 1 ≥ P`; priority requests require one free slot. No slot is added at decode. A globally full slot set gives `inflight`; crossing only the reserved-slot floor gives `reserve`. Both phases release their bytes and slot on every terminal path. With only nonpriority traffic, at least `R` bytes and `P` slots remain free, enough to receive and decode a largest legitimate priority batch even at the minimum budget. Existing priority traffic, a device's own two slots/rate bucket and CPU or storage contention can still delay it. The client-selected class is not a security boundary: a compromised device can label any batch `findings`.
- `max_inflight`: requests between receive admission and release, default `floor((B − Weight_max) / (2 × C))` clamped to 4 through 256, so every in-flight request can hold its receive weight while one maximal decode and one more receive still fit; `P` reserves receive slots within that cap.
- Per-device slots: at most 2 tickets per device, the agent's own limit of two uploads (events section 2.4). A third is refused and counted. It is not evidence of a modified agent, because a broken connection can leave the server holding a ticket while the agent retries.
- Per-device rate bucket: capacity 67,108,864 bytes (`body.MaxDecodedBytes`), in work bytes `Q(w, s)`, refilled at 4,259,840 bytes per second, 1/64 faster than the agent's 4 MiB/s. The agent's upload bucket ([events section 2.5](../design/events.md#25-offline-behaviour)) meters `Q` at 4 MiB/s with an 8 MiB burst, starts empty and charges every request, retries included. Every request that passes decode-rate admission is charged `Q(w, s)` on both sides, where `M` = 131,072 bytes (128 KiB) is the minimum charge: the server takes `M` at receive, before any body byte, and the rest at decode, and the agent charges the same total before it sends. In any interval of length `t` the server charges an unmodified agent for at most four requests issued before the interval, each with `Q` at most 4 MiB (the content and window sealing limits): two the agent still has in flight and two the server still holds for requests the agent abandoned, because a broken connection can leave the server finishing a body it already has. Adding what the agent's bucket released during the interval (8 MiB + 4 MiB/s × `t`) gives at most 24 MiB + 4 MiB/s × `t`, inside the server's 64 MiB + 4.0625 MiB/s × `t`. The faster refill keeps two independent clocks from accumulating a deficit: a 500 ppm clock slew is about 31 times smaller than the 1/64 margin. An unmodified agent, including one draining a full spool, is therefore never refused for rate.
- `decode_wait` default 2 s: the longest a decode-phase request waits for budget, also bounded by its request context.

Charging and waiting. `Receive` refills the bucket and observes whether credit is below `M` before selecting a response. It counts that observation once toward the rate finding even when both device slots are held. It then checks device slots, bucket, global in-flight slots, reserved slots, global bytes and reserved bytes, in that order. Full device slots keep response reason `device_concurrency`; a bucket below `M` with a device slot free gives `device_rate`. Charge `M` whenever credit permits, including concurrency, in-flight, byte and reserve refusals; never charge a deficit. Refusals acquire no ticket. Concurrency with adequate credit alone supplies no rate evidence. `Ticket.Decode` charges the remaining `Q(w, s) − M` before any wait; insufficient credit counts one rate observation and refuses immediately. No charge is refunded on failure, cancellation or timeout. A refused receive cannot also reach decode, so the two phases cannot double-count one deficit. Agent conformance follows because every server charge follows an agent charge at least as large.

The minimum charge permits at most 512 charged requests from a full server bucket, then 32.5 per second sustained (the agent's ceiling is 32). Uncharged requests below `M` cost a limiter call and count toward the rate finding. Neither figure bounds unauthenticated traffic or limiter-call CPU. Minimal one-line decode measurements do not cover adversarial blocks, large windows or malformed frames. Section 9 qualifies the bounded input-copy/preflight/decode path at the paid charge, including allocation and garbage collection, before any per-device CPU claim. A successful preflight followed by a decode-rate deficit also pays only `M` and must qualify without codec entry. The handler slice also measures TLS, authentication, storage and acknowledgement costs; a failed CPU target returns the rate/charge or frame limits to design, not a looser test.

Decode-phase waiters form two FIFO queues, `findings` and `audit` first, then the other classes. A new request is admitted at once only when its own queue is empty and its incremental weight fits under the byte rules above; otherwise it joins its queue's tail. On every release the limiter admits the priority head while it fits, then the other head while it fits above `R`, repeating until neither fits. A non-fitting head blocks only its own queue. Cancellation or expiry removes the waiter; the caller releases its receive charge and slot. Waiters retain their already-read compressed frame and read nothing further. Receive admission never queues, even for priority traffic; byte and slot reserves make capacity available without allowing receive-only uploads to consume it.

Release. The ticket is released when the handler finishes, after the response is written or the request fails, so the budget covers the raw lines through validation and storage; the storage deadline of section 5 bounds that hold. The storage stage's own buffers (enriched NDJSON for the export-log object, `COPY` staging rows) are not part of `Weight`. The ingest slice measures their peak per batch, streams from the `Line` slice without a second full copy, and adds a storage term to `Weight` in a reviewed change if that peak exceeds 25 % of `S`.

`Retry-After` is a canonical decimal in 5 through 60 (wire section 5). Compute a base, clamp it to 5 through 60, multiply by `0.8 + 0.4 × random()` from the injected source, round half up, then clamp to 5 through 60 again. Apply this same transformation to **every** 429 and 503, including device concurrency and rate. Device-concurrency base is 5, so final headers range from 5 to 6. Device-rate base is `ceil(deficit / ServerRefill)`, at most 16 before jitter, so a base of 16 yields 13 through 19; 16 is not a final-header ceiling.

For global in-flight and receive slot-reserve refusals, base is `ceil(100 / n)`, where `n` is the number of tickets released in the last ten seconds, or 60 when `n = 0`. Keep ten one-second counters indexed by elapsed time. For `n = 3`, base 34 yields headers 27, 34 and 41 at factors 0.8, 1 and 1.2. A single slot released 20 times in ten seconds produces base 5 even if every other slot remains occupied. The selected floor is a 5-second header; the agent's additional ±20 % jitter permits a 4-second pause. No stronger occupancy-dependent or starvation guarantee follows from release rate. Keep this floor to allow prompt recovery when capacity returns; a higher floor would delay legitimate retries and would still not bound hostile request arrivals.

For byte-budget, byte-reserve and handler-level 503 refusals, base is `ceil((ahead + delta − usable) / drain)`, with `ahead` the incremental bytes waiting in both queues, `delta` the requested additional bytes (`C` at receive, `Weight − C` at decode, supplied weight for handler-level refusals), and `usable = available − R` for nonpriority byte-reserve checks, else `available`. `drain` is released bytes during the last ten seconds divided by ten, using ten elapsed-time one-second counters; zero drain gives 60. The limiter retains whether a reserve refusal was caused by slots or bytes to select the formula. Wire response fixtures and status binding stay unchanged.

Security finding. Two signals prove a client that is not an unmodified agent, and the limiter owns both because it sees each with the authenticated device. First, a decode request whose declared content size or window exceeds `SealingLimit`, the largest content and window any agent release in AG-04's served window seals: 4 MiB, which a release that raises the writer's limit raises in the same release ([batch writer](agent-batch-writer.md#3-sealing-limits-and-error-precedence)). The frame is still admitted or refused on its normal terms, because EV-09 accepts it, but the evidence is recorded. Second, more than 20 rate-deficit observations in the trailing ten minutes, counted in ten one-minute counters: a receive bucket below `M`, including a `device_concurrency` response, or an insufficient decode remainder. These are evidence counters independent of response-reason counters. The decision that first establishes either signal for a device carries `Finding` (`oversize_frame` or `rate`), and no further finding is raised for that device for ten minutes, so the detection inbox is not flooded. Suppression hides no volume: every rate deficit increments its device counter even during suppression, and every oversize frame increments the device's oversize counters and `ricevanta_ingest_oversize_frames_total{class}`. The handler records a device-scoped security finding through the `detection` module's finding contract, a later gate shared with the device-binding finding of the body spec. No `pipeline_activity` event is emitted: that class's activities are a closed list ([OCSF profile section 1.1](ocsf-profile.md#11-foundation-scope-and-class-allocation)) and admission adds none.

Attribution. A compromised device that stays within the sealing limit and its bucket raises no finding, yet multiple such devices can consume a replica's CPU; section 9 must qualify the per-device cost. Each device entry therefore also keeps ten one-minute counters of admitted declared bytes, of decode time in microseconds, which the handler reports with `Ticket.Decoded` without rounding a short decode to zero, and of oversize frames; `Snapshot().TopDevices` returns the ten devices with the most decode time in the trailing ten minutes, each with its oversize-frame count. While the capacity alert of events section 8 is active, the handler writes them as one structured log record per minute. Metrics keep no device label, so their cardinality stays fixed.

Every one-minute counter, the ten-minute finding suppression and the ten one-second drain counters are indexed by time elapsed since the limiter started, `now.Sub(start)` on the injected clock, which Go computes from the monotonic clock reading; a wall-clock step therefore neither freezes nor clears them early.

Device entries. An entry exists while the device holds a slot, its bucket is below capacity, a counter is nonzero or its finding suppression runs; every limiter call removes up to two idle entries from the head of a list ordered by last update. Memory is therefore bounded by the devices active in the last ten minutes, at most the enrolled fleet, at 384 bytes or less each: 7.7 MB at 20,000 devices.

## 4. Process memory ceiling and configuration

Deployment authority owns `server.memory_limit`, `GOMEMLIMIT`, `ingest.decode_budget`, `ingest.max_inflight` and `ingest.decode_wait`. They are host/process settings, not console or GitOps resources. No `platform.settings` permission grants authority to change them. The quarter reserves and work-charge constants are protocol rules, not runtime operator actions. The separate permission-coverage refresh must extend `deployment-settings` with this exemption and inventory this spec plus the changed events/body documents; no new console permission is needed.

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

Decode CPU measured in section 1 is 19 to 23 ms per MiB for realistic events with the lean walker (32 to 43 ms with the reference token decoder) while hostile shapes reach 62 ms per MiB measured and 78.125 ms per MiB at the candidate qualification ceiling (78 ms measured with the reference token decoder). Using only those realistic-event measurements, a 4 vCPU replica spending half its CPU on decoding would handle about 87 MiB of realistic events per second, 21 largest legitimate batches per second. At 20,000 endpoints on three replicas (EV-01) each replica serves about 6,700 devices; the per-device bucket, the budget and the jittered `Retry-After` shape a mass reconnect into that rate while `findings` and `audit` keep their reserve (events section 2.5).

## 5. Handler obligations

The handler slice that consumes this package must do the following, in order, for `POST /agent/v1/events`; the limiter cannot enforce any of it from inside.

1. Serve on the `agent` listener configured as [architecture section 3.4](../architecture.md#34-agent-protocol) specifies, including the HTTP/2 stream cap and receive buffers; no server-wide `ReadTimeout` or `WriteTimeout`, which would cut long polls.
2. Authenticate under the authorization snapshot (backend section 3), reject `update_only` devices, then `wire.ParseHeader` for the tentative class. Reject a declared `Content-Length` above 5,000,000 with 413 before reading the body.
3. `Receive(device, class)`; on refusal write 429 or 503 with the decision's `RetryAfter` and read no body byte.
4. Read the body under a progress deadline: wrap the request body in a reader that calls [`ResponseController.SetReadDeadline`](https://pkg.go.dev/net/http@go1.27.1#ResponseController.SetReadDeadline) with the current time plus 20 s before the first read, and again each time 16 KiB more have arrived since the last extension; Go does not extend a deadline that has already passed. The minimum progress is 16 KiB per 20 s, about 820 bytes per second; a slower upload fails its read, and the request ends without a response status. A 5,000,000-byte body at that rate holds its receive slot for at most 6,104 s; a device holds at most two slots however long each lasts.
5. `wire.Decode`, then `body.ReadFrame` on the same reader; map errors per the body spec. Then clear the read deadline and call `SetWriteDeadline(now + 60 s)`, which bounds the wait, the decode, storage and the response written after the body.
6. `ticket.Decode(ctx, frame.Window(), frame.ContentSize())`; on refusal write the mapped status. Then check `ctx.Err()`: a canceled request (connection closed, HTTP/2 stream reset, per [Request.Context](https://pkg.go.dev/net/http@go1.27.1#Request.Context)) skips `body.DecodeFrame`, which is CPU-bound and not interruptible. The 5.0 s maximum and about 14 s for 11 maximal decodes on 4 vCPU are unqualified planning estimates. Section 9 must measure all admitted and failing frame shapes and mixed-size concurrency before these estimates support a handler deadline.
7. `body.DecodeFrame`, then validation, storage, ledger and the acknowledgement fence under `context.WithTimeout(ctx, 20 s)`. On expiry answer 503 `unavailable` with `Limiter.Unavailable(storage_timeout, weight)`; an uncertain commit is never acknowledged (events section 3.5). The 60 s write deadline is a required transport bound, not a proven bound on non-interruptible decode completion. Handler integration is blocked until qualification demonstrates decode completion and ticket release inside that deadline with the 2 s wait and 20 s storage allowance, including contention from every configured in-flight decode; eleven maximal decodes alone do not cover it. `ticket.Release()` is deferred from step 3, so every path releases exactly once.
8. Metrics: `ricevanta_ingest_admission_budget_bytes`, `ricevanta_ingest_admission_inuse_bytes`, `ricevanta_ingest_admission_waiting`, `ricevanta_ingest_admission_wait_seconds`, `ricevanta_ingest_inflight`, `ricevanta_ingest_decode_seconds{class}` and `ricevanta_ingest_refused_total{class,reason}` with the `Reason` values of section 6 plus `canceled`, and `ricevanta_ingest_oversize_frames_total{class}`, incremented for every decode request above `SealingLimit`. Report each decode's duration with `ticket.Decoded`. When a decision carries a `Finding`, record the security finding of section 3, and while the capacity alert is active log `Snapshot().TopDevices` once a minute. Sustained capacity refusals for over one minute raise the capacity alert of events section 8: aggregate `ricevanta_ingest_refused_total{class,reason}` across classes for `reason` in `inflight`, `budget` and `reserve`. Both byte-reserve refusals (receive or decode) and receive slot-reserve refusals count as `reserve`; neither requires a simultaneous `inflight` or `budget` refusal. This same alert enables the once-per-minute attribution log, including when `TopDevices` is empty because no decode has completed. Device-rate and device-concurrency refusals alone do not raise this capacity alert.

Every path that ends without a final status, such as a failed or expired body read, a canceled request that skips the decode or an expired write deadline, ends with `panic(http.ErrAbortHandler)`, never a plain return: Go writes an implicit 200 when a handler returns without a header, while the panic resets the HTTP/2 stream or closes the HTTP/1.1 connection and still runs the deferred `Release` ([`ErrAbortHandler`](https://pkg.go.dev/net/http@go1.27.1#ErrAbortHandler)).

The agent's upload timeouts in [events section 2.4](../design/events.md#24-sealing-upload-and-acknowledgement) depend on qualification of these bounds. Before handler integration, prove that an unmodified agent abandons only after the server ends the request or the connection breaks; the planning estimates do not prove it.

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

`Weight` is pure; a window or size above 64 MiB, which EV-09 rejects first, returns `ErrArgument`, never a panic. `Defaults` returns `ErrConfig` for a memory limit below the section 4 minimums. `New` validates `256 MiB ≤ Budget ≤` the role's fraction of `MemoryLimit`, `MaxInflight ≥ 4`, `DecodeWait > 0` and the in-flight invariant, returning `ErrConfig` with the failing value. `Receive` never blocks and takes no context; it applies the section 3 check order, charging `MinCharge` on admission and all capacity refusals whenever the bucket holds it, independently counting a below-minimum bucket even on a concurrency response, and preserving both reserves, and a refusal returns a nil ticket and a `Decision` with a nonzero `Status`. `Decode` blocks at most `DecodeWait` or until `ctx` ends, returning `ctx.Err()` on cancellation; an argument above 64 MiB is `ErrArgument`; it returns a `Decision` whose `Status` is 0 on admission, and a refusal leaves the ticket in the receive phase for the caller to release. `Finding` can be set on an admitted or a refused decision. `Decoded` adds a decode's duration, in microseconds, to the device's attribution counters. `Unavailable` computes the 503 `Retry-After` of section 3 for handler-level refusals. Calling `Decode` twice, or `Decode` after `Release`, is `ErrState`; `Decoded` after `Release` is ignored. An empty device string is `ErrDevice`. `Release` is idempotent on the same ticket and never blocks. `Snapshot` returns the counters for metrics and the top devices without locking out admission for long. The package imports only `batch` and the standard library; it has no HTTP, logging or database code and holds no goroutines of its own.

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

No hash means no seed and nothing for an attacker to collide. The pinned `slices.SortFunc` is pattern-defeating quicksort that falls back to heapsort after `bits.Len(n)` bad pivots ([source](https://github.com/golang/go/blob/go1.27.1/src/slices/zsortanyfunc.go)), the algorithm whose O(n log n) comparisons [`sort.Sort`](https://pkg.go.dev/sort@go1.27.1#Sort) documents. A line therefore costs O(n log n) comparisons for at most `n = 209,715` entries, plus `n − 1` neighbour checks, and each comparison reads at most the shorter name, so the bytes compared are O(N log n) for at most `N = 1 MiB` of names; no input reaches the quadratic case a hash flood forces. Measured comparisons per 1 MiB line: 2,562,437 flat, 2,178,442 densenested, 149,811 arrayobjs, 209,726 for the 5-byte duplicate line and 5,239 for 1,041 names sharing a 1,000-byte prefix; the measured whole-batch CPU reaches 4.0 s (random3); 5.0 s remains the candidate qualification ceiling of section 1.

`T` covers the walker: arena `L`, entries `2.4 × L` and the line scratch, against the `5 × min(s, 1 MiB)` term and the 4 MiB constant of section 2, which CI proves on the densest, rounding and concurrent shapes (section 9).

The EV-09 ceilings. EV-09 admits 64 MiB of content and a 64 MiB window, 16 times the agent writer's 4 MiB sealing limit. That headroom sets the hostile cost: 167.5 MB of weight against 26.0 MB for the largest legitimate batch, a candidate 5.0 s non-interruptible decode CPU ceiling per batch, pending section 9, and 11 hostile batches filling a Helm budget. Lowering both ceilings to 8 MiB, twice the sealing limit, would cut the hostile weight to 35.4 MB; CPU does not necessarily fall proportionally because window, block and fixed work also matter, and would let a Helm budget hold 54 hostile batches, without affecting any batch the agent writer produces. Neither ceiling alone establishes sustained CPU; section 9 qualifies cost per work charge. EV-09 keeps 64 MiB: admission charges every request its declared cost, so the headroom costs capacity under attack rather than memory safety; lowering it means revising the wire and body contracts, their reference fixtures and the implemented decoder, and would tie every change of the agent's sealing limit to a server contract revision. The `oversize_frame` finding of section 3 attributes every frame above the sealing limit to its device at no cost, which recovers most of the security value of lower ceilings.

Rejected: a hash set keyed per process with `hash/maphash`, faster on flat lines but with a worst case that rests on a secret seed and, pre-sized for 209,715 entries at half load, an 8 MiB table against 3.6 MB of arena and entries for sorting; an unkeyed hash, which a compromised agent can flood into quadratic probing; a streaming decoder that yields lines before the checksum, which EV-09 rejects; `GOGC` tuning alone, which cannot bound the live set.

## 8. Threat trace

| Attacker | What the mechanism yields and what remains |
|---|---|
| Stolen enrollment token | Uploads need the device certificate enrollment issues; the attacker is then one device: two concurrent uploads, a 64 MiB burst then about 4 MiB/s of work bytes per replica, at most 335 MB of budget. Work charge includes the window; block count is checked before codec creation. CPU per paid charge remains gated by section 9, including tiny and malformed frames; there is no qualified 0.03-core tiny-frame bound. Any frame above the 4 MiB sealing limit, or more than 20 rate deficits in 10 minutes (including concurrent requests below `M`), raises a security finding. Token policy is PKI-02. |
| Compromised agent host sending maximal-cost batches in parallel | Same per-device bounds; each batch costs at most 167.5 MB of budget; 5.0 s of CPU is a qualification target, and its first frame above the sealing limit raises a security finding. It can label batches `findings` to draw on the reserve and connect to every replica to multiply its rate by the replica count. Devices staying within the sealing limit and bucket can collectively exhaust CPU without a finding; their required number is unqualified; the budget caps their memory at `B`, `findings` and `audit` keep the memory reserve but share the CPU, and raw, context and lineage from other devices receive 503 with jittered `Retry-After` and keep spooling. The per-device finding and the top-device log of section 3 are the hooks for response; isolating or suspending a device is an MDM-02 and EDR-04 protected action under BE-02, not an admission side effect. |
| Slow uploads | A receive slot holds only `C`, one in-flight count and one device slot, for up to 6,104 s at the minimum progress, under 16 streams per connection. A device holds at most two slots however long each lasts, so occupying every in-flight slot needs `max_inflight / 2` devices sending continuously. Nonpriority uploads cannot consume the priority byte and slot reserves; priority-labelled uploads can. While global capacity is exhausted other devices receive 503 with a `Retry-After` that follows the slot release rate, up to 60 s while no slot frees, and spool; each extra request costs `M` when available and otherwise counts toward the rate finding while retaining the concurrency response; and sustained `inflight`, `budget` or `reserve` refusals raise the capacity alert and enable attribution logging. Nonpriority-only saturation can produce only `reserve` refusals while global slots and bytes remain available; it still alerts, although decode-time attribution cannot identify receive-only holders. |
| 20,000 endpoints reconnecting | Each replica admits up to its budget, refuses the rest with 503 and 5 to 60 s jittered `Retry-After`, serves `findings` and `audit` first and shapes each device to 4 MiB/s, so the backlog drains at the measured decode rate instead of exhausting memory. Nothing acknowledged is lost: a refused batch stays in the spool (EV-04). |
| Compromised console session | Admission limits are process configuration and protocol constants, not API resources; the session cannot raise or lower them. Any later API for them must be a protected action (BE-02). |
| Rogue extension publisher | Publication gives no device certificate and no upload path; nothing to gain here. |
| Network position between agent and server | Cannot create admitted requests without the device key under mTLS. Can stall or cut connections it carries; a stalled request ends after 20 s without progress and never yields a 200, and the agent retries. |
| Database writer without signing keys | The limiter reads no database and persists nothing; no row changes a limit or grants capacity. Stalling the storage stage holds tickets for at most the 20 s storage deadline, after which requests answer 503 and release their budget. |
| Server restored from backup | Admission state is in memory and rebuilt at start; a restart clears evidence and suppression and gives each authenticated device a fresh 64 MiB work burst. It grants no identity authority: the handler must remain sealed under BE-12 until current authorization is restored, then apply both reserves; a backup cannot restore tickets or bypass preflight. |

## 9. CI evidence and qualification gates

The 34 encoder-generated single/concurrent cases remain required: the section 1 shapes and size/window variants, including 4 maximal flat, 4 round 2,047 × 32,769, 4 arrayobjs, 4 singlechar, 4 random3, 8 badid, 8 realistic 5,000 and 16 largest legitimate batches. They cover allocation density, not all codec work. Add these 16 named cases to the fixed case table; structural mutations are hand-built measurement inputs with exact expected outcomes, not encoder-only round trips. Each row must prove that its intended rejection stage or accepted block count is reached, without relying on an earlier unrelated error.

| Case key | Frame and expected outcome |
|---|---|
| `blocks-min-at` | Valid 103-byte line, 2 blocks including one empty raw block; success |
| `blocks-min-over` | Same output, 3 blocks; `ReadFrame` returns `ErrFrame`, codec not created |
| `blocks-min-ceiling` | Same output with empty raw blocks filling the compressed allowance; `ErrFrame` at header 3, codec not created |
| `blocks-4m-at` | Valid 4 MiB output, 33 blocks with maximum empty-block padding permitted by the cap; success |
| `blocks-4m-over` | Same output, 34 blocks; `ErrFrame` before codec creation |
| `blocks-64m-at` | Valid 64 MiB output, 513 blocks with maximum empty-block padding; success |
| `blocks-64m-over` | Same output, 514 blocks; `ErrFrame` before codec creation |
| `small-window64` | 103-byte valid output and advertised 64 MiB window; success, `Q = 64 MiB` |
| `small-window64-checksum` | Same frame with corrupt checksum; `ErrChecksum`, full `Q` paid |
| `malformed-entropy` | Declared 103 bytes, 128 KiB window, structurally valid maximum-sized compressed block, valid header and checksum bytes, corrupted literal/sequence tables; codec `ErrFrame`, full `Q` paid |
| `late-checksum64` | 64 MiB output at block cap, checksum failure after bounded decoding; `ErrChecksum` |
| `size-lie-small` | Declared 103 bytes, permitted 128 KiB window, block expands beyond declaration; `ErrContentSize`, full `Q` paid |
| `preflight-ceiling` | Near-5 MB body with legal block lengths/count followed by a truncated final header; preflight `ErrFrame`, only `M` paid |
| `preflight-rate-deficit` | Near-5 MB structurally valid body at the block cap; `ReadFrame` succeeds but decode credit is insufficient, codec not created, only `M` paid |
| `concurrent-small-window64` | 16 simultaneous `small-window64` decodes; success |
| `concurrent-blocks64` | 4 simultaneous `blocks-64m-at` decodes; success |

Boundary unit tests also cover zero content, count overflow combined with trailing data/checksum faults, all block types including zero-length RLE/compressed blocks, and `s` adjacent to every charge/block boundary. A reference decoder may reject an empty compressed block; Ricevanta still counts it before codec entry. Live Rust-to-Go writer tests on Linux must show all served writer profiles and size boundaries satisfy the cap; the writer's native qualification matrix still covers macOS ARM64, Windows x64 and Linux x64. Do not add Go interoperability jobs to the other native hosts. A failure blocks the profile change; it does not silently exempt an agent or relax the cap. Encoder compatibility, including output-only uploaders in the served release window, is **verify** until those tests pass.

`TestDecodeCostModel` is built with `//go:build !race`. The parent runs each of the 50 case keys in isolated limited and unlimited children with `GOGC=100` and `GOMEMLIMIT=off`. A child measures baseline `/memory/classes/total:bytes − /memory/classes/heap/released:bytes` after `runtime.GC()`, then sets `debug.SetMemoryLimit(baseline + N × Weight(w, s))`; for any case with no codec entry use `N × C` because only receive memory is reserved. Include the bounded compressed-buffer copy and preflight in measurements. Report separate preflight and decode CPU plus their sum, block headers visited, codec invocations, paid work charge, allocations, wall time, peak memory and `VmHWM`. Fixture construction is outside the timed interval. Run short cases repeatedly in the same isolated child with fresh per-request state and report per-request CPU, so timer resolution cannot erase their cost. Measure every error path with no retained provisional lines.

Require the expected lines or exact sentinel, zero `/gc/limiter/last-enabled:gc-cycle`, and peak total-minus-released at most 1.1 times the memory limit. Limited wall time must be at most twice the unlimited reference when the reference is at least 500 ms, otherwise at most reference plus 500 ms. No error case is exempt from memory or CPU checks. Each measured request's combined preflight/decode CPU must be at most `5 s × paid_charge / 64 MiB`, including GC: 9.765625 ms at `M`, 312.5 ms at 4 MiB and 5 s at 64 MiB. This is a qualification target on the recorded host/toolchain, not a platform-independent time guarantee. A failure blocks the gate and returns charges, limits or the ceiling to design review. The hostile/flat CPU ratio remains useful diagnostic output but cannot substitute for cost per paid charge.

On this target a device's sustained admitted/preflight-rejected work consumes at most `5 × 4.0625 / 64 = 0.3173828125` core, with up to 5 CPU-seconds of full-bucket burst; uncharged limiter calls, TLS and storage remain outside that equation. This is conditional on passing measurements for the whole required corpus and qualification hosts. The count of compromised devices needed to exhaust CPU is not established by the encoder-only measurements.

The limited child emits exactly one `COST_MEASUREMENT` line per case key, with repeated short runs aggregated; the unlimited child emits `COST_REFERENCE`, which never counts as a limited measurement. The parent rejects missing, duplicate, unknown or malformed measurements and ends with exactly one `COST_MODEL_CASES n=50`. With `RICEVANTA_COST_MODEL=full`, all 50 cases run when `TestDecodeCostModel` is selected; otherwise the test skips explicitly. `BenchmarkDecodeCost` reports time, bytes and allocations for accepted and rejected cases.

### 9.1. Selected-test proof composition

`ingest-cost-model` is one catalogue ID in `scripts/ci/targets.toml`, with mode `go-cost-model`, working directory `server`, package `./internal/events/body`, test `TestDecodeCostModel`, `cases = 50`, benchmark `BenchmarkDecodeCost`, and `operations = 3`. Pin `test_flags = ["-timeout=15m"]` and `benchmark_flags = ["-benchmem", "-benchtime=3x", "-timeout=15m"]`. The wrapper sets `GOENV=off`, `RICEVANTA_COST_MODEL=full` and `GOGC=100`; the test's children set `GOMEMLIMIT=off` before applying their own limit. Use the dedicated two-phase mode; do not combine benchmark events with selected-test events or allow benchmarks in generic selected runs.

The wrapper executes these discovery and payload commands sequentially from `server/`, retaining each command's stdout, stderr and exit status:

```sh
go test -list '^(TestDecodeCostModel)$' ./internal/events/body
go test -json -count=1 -timeout=15m ./internal/events/body -run '^(TestDecodeCostModel)$'
go test -list '^BenchmarkDecodeCost$' ./internal/events/body
go test -json -run '^$' -bench '^BenchmarkDecodeCost$' -benchmem -benchtime=3x -timeout=15m ./internal/events/body
```

The first phase requires exact test discovery in `github.com/ricevanta/ricevanta/server/internal/events/body`, a passing selected test and package, exit zero, and no benchmark events. Count only measurement records attributed to that package and `TestDecodeCostModel` or its passing subtests in Go JSON output. Require exactly 50 well-formed `COST_MEASUREMENT` records with `mode=limited`, one per expected `case`, and exactly one matching total. Reject missing, duplicate, unknown or malformed keys, including a duplicate replacing a missing case while the count stays 50. Neither stderr, unrelated test output, package-only output nor `COST_REFERENCE` supplies measurement proof. The Go parent validates every measurement field and numerical acceptance bound above; the wrapper independently validates record syntax (`key=value` fields, no duplicate/empty fields), mode and the exact case-key set.

The catalogue's `case_keys` contains these 34 encoder keys plus the 16 literal case keys in the section 9 table. For encoder keys, append `/N` to each shape in the following table for every listed N; the 16 adversarial keys have no appended suffix. Require 50 distinct entries. The wrapper compares against this catalogue, never a key list learned from the current test output; `check_policy.py` independently pins the exact set.

| Encoder shapes | N values |
|---|---|
| `flat-64x1MiB-single`, `arrayobjs-64x1MiB-single`, `singlechar-64x1MiB-single`, `random3-64x1MiB-single`, `round-2047x32769-single` | 1, 4 |
| `badid-10000-single`, `realistic-5000-win4` | 1, 8 |
| `dense-4x1MiB-win4` | 1, 16 |
| `nested-64x1MiB-single`, `dense-64x1MiB-single`, `densenested-64x1MiB-single`, `prefix-64x1MiB-single`, `numbers-64x1MiB-single`, `strings-64x1MiB-single`, `round-10000x5377-single`, `flat-10000x6710-single`, `minok-10000-single`, `realistic-2000-win4`, `realistic-10000-win4` | 1 |
| `flat-1x1MiB-single`, `flat-4x1MiB-single`, `flat-16x1MiB-single`, `flat-1x1MiB-win4`, `flat-4x1MiB-win4`, `flat-16x1MiB-win4`, `flat-64x1MiB-win4` | 1 |

Only after test verification succeeds does the wrapper run benchmark discovery and the benchmark payload. Require exact root discovery in the same package, exit zero and package pass, no tests, only `BenchmarkDecodeCost` and its sub-benchmarks, and exactly one correctly attributed result for each started leaf with exactly three iterations, positive finite `ns/op`, and valid bytes/allocation fields. A failed, skipped, missing or incomplete benchmark invalidates the whole ID even when all measurements passed. Preserve the generic selected-test and benchmark validators' separate rules.

Retain raw evidence separately for both phases. The wrapper writes decoded Go output and stderr from the test payload to `$RUNNER_TEMP/ingest-measurements/cost-model.log`, then appends decoded benchmark output and stderr, including failed-run diagnostics. Require a nonempty log. It writes `verified.json` only after both phases succeed, with the test summary (measurement count and validated keys), `summary.benchmark` (leaf results and three-iteration count), both discovery/payload command pairs, and the same `GITHUB_SHA`, `GITHUB_RUN_ID` and `GITHUB_RUN_ATTEMPT`. Start with fresh evidence so a failed retry cannot leave an earlier success eligible for a receipt. When `required.receipt` calls `run_selected.verified`, the cost-model record reader must also require mode `go-cost-model`, the exact package, command pairs, count/key set and successful benchmark summary with three iterations per leaf; a generic success envelope or test-only record is insufficient. A log cannot replace this composite proof.

The workflow invokes `python -B scripts/ci/run_selected.py --id ingest-cost-model --evidence "$RUNNER_TEMP/evidence"` unconditionally from the repository root. Keep the `if: always()` nonempty-log check and upload of `ingest-measurements-<runId>-<runAttempt>` with 30-day retention outside receipt directories. Shell `tee`/line counting is not the evidence verifier. `server-validate` includes `ingest-cost-model` in both workflow `CHECKS` and `inventory.py`; its receipt requires the composite verified record for the same tested commit, run and attempt under [CI hardening](ci-hardening.md).

The exact ordinary-suite skip allowance is package `github.com/ricevanta/ricevanta/server/internal/events/body`, test `TestDecodeCostModel`, reason `full ingest cost model runs separately without race instrumentation`, proof `ingest-cost-model`, modes `["server-unit", "server-race", "go-fuzz"]`. It permits only an observed skip of that exact test in those modes; it permits no missing discovered test, wildcard, subtest or skip in `go-cost-model`. The `!race` test's absence from race discovery needs no fabricated skip. The separate proof is required by `server-validate` in the same required CI run, even when an ordinary suite finishes before the dedicated proof; a skip by itself is never sufficient evidence.

`check_policy.py` must pin the ID, placement/mode, package/test discovery and payload commands, both timeouts, benchmark name/flags/iterations, 50-case count and exact key set, exact skip row, unconditional wrapper invocation, diagnostic log check/upload and `server-validate` check membership. Catalogue, wrapper and policy must agree; changing only the count to 50 is insufficient. The implementation plan lists negative tests for each boundary. No cost-model CI evidence is established by this document.

Before handler integration, qualify CPU and peak memory on supported server x64 and ARM64 configurations, including 64 KiB-page kernels. Exercise maximal occupancy at every supported budget/slot configuration with small, large-window, maximal-output and mixed frames, plus receive-only uploads. Record wall completion under contended CPU; each post-body request must complete decode and release within the 60 s deadline after allowing 2 s admission wait and 20 s storage. A write deadline cannot interrupt `DecodeFrame`. If the bound fails, a reviewed CPU concurrency limit or interruptible/isolated decode mechanism is required before integration. Separately measure transport memory, storage buffers and agent upload deadlines; none of these gates is discharged by the 50-case library test.

## 10. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: memory under ingest load is bounded by configuration that follows from the process memory limit; hostile batch shapes pay for what they cost while the agent contract and response bodies stay as specified; detections keep a memory reserve; an unmodified agent is never refused for its own rate and never sends a frame above the sealing limit, so either is evidence attributed to a device; every refusal carries a bounded, jittered `Retry-After` the agent already honours; the expanded model must pass the dedicated CI gate; the lean walker removes the allocation storm and cannot be hash-flooded.

Trade-offs: byte and slot reserves can leave capacity idle while nonpriority uploads retry; the block cap rejects some RFC-valid frames, with writer compatibility a required gate; large-window small frames spend more bucket credit even if their output is tiny; two admission phases and the additive `body` split; a request may wait up to 2 s before decoding; a maximal legitimate batch is charged 26.0 MB although realistic events retain under 10 MB, because `S` prices worst-case allocator rounding and `T` the walker's fixed state and per-line values; a process without a memory limit cannot run the `agent` role; the per-device rate is a protocol constant, so changing it changes agent and server together; the sort-based duplicate check spends about as much CPU as the token walk on flat key-dense lines.

Dependencies: the standard library, the existing `batch`, `wire` and `body` packages and the pinned `github.com/klauspost/compress` already in `licensing.md`. No new module: `golang.org/x/sync/semaphore` was considered and rejected because its single FIFO cannot express the class reserve and the per-device rules, and the limiter is about two hundred lines.

Limits: the weight bounds decoding, not the storage stage, whose buffers the ingest slice measures; CPU work is shaped per device and by the budget, without a CPU scheduler; so multiple compromised devices staying within the sealing limit and their buckets can consume a replica's CPU; the per-device CPU bound remains a qualification gate, with detections sharing CPU, with only the top-device log to attribute them; per-device state is per replica; HTTP/2 receive buffers and per-connection memory sit outside the budget, so the transport slice caps connections at about eight per device certificate per replica and measures the exposure; a link that cannot carry 16 KiB in 20 s cannot deliver a batch (events section 2.4); numbers are from one Linux x64 host and CI reproduces them on x64 `ubuntu-24.04` runners only, while server images also ship for `linux/arm64`, where the model is unmeasured, including on kernels with 64 KiB pages; `DecodeFrame` is not interruptible once started.

Alternatives: unlimited blocks with an output-only charge (rejected: empty blocks evade that charge); charging block count after an unlimited walk (rejected: preflight itself remains underpriced); lowering the 64 MiB window to match small content (rejected: changes independent window compatibility instead of charging it); reserving only decode bytes (rejected: receive-only uploads consume the reserve or every slot); a higher retry floor under partial occupancy (rejected: delays recovery without bounding hostile arrivals); a fixed concurrency count (rejected: a count admits either too few legitimate batches or too many hostile ones, since weights differ by 18 times); charging `Content-Length` (rejected: compressed size does not bound decoded size); charging the worst case for every request (rejected: admits six requests per gigabyte regardless of size); a queue of compressed bodies (rejected: it buffers 5 MB per queued request before knowing the decode cost and still needs this budget); per-device CPU accounting (rejected: it measures after the fact, while declared work and block limits are available before decoding; their CPU envelope still requires qualification); metering the agent's bucket in compressed bytes (rejected: realistic events compress about 31 times, so the server could not bound decoded work without refusing unmodified agents); lowering EV-09's ceilings (rejected for this design, section 7).

## 11. Sources

- [Go garbage collector guide, memory limit](https://go.dev/doc/gc-guide); [`runtime/debug.SetMemoryLimit`](https://pkg.go.dev/runtime/debug@go1.27.1#SetMemoryLimit); [`runtime/metrics`](https://pkg.go.dev/runtime/metrics@go1.27.1) for `/gc/heap/live:bytes`, `/gc/heap/allocs:objects`, `/memory/classes/total:bytes`, `/memory/classes/heap/released:bytes` and `/gc/limiter/last-enabled:gc-cycle`; Go 1.27.1 [size classes](https://github.com/golang/go/blob/go1.27.1/src/internal/runtime/gc/sizeclasses.go) and their [generator's waste rules](https://github.com/golang/go/blob/go1.27.1/src/runtime/_mkmalloc/mksizeclasses.go).
- [`net/http`](https://pkg.go.dev/net/http@go1.27.1): `ResponseController.SetReadDeadline` and `SetWriteDeadline` (a passed deadline is not extended), `Request.Context`, `HTTP2Config`, `ErrAbortHandler`; Go 1.27.1 `net/http/server.go`, where a handler that returns without a header gets an implicit 200 (`finishRequest`) and `ReadHeaderTimeout` also bounds the TLS handshake (`tlsHandshakeTimeout`).
- [`slices`](https://pkg.go.dev/slices@go1.27.1#SortFunc) and its [pdqsort source](https://github.com/golang/go/blob/go1.27.1/src/slices/zsortanyfunc.go); [`sort.Sort`](https://pkg.go.dev/sort@go1.27.1#Sort) for the documented O(n log n) bound.
- [RFC 9110 section 10.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3) (`Retry-After`, delay-seconds), [section 15.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.6.4) (503), [section 15.5.14](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.14) (413); [RFC 6585 section 4](https://www.rfc-editor.org/rfc/rfc6585.html#section-4) (429).
- [RFC 8878 section 3.1.1.1.2](https://www.rfc-editor.org/rfc/rfc8878.html#section-3.1.1.1.2) (Window_Descriptor); [klauspost zstd v1.20.1 `framedec.go`](https://github.com/klauspost/compress/blob/v1.20.1/zstd/framedec.go) and [`history.go`](https://github.com/klauspost/compress/blob/v1.20.1/zstd/history.go) for the history allocation rule.

## 12. Unresolved questions

No owner policy choice remains open. Block limits, work charging, receive reserves, independent rate evidence and retry floors are selected here. The unmeasured CPU, writer compatibility, ARM64, transport, storage and upload gates above remain implementation blockers, not permission to weaken the bounds. Independent design review must approve the revised spec and plan before code changes.
