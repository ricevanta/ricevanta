# DLP design

How Ricevanta classifies content and decides data movement: the scanner helper `ricevanta-scan`, the detectors, content fingerprints, the classification catalogue, the channel decision logic, the warn interaction, the exact-byte contract for newly written content, evidence, exfiltration detection and the memory DLP adds. The feature list is `../blueprint.md` section 3.3. The enforcement points, browser gating, clipboard mediation and their OS mechanisms are in `agent.md` section 3, `extensions.md` section 7 and the capability matrix in `../platform-support.md`; this file links them and does not restate them. Detector formats are in `../specs/rule-adapters.md` sections 5 to 7; the built-in validators, the Vietnamese and financial recognizers, confidence combination and redaction masks are in `../specs/dlp-detectors.md`. Decisions: DLP-01 to DLP-08, AG-02, AG-06, EXT-03, EXT-06, LIN-01, POL-02, BE-02 and SH-01 in `../decisions.md`; conflicts C4 and C5 in `../analysis.md`. Section 10 names both settled inputs and required enforcement mechanisms that remain release blockers. Claims marked "verify" rest on a secondary source or were not confirmed on a first-party page.

## 1. Pipeline

| Stage | Where | Output |
|---|---|---|
| Trigger | Enforcement point (`agent.md` section 3) | An authorization or notification event on a channel, with an open descriptor or handle for content decisions |
| Rule-only decision | Enforcement point | Allow or deny from path, process, signer, destination-kind and uid rules (`../specs/policy-envelope.md` section 2.2) |
| Context | Core `dlp` module | Application, user, session, destination, device state (section 6.1) |
| Classification lookup | Core | Cached result by file identity or content hash (section 2.6), the lineage-inherited label (section 5.3) |
| Scan | `ricevanta-scan`, then `ricevanta-ext` for extension parsers and classifiers | Detected type, extracted text, matches with offsets and confidence, coverage state |
| Classification | Core | Categories, label and confidence (section 5) |
| Decision | Core | Policy evaluation (section 6.2) and the action, including warn through `ricevanta-session` (section 6.3) |
| Evidence | Core | `data_security_finding` with DLP-02 evidence (section 7) |

The core scans only when an in-scope enforcing or monitoring policy on that channel and destination names detectors and no cached result exists. Opens that no DLP policy covers never reach the core.

## 2. Scanner helper `ricevanta-scan`

### 2.1 Process, privilege and lifecycle

The core starts `ricevanta-scan` on the first content request, keeps it for 60 s after the last request and then stops it, so its idle footprint is zero (AG-02, `agent.md` section 6). At most one scanner process runs; it uses at most two worker threads by default (a policy value), runs synchronous decisions at normal priority and background scans (section 6.4 and at-rest discovery) at background priority (`nice` 10 on Linux, below-normal priority class on Windows, utility QoS on macOS). The scanner never opens a path: it reads only the descriptor or handle the core passes over the IPC channel of `agent.md` section 4, and writes nothing to disk.

| OS | Privilege reduction | Memory cap (256 MB default) |
|---|---|---|
| macOS | Dedicated hidden service user; App Sandbox entitlement with no file, network or device entitlement, so only passed descriptors are readable (verify that a launchd-spawned sandboxed helper reads passed descriptors) | No hard per-process cap exists; the core samples `phys_footprint` every 100 ms during a scan and kills the helper above the cap |
| Windows | AppContainer token with no capabilities, handles duplicated into the process | Job object with `JOB_OBJECT_LIMIT_PROCESS_MEMORY` and kill-on-close |
| Linux | Dedicated system user, `no_new_privs`, a seccomp allow list without `open` family calls, and a Landlock ruleset with no filesystem rights where the kernel has Landlock | cgroup v2 `memory.max` and `pids.max` on the helper's own cgroup |

On every OS the Rust global allocator accounts allocations and refuses work above 90 % of the cap, so a large document ends as `truncated` with reason `memory` before the OS cap kills the process. PDFium and Tesseract allocate outside the Rust allocator, which is why the OS cap and the footprint sample remain the hard bound. A kill or crash follows the retry and `closed` rule of AG-06.

### 2.2 File-type detection independent of extension

1. Magic numbers: the `infer` crate plus an in-project table that sub-types containers (OOXML by `[Content_Types].xml`, ODF by its `mimetype` member, OLE compound files by stream names, email by header grammar).
2. Magika for content without a reliable signature (source code languages, structured text, scripts): the `standard_v3_3` model (3.16 MB, 216 output types) reads the first and last 1,024 bytes; inputs under 8 bytes skip the model ([config](https://github.com/google/magika/blob/main/assets/models/standard_v3_3/config.min.json), [input.rs](https://github.com/google/magika/blob/main/rust/lib/src/input.rs)). The model runs on `tract-onnx` (pure Rust), the runtime Magika's own main branch has moved to, instead of the published `magika` 1.1.0 crate, which links ONNX Runtime through `ort`; the scanner switches to the `magika` crate once a release on `tract` is published.
3. The file extension never selects a parser. A mismatch between extension and detected type is recorded as `type_mismatch` on the finding and is a CEL-visible signal (section 8), which covers renamed content (`../specs/platform-qualification.md` section 5).

The Magika repository is Apache-2.0, but the model directory carries no license file of its own, so whether the weights are under Apache-2.0 is the open fact `../analysis.md` section 4 records; the model is not shipped until it is confirmed. Until it ships, in-project heuristics classify text types (shebang lines, language keywords and structural grammars for JSON, XML, CSV, YAML and common source languages), and content with no reliable signature otherwise takes the string sweep of section 2.3.

### 2.3 Extraction per format

| Format | Library | License | Notes |
|---|---|---|---|
| PDF | PDFium through `pdfium-render`, PDFium built in-project | BSD-3-Clause; crate MIT or Apache-2.0 | Text with positions; renders every page for OCR regardless of its text layer (section 2.4) |
| OOXML (docx, pptx) | `zip` and `quick-xml`, extraction in-project | MIT; MIT | Body, headers, footers, comments, notes, tracked changes, embedded objects recursed as members |
| Spreadsheets (xlsx, xlsb, xls, ods) | `calamine` | MIT | Cell text row by row, which keeps row structure for record detection (`../specs/dlp-detectors.md` section 5) |
| Legacy Word and PowerPoint (doc, ppt) | `cfb` plus in-project readers for the [MS-DOC] piece table and [MS-PPT] text atoms | MIT | Word 6 and 95 files fall back to the string sweep below |
| ODF (odt, odp) | `zip` and `quick-xml` | MIT | `content.xml` and `styles.xml` |
| RTF | `rtf-parser` | MIT | Embedded objects extracted and recursed |
| HTML, XML | `html5ever`; `quick-xml` | MIT or Apache-2.0; MIT | Text nodes plus `alt`, `title` and form values; script and style bodies go to the secrets detectors only |
| Email (eml, mbox, msg) | `mail-parser`; `msg_parser` | Apache-2.0 or MIT; MIT | Headers, bodies and attachments recursed as archive members |
| Images (PNG, JPEG, TIFF, BMP, WebP, HEIC where the OS decoder exists) | Tesseract 5 with the `tessdata_fast` `vie` and `eng` models, built through `tesseract-rs` | Apache-2.0; crate MIT; Leptonica BSD-2-Clause (verify) | Section 2.4 |
| Archives and compression | `zip`, `tar`, `flate2`, `bzip2`, `liblzma`, `zstd`, `sevenz-rust2` | MIT; MIT or Apache-2.0; MIT or Apache-2.0; MIT or Apache-2.0; BSD-3-Clause; Apache-2.0 | Section 2.5 |
| Source code, plain text, CSV, JSON | In-project, with `chardetng` and `encoding_rs` | Apache-2.0 or MIT; (Apache-2.0 or MIT) and BSD-3-Clause | Encoding detected on the first 64 KiB; UTF-16 by byte-order mark |
| Any other binary | In-project string sweep | | Runs of at least 6 printable characters in UTF-8, UTF-16LE and the detected legacy encoding, so an unknown container still reaches the detectors |

Extracted text is normalized to Unicode NFC and carries an offset map back to source bytes, which evidence uses (section 7). Text per object is capped at 16 MB (the parser cap of `../specs/extension-agent-runtime.md` section 2); beyond it the result is `truncated`. RAR is not extracted: the only Rust reader embeds UnRAR, whose license forbids building RAR-compatible archivers and is not an open-source license, so RAR archives end as `unsupported` (section 2.5) and policies decide on them. Formats the built-in scanner does not extract can be assigned to an extension `parser` module (`../specs/extension-agent-runtime.md` section 3).

Rejected: MuPDF (AGPL-3.0); `pdf-extract` alone, whose text fidelity on non-Latin encodings is unproven (verify) and which cannot render pages for OCR; `undoc`, `office_oxide` and `rwml` for legacy Office, which are young and unverified, so they serve as test oracles only; `ocrs`, whose model weights are CC-BY-SA-4.0 and which has no Vietnamese model; Apache Tika, which is Java (C4).

### 2.4 OCR

OCR inspects images and the rendered visual content of every PDF page, including pages with native, incomplete or misleading OCR text layers. PDFium renders pages to bitmaps ([public API](https://pdfium.googlesource.com/pdfium/+/refs/heads/main/public/fpdfview.h)); a text object never suppresses the page's OCR work. The scanner runs detectors over both text-layer and OCR results, maps matches to page coordinates, and deduplicates the same detector and normalized value at the same page region before confidence aggregation. Distinct regions retain their evidence.

The scan plan fixes rendering resolution and preprocessing. Images above 20 megapixels are downscaled; OCR has a budget of 10 s per object or PDF page and 30 s per scan. The coverage ledger records text extraction, rendered-page OCR and each skipped or unfinished page or image. Exhausting a render, text, memory or OCR budget returns `truncated` with the affected coverage and reason, never `complete`. A synchronous decision waits for OCR only with `ocr: sync`; otherwise it uses a result for the same scan plan or returns `pending_ocr`, and the hold point of section 6.4 or a background scan completes the work. Handwriting and low-resolution photos have unmeasured recall, so first-party packs treat OCR matches at reduced confidence (`../specs/dlp-detectors.md` section 6).

### 2.5 Archive and nesting bounds

| Bound | Default | On reaching it |
|---|---|---|
| Nesting depth (archive in document in archive) | 8 | `truncated`, reason `depth` |
| Members per scan | 10,000 | `truncated`, reason `members` |
| Decompressed bytes per scan | 2 GiB, streamed, never held whole | `truncated`, reason `bytes` |
| Expansion ratio per member | 200:1 after the first 1 MiB | `truncated`, reason `ratio` (decompression bomb) |
| Encrypted member or document | | `encrypted`; no password guessing |

Every scan returns a `coverage` state, `complete`, `truncated` (with reason), `encrypted`, `corrupt`, `unsupported` or `pending_ocr`, and CEL sees it as `match.coverage`, so a policy can block what it could not inspect instead of treating it as clean. The bounds are policy values.

### 2.6 Cache

Results are keyed by the content's BLAKE3 hash and byte length plus a canonical scan-plan digest. The digest is SHA-256 over [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) JSON after defaults are explicit and unordered sets are sorted. The plan binds every input that can change extraction, matches or coverage:

- Scanner and built-in parser build digests, type model digest, normalization version and selected parser mappings.
- Immutable detector and fingerprint pack digests, selected rule identities, detector parameters and classification configuration.
- Each selected extension parser or classifier's package digest, component and artifact digest, interface version, configuration and `(recovery_epoch, grant_generation)` from the installed bundle (`../specs/policy-envelope.md` section 6). A grant restored to equal capabilities still has a new generation.
- Extraction formats, text and nesting limits, rendering resolution, OCR mode, engine and trained-data digests, languages, preprocessing and all work, memory and time bounds.
- The accepted organization `recovery_epoch`, including scans with no extension component.

The core freezes the plan before scanning and requires the same current plan and component generations before accepting a result or releasing a verdict. A change discards stale in-flight output and scans under the new plan. A cache entry is reusable only for an equal digest and coverage that satisfies the current request; incomplete results retain their exact coverage and cannot suppress unfinished work or become clean results. The cache stores matches and bounded coverage summaries, not extracted text or a context-dependent final policy verdict. The core recomputes policy conditions, exceptions and lineage inheritance for each decision.

The core holds the 4,096 most recent results in memory and up to 100,000 in `state.db`; a plan change makes old entries ineligible. A second map from file identity (`lineage.md` section 2) plus size and change counter (APFS inode and modification time, the Windows file ID with the USN, the Linux inode with `i_version` or ctime) to content hash avoids rehashing unchanged files; a close-after-write notification removes the hint.

File metadata is a lookup hint, not authorization to release bytes. A content allow requires the immutable snapshot and generation exclusion of section 6.4; a later close notification cannot repair a stale verdict used during an open write or mapping mutation.

### 2.7 Time bounds

A synchronous scan runs within the policy deadline (default 2 s) under AG-06. A background scan has a 30 s budget per object. YARA-X runs with `Scanner::set_timeout` set to the remaining budget ([docs.rs](https://docs.rs/yara-x/latest/yara_x/struct.Scanner.html)); YARA-X offers no memory limit of its own, which the process cap covers. Cold start (process launch, model load, rule deserialization) has a target of 300 ms at the 99th percentile, measured by the footprint benchmark (AG-09), and counts against the deadline of the decision that started it.

## 3. Detectors

| Kind | Format and home | Use |
|---|---|---|
| Recognizers: pattern, context words, validator | `pii` packs, `../specs/rule-adapters.md` section 6; validators and first-party recognizers in `../specs/dlp-detectors.md` | Personal identifiers, financial data, customer records |
| Secrets: pattern, keywords, entropy, allow lists | `secrets` packs, `../specs/rule-adapters.md` section 7 | API keys, tokens, private keys, connection strings |
| YARA-X rules over raw bytes and over extracted text | `yara` packs, `../specs/rule-adapters.md` section 5 | Confidential-document structures and markings, file structures |
| Keyword and dictionary lists | `dictionary` packs, `../specs/dlp-detectors.md` section 4 | Project code names, document markings, financial vocabulary |
| Content fingerprints | `fingerprint` packs, section 4 | Registered confidential documents and source trees |
| Extension classifiers | `classifier` modules (EXT-03) | Anything the formats above cannot express |

YARA-X runs twice per object: once over raw bytes for structure, once over the extracted text for markings, with rule metadata `scope: raw | text | both`. Source code is a classification from the detected type (Magika's language types) plus organization markers (internal package names, copyright headers, repository fingerprints) and the secrets detectors; first-party packs cover the initial emphasis of `../blueprint.md` section 3.3: source code, API keys, customer information, Vietnamese personal identifiers and financial data. Confidence per match and per document follows `../specs/dlp-detectors.md` section 6.

## 4. Content fingerprints and partial matching

| Method | Computed over | Answers |
|---|---|---|
| Exact | BLAKE3 of the raw bytes, and BLAKE3 of the normalized text | Identical file; identical text in another container (a PDF exported from a registered docx) |
| Similarity | TLSH (`tlsh2`, 128 buckets) over the normalized text, at least 50 bytes ([TLSH README](https://github.com/trendmicro/tlsh)) | An edited revision of a whole registered document |
| Partial | Winnowed character shingles over the normalized text | An excerpt of a registered document inside other content |

Normalization for all three: NFC, Unicode case folding, every run of non-letter and non-digit characters replaced by one space. Diacritics are kept, since removing them merges distinct Vietnamese words.

Partial matching follows winnowing ([Schleimer, Wilkerson and Aiken](https://theory.stanford.edu/~aiken/publications/papers/sigmod03.pdf)): a 64-bit Rabin-Karp rolling hash over every k-gram of k = 50 characters, and the minimum hash in each window of w = 30 consecutive hashes selected. Any passage of at least t = k + w - 1 = 79 normalized characters shared with a registered document yields at least one shared fingerprint, and about 2/(w+1), 6.5 %, of positions are selected, so a 30,000-character document carries about 1,900 fingerprints. Stored fingerprints are keyed BLAKE3 hashes of the selected values, truncated to 64 bits, under a per-organization fingerprint key, so a leaked index cannot be tested against guessed text without the key; the key reaches agents in the bundle and so protects backups and exports, not a compromised endpoint.

Default partial-match threshold: 12 shared fingerprints after boilerplate removal, which corresponds to about 240 characters of shared text, two or three sentences. Confidence rises with the shared count: 0.9 at 12, 0.95 at 24, 0.99 at 48 and above. A set may also require `min_containment`, the share of the registered document's fingerprints found (default off). The TLSH default threshold is a distance of 50 or less at confidence 0.9; Trend Micro publishes detection and false-positive rates per distance only in the TLSH paper's tables (verify the rate at 50 there). Fingerprints that occur in 10 or more registered documents, or in the operator's template corpus (letterheads, legal boilerplate), are removed at compile time.

Registration: an operator creates a fingerprint set through `/api/v1` (console, CLI or GitOps) and uploads documents or archives of them, including a source tree. `jobs` runs the same `ricevanta-scan` binary, built for the server image's architectures, as a subprocess under the same caps and under a dedicated uid with no network, no inherited environment or credentials, and the Linux restrictions of section 2.1, so extraction and normalization are byte-identical on both sides. The output is a `RulePack` of format `fingerprint`: a sorted array of 12-byte entries (fingerprint, document index), the TLSH digests and the exact hashes. The pack carries a document index and the set uid only; names, labels and categories resolve on the server when a finding is displayed. Publishing it follows the rule-pack lifecycle and is a protected action (BE-02, `policy.md` section 6). Uploaded originals stay in the blob store under envelope encryption (BE-06) until the set is deleted, because a normalization change in a later scanner release requires recomputing; an operator can choose to discard them after fingerprinting and re-upload on such a change.

Matching runs in the scanner: it computes the content's fingerprints with the same parameters, looks each up by binary search in the memory-mapped index and counts shared fingerprints per registered document; TLSH digests are compared linearly (35 bytes each). The index counts against the scanner cap; the compiler refuses a scope whose fingerprint packs exceed 64 MB in total (about 5.6 million fingerprints, roughly 2,900 documents of 30,000 characters), a policy value bounded by the 256 MB cap.

Tuning: a new set runs in `mode: monitor` first; the console shows the distribution of shared counts and TLSH distances per registered document from the monitor findings, and the operator adjusts `min_shared`, `min_containment` and the TLSH distance per set. Raising a threshold on an enforcing set is a weakening change (`../specs/policy-envelope.md` section 2.3).

## 5. Classification catalogue

### 5.1 Categories and labels

The catalogue is server data owned by the `dlp` module (BE-04) and compiled into the bundle. A category has an id, a sensitivity label, a default `minConfidence` and an optional free-text `reference` the organization fills (DLP-03); a detector rule names its category. First-party categories:

| Category | Label |
|---|---|
| `pii.vn.basic` (personal identification number, CMND, passport, phone, social and health insurance numbers) | confidential |
| `pii.vn.sensitive.id_image` (images of căn cước, CCCD or CMND cards) | restricted |
| `financial.card` (card number, expiry, CVV, track data) | restricted |
| `financial.account` (bank account, transaction history, credit and securities data) | restricted |
| `customer.records` (bulk records combining identifier types) | restricted |
| `secret.credential`, `secret.private_key` | restricted |
| `source_code`, `source_code.org` | confidential |
| `confidential.marked`, `confidential.registered` (markings, fingerprint sets) | per set, default restricted |

Labels are ordered `public < internal < confidential < restricted`; an organization adds categories and labels, and `match.classification` is the highest label among matched categories at or above their `minConfidence`.

### 5.2 Organization rules and exceptions

Organization-specific rules are packs of the formats in section 3, authored in the console or GitOps. Exceptions use the `Exception` resource (`../specs/policy-envelope.md` section 3): a scope and a condition over the DLP variables, for example a finance group uploading to the organization's SharePoint tenant. Value-level exclusions (test card numbers, the organization's own tax code, sample identifiers in documentation) are invalidator lists inside the pack and narrow one detector without exempting a policy. Both kinds of change are weakening changes when they reduce enforcement.

### 5.3 Inheritance through lineage

A content revision's effective classification is the higher of its scan result and its durable sensitivity floor (`lineage.md` section 3). A derived revision (copy, extraction, archive, save-as) inherits the highest source label when edge confidence is at least 0.8 (a policy value). The floor and compact justification persist independently of edges, summary retention and detector-cache invalidation. Busy-process compaction preserves the maximum source floor while lowering confidence in the provenance assertion; pressure cannot lower the effective label. Inheritance classifies unreadable content, including an encrypted archive built from restricted sources. CEL exposes the source revision and content hash when known in `match.inherited`; evidence names the floor and justification. Lowering the floor requires the approved reclassification of `lineage.md` section 3.

## 6. Channel decisions

### 6.1 Context

| Context | Source | CEL |
|---|---|---|
| Application | Process path, signer, bundle or package id from the enforcement point event | `event.actor.process` |
| User and session | Login session, interactive or remote (`agent.md` section 2, `Session`) | `user`, `session` |
| Destination | Removable volume (vendor and product id, serial, encrypted), cloud sync client and account, browser host and tab URL, network host, clipboard consumer where the OS names it | `destination` |
| Device state | Compliance, labels, groups | `device` |
| Content | Classification, categories, confidence, distinct match count, coverage, inheritance | `match` |
| Recent activity | Per-user sliding-window counters (section 8) | `activity` |

Removable media are identified at mount through IOKit and Disk Arbitration on macOS, the device instance path in the driver on Windows, and udev properties on Linux. Cloud sync folders come from each client's own configuration (OneDrive account folders, `~/Library/CloudStorage/` File Provider domains on macOS, Dropbox `info.json`, Google Drive for desktop, iCloud Drive, Nextcloud; verify each location per client and OS); `destination.managed` is true when the account's tenant is in the operator's managed-tenant list.

### 6.2 Evaluation order

1. Ricevanta's own processes are excluded (`agent.md` section 3).
2. The conflict plan selects in-scope policies for the trigger and evaluates point predicates. A point finishes only when unresolved core policies and exceptions cannot change the global decision or actions (`policy.md` section 3.2).
3. The core evaluates context predicates, including policies without detectors. Context-only exceptions may remove their policy when all inputs exist. An exception error grants no exemption and raises policy health.
4. When a remaining policy or exception needs content, classification combines a valid cache result and the durable sensitivity floor, then scans within the earliest required deadline. A detector-free policy using `match` needs the scope's classification catalogue; otherwise no scan is required.
5. Evaluate `minConfidence`, each remaining CEL condition and its content-dependent exceptions against this operation's results. Select the highest matching priority across both placements, with the strictest action at equal priority. `monitor` policies record without voting. With no matching enforcing policy, allow is the default.
6. Apply the action (section 6.3), evidence (section 7) and activity counters (section 8).

A missed deadline, a throttled check or an unavailable helper applies the policy's fail mode (AG-06). A second deadline miss on the same content hash within 24 hours applies `closed` and raises an alert, as a repeated scanner crash does. An incomplete `coverage` is not a failure: it is data the condition can test.

### 6.3 Actions and the warn interaction

`allow`, `block`, `alert` and `redact_clipboard` follow `../specs/policy-envelope.md` section 4; `mode: monitor` records the outcome. `warn` asks the user through `ricevanta-session`: a dialog with the policy's message (localized), the classification label and destination, `Cancel` and `Continue`, and a justification field that the policy marks `required`, `optional` or `none`. Parameters: `timeout` (default 60 s; expiry means `Cancel`), `justification`, `message`, and `unattended` (`block` by default, `allow`), which applies when no interactive session helper can be reached, for example a service account, an SSH session or a locked screen. The interaction depends on whether the hold point can wait for a person:

| Channel | Interaction |
|---|---|
| Browser through a connector | The core holds the verdict while the dialog runs, bounded by the request's `expires_at` ([analysis.proto](https://github.com/chromium/content_analysis_sdk/blob/main/proto/content_analysis/sdk/analysis.proto)); Firefox's `AgentTimeout` is written as the warn timeout plus the deadline. With less than 10 s left and `justification` `none` or `optional`, the core returns the protocol's `WARN` verdict, the browser shows its own warning and the acknowledgement's `final_action` records the user's choice without a justification; when `justification` is `required` and the dialog cannot complete, the verdict is `BLOCK` |
| Browser through the content-script gate | The content script holds the event until the dialog answers; release also requires a qualified gate that binds the verdict to one exact-byte transfer |
| Clipboard, paste | Deny then approve only on a qualified owner path that mediates each read. `Continue` permits one later request for the same content hash and consumer when the OS identifies it, or the next request when it does not. Windows and macOS have no qualified per-read mechanism, so their warn and block clipboard actions remain release blockers (sections 6.5 and 10). |
| File open, write, copy, removable media, cloud sync, print spool | On a qualified exact-byte gate, deny then approve: the operation fails, the dialog opens, and `Continue` grants a one-time allowance bound to immutable content hash, length and generation, process identity, destination and user for 60 s. The gate consumes the allowance atomically on retry; changed bytes require a new decision. The unresolved file mechanism remains a release blocker |

Choices, justifications and timeouts are recorded as `policy_activity` and `data_security_finding` events; offline they spool like every event and the local decision does not wait for the server. Qualified file-system channels use deny then approve (`../specs/policy-envelope.md` section 4): no OS deadline is held open for a person. A dialog alone does not qualify a blocked channel.

### 6.4 Exact-byte file gate

The file gate has one acceptance contract for removable media, cloud sync folders, network shares, browser downloads and policy-named paths:

1. A write makes the file identity dirty before another process can read the changed bytes. Readers through a descriptor opened before the write, a duplicated descriptor, direct I/O or an existing mapping are covered as well as later opens.
2. The scanner reads an immutable snapshot. The verdict binds its BLAKE3 hash, byte length, file identity and change generation.
3. Release succeeds only if the bytes at the destination still match that tuple. A concurrent truncate, write, replacement or mapping fault keeps the object dirty and causes a new scan or the policy fail mode. A cached verdict never authorizes a later generation.
4. A create or write to removable media or a network share holds newly produced bytes locally until that contract permits release. Classification inferred from the writer's lineage may deny early, but it cannot authorize unscanned bytes.

The existing OS hooks do not yet implement that contract. Endpoint Security has authorization events for open and mapping but no selected mechanism that contains reads from an already open descriptor after a later write. A Windows minifilter can observe read, write and section creation, and Linux Security Module hooks can recheck descriptor reads and new mappings, but neither platform design specifies an immutable staging transaction or the treatment of mappings that already exist. Close-after-write followed by a held next open therefore remains useful telemetry, not proof of prevention. Deleting a blocked file after a removable write or scanning typed network-share content after close is remediation and is not a supported block.

Full file-channel blocking remains a v1.0.0 release blocker. The platform design must choose and qualify a staging or read and mapping mediation mechanism on each OS. Qualification must include descriptors and mappings opened before the writer, concurrent writes and truncates, direct I/O, a writer that never closes, an unmount or device removal during a verdict, and byte substitution between scan and release (`../specs/platform-qualification.md` section 5). No `Unsupported` result or alert-only fallback satisfies SH-01.

### 6.5 Channels decided elsewhere

Clipboard mediation, browser gating, print at the spool and downloads are mechanisms of `agent.md` section 3; per-browser policy and pins come from `extensions.md` section 7. This file adds what those sections leave open:

- Connector registration: the core serves one `content_analysis_sdk` agent created with `user_specific: false` ([analysis_agent.h](https://github.com/chromium/content_analysis_sdk/blob/main/agent/include/content_analysis/sdk/analysis_agent.h)). Chrome and Edge connector entries set `service_provider: local_system_agent` on every OS where the adapter declares a connector ([Chromium policy](https://chromium.googlesource.com/chromium/src/+/main/components/policy/resources/templates/policy_definitions/Miscellaneous/OnFileAttachedEnterpriseConnector.yaml), [Edge policy](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/onfileattachedenterpriseconnector)); Firefox sets `IsPerUser: false` and `PipePathName` to the same agent name ([policy templates](https://mozilla.github.io/policy-templates/#contentanalysis)). Chrome pins the agent through `verification`; Edge documents no pin, so the agent creates its pipe as the first instance with a SYSTEM-only creator ACL on Windows and its socket in a root-owned directory on macOS, and only an administrator, who is outside the tamper boundary of `agent.md` section 9, can bind the name first. Chrome's `require_justification_tags` stays unset, because the justification comes from the session dialog.
- Chromium fallback contract: Chrome without Chrome Enterprise Core on macOS, Windows and Linux, and Edge on Linux, use content-script and blocking `webRequest` candidates. `webRequest` exposes WebSocket and WebTransport handshakes, not established-session messages ([Chrome documentation](https://developer.chrome.com/docs/extensions/reference/api/webRequest)). The required gate must mediate each exact-byte send from pages and workers, including an established session, or use a qualified restriction that prevents those channels carrying uninspected bytes. Handshake cancellation and intercepted DOM events do not prove that contract. Upload and paste blocking through these fallback adapters remains a v1.0.0 release blocker; an unrelated allow never authorizes later messages.
- Safari content-script gate: the content script can hold the DOM events it sees and stream their bytes to the native handler. It does not control page or worker network APIs. Apple's documented `declarativeNetRequest` conditions match URL and resource metadata, including the `websocket` resource type, but expose no request body or transfer identifier ([Apple documentation](https://developer.apple.com/documentation/safariservices/blocking-content-with-your-safari-web-extension)). A destination allow rule therefore cannot prove that the sent bytes are the inspected bytes, and a timed tab or destination allowance is forbidden. The required gate must bind one verdict to the exact bytes and one network transfer across file picker, drag and drop, paste, form submission, `fetch`, `XMLHttpRequest`, `sendBeacon`, workers and WebSocket messages, including a socket opened before the decision. No such Safari mechanism is established, so Safari upload and paste blocking are a v1.0.0 release blocker. TLS interception remains rejected.
- Clipboard contract: a blocked clipboard item must remain unreadable until its verdict, and every read after the verdict must receive its own decision or consume a one-use allowance. Re-owning after notification cannot protect a reader in the interval. Windows delayed rendering sends `WM_RENDERFORMAT` only while a format has no rendered handle; `SetClipboardData` then places a handle that later callers retrieve without another owner callback ([Microsoft documentation](https://learn.microsoft.com/windows/win32/dataxchg/clipboard-operations)). A macOS [promised-data provider](https://developer.apple.com/documentation/appkit/nspasteboarditemdataprovider) supplies a type on request, but no documented callback authorizes every subsequent read. X11 `SelectionRequest`, `ext-data-control-v1` and the GNOME owner path remain candidate per-request mechanisms; their watcher-then-re-own design also leaves first-read exclusion unresolved. Clipboard blocking remains a v1.0.0 release blocker on every required session until the native design passes the first read, allowed first read followed by denied second reader, simultaneous readers, every advertised format, history and cross-device cases.
- macOS pasteboard access: no managed setting pre-approves reads; the `com.apple.TCC.configuration-profile-policy` payload lists no pasteboard service ([schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.TCC.configuration-profile-policy.yaml); [forum 794560](https://developer.apple.com/forums/thread/794560)). Qualification must record the user-granted access state needed by any candidate helper, but that state does not provide a per-read hook.
- GNOME selection ownership: the GNOME Shell extension subclasses `MetaSelectionSource`, a derivable type whose `get_mimetypes`, `read_async` and `read_finish` are virtual ([meta-selection-source.h](https://gitlab.gnome.org/GNOME/mutter/-/blob/main/src/meta/meta-selection-source.h)); on owner change for the clipboard and primary selections it copies the offered types within the payload bound and sets its own source as owner, and its `read_async` asks `ricevanta-session` over the session D-Bus before returning a stream (verify that GJS can implement these virtual functions asynchronously). Each side checks the other's executable through the connection's process id. The extension installs system-wide and is enabled through a locked dconf key; its `shell-version` lists only qualified GNOME releases, so an unqualified release loads no extension and the helper reports unavailable. The requesting client is not identified.

## 7. Evidence

Stored and exported (DLP-02): content hash, rule id, category, label, confidence, byte offsets into the source, coverage, inheritance source, the decision and fail mode applied, and the redacted snippet of at most 200 characters when the policy allows it. The snippet comes from the extracted text around the match; every detector match inside the window is masked by its type's rule (`../specs/dlp-detectors.md` section 7), not only the triggering one. TLSH digests of classified content leave the device for cross-device lineage joins.

Never leaves the device: raw content, extracted text, OCR text beyond the snippet, unmasked match values, the content's own winnowing fingerprints, clipboard contents and files streamed from the browser. Script content follows `../specs/ocsf-profile.md` section 3.

## 8. Exfiltration detection

| Behaviour | Agent, single device | Server |
|---|---|---|
| Volume to removable media | `activity.removable_bytes_1h` and `activity.removable_files_1h` of classified content per user | Cross-device totals per user |
| Burst of uploads | `activity.uploads_10m` and `activity.upload_bytes_10m` | Bursts across devices and destinations |
| Archive then transfer | An archive inheriting a label (section 5.3) transferred within 30 minutes of creation | Joined with process and network telemetry |
| Channel switching | `activity.blocked_10m`: a block followed by another channel's attempt for the same content hash | Repeated patterns over days |
| Masquerading | `type_mismatch` on a transferred file | |

Counters live in `state.db` in one-minute buckets per user and channel class, a few kilobytes per user, so policies can block on them offline. Longer windows and cross-device correlation run in the server's correlation engine over `data_security_finding` events, specified with EDR in `edr.md`. Default first-party detections: 100 MB or 50 classified files to removable media in one hour, 20 classified uploads or 200 MB in 10 minutes, and any archive-then-transfer of restricted content.

## 9. Memory and performance

DLP adds to the idle core only the compiled channel tables (counted in the policy share of `policy.md` section 9), the 4,096-entry result cache (about 1 MB), the pending-file set (at most 10,000 entries, about 1 MB) and the activity counters, a target of 3 MB within the core's 44 MB. The scanner is not resident at idle. Its 256 MB cap is reserved as follows, measured and re-derived from the first prototype:

| Consumer | Reservation |
|---|---|
| Magika model and `tract` runtime | 16 MB |
| Compiled YARA-X, regular-expression sets and keyword automata | 48 MB |
| Fingerprint index (section 4) | 64 MB |
| PDFium or Tesseract working set, one object at a time | 64 MB |
| Extraction buffers, text up to 16 MB, archive streams | 64 MB |

## 10. Design status

| Item from `../analysis.md` section 3 | Where |
|---|---|
| Vietnamese identifier validation rules and financial data types | `../specs/dlp-detectors.md` sections 2 to 5 |
| Fingerprinting method and partial-match threshold | Section 4 |
| Rust extraction libraries per format | Section 2.3 |
| Clipboard prevention contract | Section 6.5; Windows/macOS per-read mechanisms and Linux first-read exclusion remain release blockers |
| Safari content-script gate and bypass tests | Section 6.5; exact-transfer mediation remains a release blocker |
| Connector agent registration on Chrome and Edge per OS | Section 6.5 |
| Hold point for newly written content | Section 6.4 defines the exact-byte contract; platform mechanisms remain release blockers |
| macOS pasteboard pre-approval | Section 6.5: none exists, an OS limit |
| GNOME Shell extension selection ownership | Section 6.5 |

## 11. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: content never leaves the endpoint for classification; the scanner holds no idle memory and cannot open files on its own; coverage states make uninspected content a policy decision instead of a silent pass; one scanner binary computes fingerprints on the server and matches them on the agent, so normalization cannot drift; lineage inheritance classifies what cannot be read; the enforcement contracts distinguish prevention from remediation.

Trade-offs: OCR and PDFium bring C and C++ code into the scanner, accepted because the scanner is isolated and capped; rendering every PDF page adds work and can reach the declared OCR budget; deny-then-approve asks the user to repeat an operation on channels that qualify it; keeping uploaded originals for recomputation stores sensitive documents on the server under envelope encryption; exact-byte staging or mediation adds platform work that the current file hooks do not provide.

Dependencies: `infer`, `tract-onnx`, the Magika model, `pdfium-render` and PDFium, `zip`, `quick-xml`, `calamine`, `cfb`, `rtf-parser`, `html5ever`, `mail-parser`, `msg_parser`, Tesseract, Leptonica and `tesseract-rs` with the `tessdata_fast` models, `tar`, `flate2`, `bzip2`, `liblzma`, `zstd`, `sevenz-rust2`, `chardetng`, `encoding_rs`, `regex`, `aho-corasick`, `yara-x`, `tlsh2`, `blake3`; rows in `../licensing.md`.

Limits: RAR archives are not extracted (license); OCR recall on handwriting and photos is unmeasured; macOS cannot identify the pasteboard reader and has no managed pasteboard pre-approval; Edge has no documented connector pin; the GNOME extension depends on Mutter's selection API per release; fingerprints cannot match a paraphrase; the keyed fingerprints and TLSH digests of registered documents are present on every endpoint in scope, and the fingerprint key protects backups and exports, not a compromised endpoint. The file, clipboard, Safari and Chromium fallback gaps in sections 6.4 and 6.5 remain required release blockers.

Alternatives considered: ssdeep (GPL-2.0, `../licensing.md`); TLSH alone for partial matching (rejected: a whole-input digest does not find an excerpt); word shingles (rejected: Vietnamese syllable spacing makes word boundaries a poor unit and character k-grams also cover source code); fingerprints computed on agents from server-pushed documents (rejected: sends confidential documents to every endpoint); rename or unmount alone as the file hold point (section 6.4); source lineage as authorization for later unscanned bytes (rejected: it does not bind exact bytes); warn as a notification on file channels (rejected: not a choice); the `magika` crate with ONNX Runtime (rejected while `tract` is available: a C++ runtime in the scanner).

## Sources

- Type detection and extraction: [Magika](https://github.com/google/magika), [tract](https://github.com/sonos/tract), [PDFium](https://pdfium.googlesource.com/pdfium/), [pdfium-render](https://github.com/ajrcarey/pdfium-render), [calamine](https://github.com/tafia/calamine), [cfb](https://crates.io/crates/cfb), [mail-parser](https://github.com/stalwartlabs/mail-parser), [msg_parser](https://github.com/marirs/msg-parser-rs), [Tesseract](https://github.com/tesseract-ocr/tesseract), [tesseract-rs](https://crates.io/crates/tesseract-rs), [sevenz-rust2](https://github.com/hasenbanck/sevenz-rust), [UnRAR license](https://raw.githubusercontent.com/muja/unrar.rs/master/unrar_sys/vendor/unrar/license.txt), [ocrs models](https://huggingface.co/robertknight/ocrs), [MuPDF](https://github.com/ArtifexSoftware/mupdf).
- Matching: [YARA-X](https://virustotal.github.io/yara-x/), [TLSH](https://github.com/trendmicro/tlsh), [tlsh2](https://github.com/vthib/tlsh), [winnowing](https://theory.stanford.edu/~aiken/publications/papers/sigmod03.pdf).
- Channels: [content_analysis_sdk](https://github.com/chromium/content_analysis_sdk), [Chromium connector policy](https://chromium.googlesource.com/chromium/src/+/main/components/policy/resources/templates/policy_definitions/Miscellaneous/OnFileAttachedEnterpriseConnector.yaml), [Edge connector policy](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/onfileattachedenterpriseconnector), [Firefox ContentAnalysis](https://mozilla.github.io/policy-templates/#contentanalysis), [Apple Safari declarative blocking](https://developer.apple.com/documentation/safariservices/blocking-content-with-your-safari-web-extension), [Microsoft clipboard operations](https://learn.microsoft.com/windows/win32/dataxchg/clipboard-operations), [Apple Endpoint Security open](https://developer.apple.com/documentation/endpointsecurity/es_event_type_auth_open), [Apple Endpoint Security mmap](https://developer.apple.com/documentation/endpointsecurity/es_event_type_auth_mmap), [Linux Security Module file permissions](https://www.kernel.org/doc/html/latest/security/lsm-development.html), [Apple TCC payload schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.TCC.configuration-profile-policy.yaml), [Apple forum 794560](https://developer.apple.com/forums/thread/794560), [Mutter meta-selection-source.h](https://gitlab.gnome.org/GNOME/mutter/-/blob/main/src/meta/meta-selection-source.h).
