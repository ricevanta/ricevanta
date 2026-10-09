# Agent extension runtime

The execution contract for `agent-module` components: Wasmtime isolation, end-to-end call limits, collector file access and responder recovery. The package and trust model is in `../design/extensions.md`; generic command signing and replay protection is in `policy-envelope.md` section 7. Decision: EXT-03.

## 1. Process and interfaces

`ricevanta-ext` is one Rust binary with two separately supervised process classes. A DLP instance runs only `classifier` and `parser` calls. A batch instance runs `collector` and `responder` calls and compiles modules before activation. The core starts each class on demand, stops it when idle and never starts one process per module. Both classes therefore have a 0 MB idle budget. Each active instance has its own policy cap whose default is 128 MB, and the default aggregate active cap is 256 MB. The DLP cap is reserved: batch allocation cannot borrow it. The core meters each instance and their aggregate under AG-08.

Each start creates a new process generation. The core sends a call only to its class and accepts results only from the generation that admitted it. Killing or replacing the batch generation cannot terminate or invalidate a DLP store. Killing the DLP generation applies the content crash contract in section 3 to its affected decisions. Both process classes run with reduced privilege, have the core as their only IPC peer and never talk to the server or another helper.

The runtime is `wasmtime` with the component model and WASIp2. Modules are `wasm32-wasip2` components. Versioned WIT packages under `schemas/wit/` define `classifier`, `parser`, `collector`, `responder`, shared match, offset-range and row types, and bounded logging.

The linker exposes only the selected capability world, `wasi:clocks/monotonic-clock` and bounded logging. It exposes no WASI filesystem, sockets, HTTP, environment, wall clock or process functions. A module with another import fails to instantiate and is reported. Each call uses a fresh `Store` from a pre-linked `InstancePre`, so guest state does not survive calls.

Classifier and parser log lines stay in the local agent log because they can echo inspected content. Only their counts leave the device. Collector and responder log lines become agent health events within a byte and rate cap; excess lines are counted.

## 2. Call lifecycle and deadline

At admission the core records monotonic `start` and computes `absolute_deadline = start + min(granted_duration, remaining_policy_duration)`; a non-content call omits the policy term. The interval starts before queue admission and covers queue time, IPC, store creation, guest execution, every host import, broker work, result transfer, output validation and cleanup. Each bundle carries a positive `cleanup_ms` smaller than the selected duration. A call that cannot enter its class's bounded queue before the work cutoff at `absolute_deadline - cleanup_ms` is refused without starting.

Wasmtime fuel limits guest instructions, and epoch interruption traps guest execution at the work cutoff. Neither mechanism stops a synchronous host operation. The helper therefore enables Wasmtime's supported async host embedding and implements blocking-looking WIT imports with async host functions. The guest still sees synchronous WIT calls. Ricevanta does not depend on the separate experimental guest component async ABI.

At the work cutoff, the core interrupts the guest, cancels outstanding host futures, invalidates the call id and every broker handle, discards any later output and prevents another broker operation for that call. Cleanup uses the reserved interval. If the call has not returned by the absolute deadline, the core kills and replaces only its process class and generation. A collector or responder timeout therefore replaces the batch instance without affecting an active classifier or parser. A late response never becomes a decision, inventory row or action plan.

Some OS calls cannot be cancelled promptly after entering the kernel. The core uses separate bounded executor and broker-worker pools for DLP and batch calls. Cancellation abandons a kernel result, but the blocked worker stays counted against its class until the call returns. Each bundle must set positive `dlp_max_concurrent_calls`, `batch_max_concurrent_calls`, `dlp_broker_workers` and `batch_broker_workers`; both DLP values must be at least one. Collector and responder work cannot enter either DLP pool. Hung collector calls may consume all batch broker workers, which refuses more batch work and reports the stuck operations, but they cannot consume DLP executor, broker-worker or process capacity. The watchdog replaces only the stuck class and reports capacity loss.

| Limit | Mechanism | Source |
|---|---|---|
| Guest CPU | Wasmtime fuel | Grant `fuel_per_call` |
| End-to-end wall time | Absolute monotonic deadline, cancellable host futures, epoch interruption and watchdog | Grant `deadline_ms`; policy deadline for content calls |
| Memory | Wasmtime `ResourceLimiter` for memory pages, tables and instances | Grant `memory_pages` |
| Output | Per-interface item and byte caps, including a default 16 MB parser-text cap | Bundle budgets |
| Concurrency | Separate bounded DLP and batch queues, call slots and broker workers | Required `dlp_max_concurrent_calls`, `batch_max_concurrent_calls`, `dlp_broker_workers`, `batch_broker_workers` bundle fields |
| Process | One replaceable instance per class, each capped separately and in aggregate | Policy values, default 128 MB per class and 256 MB aggregate |

Fuel exhaustion, an epoch trap, timeout, cancellation and an invalidated handle produce distinct health reasons. A content call takes the policy fail mode. Other calls fail without accepting partial output. Each result counts against module governance in section 5.

## 3. Compilation and decision path

The helper compiles a new module with Cranelift before its bundle becomes active and outside decision paths. The core stores the precompiled artifact in its root-only state directory, keyed by module SHA-256, Wasmtime version and target CPU features. It records the artifact hash in `state.db`, verifies the hash before every load and passes a read-only file descriptor or handle to the helper. Wasmtime treats deserialized precompiled artifacts as trusted input and exposes the load through an `unsafe` API (verify), so root-only storage and the per-load hash check are required. Compilation has a policy-set wall-clock budget whose default is 60 seconds. Failure disables and reports the module; a decision that needs it takes its fail mode.

For a DLP content decision, the core sends the file descriptor or handle to `ricevanta-scan` for built-in extraction and detectors. A policy may assign a parser only to a declared MIME type the built-in scanner does not extract. The parser returns bounded text with its source offset map, and the core supplies that text to each assigned classifier. Every hop uses the one deadline and fail mode from section 2. One helper crash causes one retry with a fresh helper only when enough deadline remains. A second crash on the same content hash applies `closed` and raises an alert. Extracted content stays in the core and helpers.

## 4. Collector filesystem broker

A collector receives query parameters and the host broker WIT interface. It never receives a raw directory preopen or `wasi:filesystem`. The interface offers bounded `list`, `open`, `read` and `close` operations over opaque regular-file handles. The core owns the underlying read-only file descriptors or handles and performs every operation under its privilege. The reduced-privilege helper therefore can read an approved root-only inventory file without gaining a privileged directory handle or authority to open any child itself.

Each opaque handle binds the package digest, component, monotonic component `grant_generation`, call id, process generation and handle id. Each list, open and read rechecks that identity against the active signed bundle, the absolute deadline and a fixed deny list. The deny list wins over every allowed ancestor, including descendants reached through a path alias. It includes agent state and caches, OS credential stores, private keys, authentication databases and user homes unless the grant names a bounded home subtree. The server rejects an invalid grant before compilation, and the agent repeats validation before activation and at every broker request. A later grant with identical values has a new generation and cannot revive a stale handle.

The broker accepts only canonical absolute paths beneath an exact granted root. It rejects `..`, alternate path syntax, symlinks, mount or namespace escapes, Windows reparse points and aliases whose resolved path leaves the root. Linux uses handle-relative resolution with `openat2` constraints where available. macOS walks components with no-follow opens and verifies the final descriptor. Windows opens components without following reparse points and verifies the final normalized handle path. A deny entry always wins over an allowed ancestor.

Every successful open creates a call-scoped identity pin. The core resolves the requested canonical path beneath an exact granted root without following links, checks the current path and object-identity deny sets, and requires a regular file with link count one. Before returning an opaque handle, it opens the same canonical path again with the same constraints and requires both opens to name the same object with link count one. It retains the approved read handle and pins its stable identity only until the call ends. A new or atomically replaced approved file can therefore be read by a later call under the same grant; normal file rotation does not write or advance `grant_generation`.

Before and after every read, the broker reopens the canonical path without following links and requires the path handle, retained read handle and call-scoped pin to name the same regular-file identity with link count one. It repeats the current path and identity deny checks and holds the bytes until the post-read fence passes. A mismatch discards the bytes and invalidates the handle. No extension can override these rules. The protected-path and protected-identity deny sets remain mandatory for every current alias the agent can observe: device and inode on macOS and Linux, and volume and file identifier on Windows. A watch snapshot is only a hint. When a deny decision depends on a protected alias's current identity, the broker resolves that identity synchronously at the fence or rejects the read. A grant is refused where the agent cannot enforce no-follow resolution, stable identity, regular-file type, trustworthy link count and the reopen fence. A privileged ancestor descriptor never grants child-open authority.

This broker prevents an unprivileged module from exploiting observable path, link and replacement races. It does not reconstruct past alias provenance. Under the agent tamper boundary, a principal already authorized to move a protected object into an approved collection root and remove every denied alias before broker admission is outside this defense. The broker treats content that principal deliberately places in the approved root as authorized, subject to the current path and identity deny checks. This boundary does not exclude approved root-owned inventory roots.

Every collector grant requires positive bounded fields `max_roots`, `max_path_depth`, `max_directory_entries`, `max_open_handles`, `max_list_requests`, `max_read_requests`, `max_bytes_per_file`, `max_input_bytes`, `max_rows`, `max_output_bytes` and `deadline_ms`. The schema enforces product ceilings. Enumeration uses stable bounded pages and does not recurse unless `max_path_depth` permits it. The core closes all handles on cancellation, deadline, grant change or helper exit. Rows validate against the manifest's declared schema before becoming inventory or compliance events; oversized fields or partial output are refused.

## 5. Governance

Each installed module is a work unit under AG-08. The agent meters fuel, peak memory, queue and call latency, broker requests, output size, traps, timeouts and helper replacements against `budgets.json`. It first rate-limits a module over budget, then disables it. A throttled content call takes the policy fail mode. The device reports each state and the console shows the module as degraded.

## 6. Responder plan and recovery

A responder runs only for a signed `extension.respond` command. The signed command binds the organization, device, immutable package digest, component name and artifact digest, interface version, grant generation, allowed action set, canonical allowed entity identities and input parameters. The server derives those fields from the enabled install and approval. A mutable package id or version is never sufficient authority.

The module returns one plan and performs no action. Every responder grant requires positive `max_plan_steps` and `max_plan_bytes` fields within product ceilings. The core validates the whole canonical plan before the first side effect: schema, both plan limits, action grant, parameters, entity identity, current package and grant state, command approval and action-specific preconditions. One malformed or unauthorized later step refuses the whole plan.

After full validation, one SQLite `synchronous=FULL` transaction stores the immutable canonical plan bytes and hash under the parent `command_uid` and every journal row for stable step id `(command_uid, index)`. No step starts before that transaction commits. A crash before the plan commit may run the module again under a fresh dispatch grant because no action has started. Once the plan commit exists, recovery uses those bytes and never runs the module again, even if a later invocation would return different output.

Each step moves through `pending`, `running`, `succeeded`, `failed`, `cancelled` or `reconcile_required`. The core records `running` before dispatching the existing response action and records the terminal state after that action's durable reconciliation point. Recovery never repeats a completed step. It reconciles a running step through the action's existing idempotency and recovery contract. If the agent cannot prove whether an unsafe side effect occurred, it leaves the step at `reconcile_required`, halts the plan and asks for operator action. Ricevanta does not claim exactly-once external side effects.

A fresh server-issued dispatch grant is required to start the command and to resume it after an agent restart. `jobs` issues the grant only while the bound package, component and exact grant generation remain enabled and authorized. Before each pending step, the core requires the command's generation to equal the current signed bundle entry. Any later grant write makes the command stale even when capability values return to the prior set. A delivered revocation, disable or grant change cancels pending steps and forbids every unstarted step. A running step retains its reconciliation obligation so the agent can determine and report what already happened; revocation does not pretend to undo an admitted side effect.

Cancellation prevents pending steps from starting and asks the current action contract to stop a running step where supported. The parent result records completed, failed, cancelled, unreconciled and unstarted steps. A failed step stops later steps unless the signed command explicitly selects a bounded continue-on-failure mode that the approval also binds.

## 7. Qualification

Acceptance cases cover deadline consumption in queues and broker calls, an unresponsive host import, an unkillable broker call, class-specific helper replacement, late output and reserved DLP process, executor, broker-worker and memory capacity. A collector timeout while classifier and parser calls are active must replace only the batch generation; the active DLP process, stores and results survive. Hung collector kernel calls must remain charged to the batch broker quota and never consume a DLP worker.

Collector cases cover an allowed ancestor with a denied descendant, path aliases, symlinks, reparse points, special files, root-only regular files and every count and byte cap. Standard user-level tests swap paths and create or remove hard links during open and read, including removal after the first open and before the second open or a read fence. No multiply-linked, removed-path or identity-changing object observed by a fence may return bytes. A stale watch snapshot alone must not authorize a current protected alias: the fence must resolve the identity synchronously or reject the read. A normal new or atomically replaced approved file must be readable in a later call under the same grant. A platform that cannot enforce the call-scoped identity pin, reopen fence and trustworthy link count must refuse the grant.

Responder fixtures cover a crash before plan persistence, after plan persistence, after a step becomes running, after its side effect and before its terminal write, and after the terminal write. They also cover a malformed later step, nondeterministic module output, changed or revoked grants, stale dispatch grants, cancellation, partial failure and an unsafe unknown reconciliation result. A grant sequence A, B, then equal-to-A must reject handles, commands and pending steps bound to the first A generation.

## 8. Sources and design assessment

Wasmtime documents async host functions for component-model links in [`LinkerInstance::func_wrap_async`](https://docs.rs/wasmtime/latest/wasmtime/component/struct.LinkerInstance.html#method.func_wrap_async): WebAssembly sees a blocking call while the host future can yield without blocking its executor thread. That supported host embedding is distinct from a guest component async ABI.

Benefits: one broker and one deadline boundary keep root access and cancellation in the core while untrusted code stays reduced privilege. Durable plans separate module determinism from action recovery.

Trade-offs: brokered reads and fresh stores add IPC and setup cost. An OS call that does not return can occupy one bounded worker until restart, so the design preserves enforcement capacity instead of promising arbitrary syscall cancellation.

Dependencies: `wasmtime`, `wasmtime-wasi`, Cranelift, WIT bindings and the agent's existing action journal. All have entries in `../licensing.md`.

Limits: modules have no network or process spawn. A collector cannot read a multiply-linked regular file, including a legitimate inventory file. The broker cannot detect a protected object's past alias after an authorized principal has moved the object into an approved root and removed every denied alias. Collector grants are unavailable where the agent cannot enforce canonical containment, stable identity, path reopening, link count and current protected-file exclusion. Responder recovery can halt for operator action when an external side effect has no safe reconciliation signal.

Alternatives considered: raw WASI directory preopens were rejected because they cannot filter denied descendants and a directory descriptor held by the reduced-privilege helper does not grant privilege to open root-only children. Fuel and epoch interruption alone were rejected because they do not cancel host I/O. Re-running a responder after plan persistence was rejected because nondeterministic output could change the action sequence.
