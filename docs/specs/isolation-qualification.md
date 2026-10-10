# Isolation qualification research candidate

This document records an unadopted candidate for resolving the console-module and inventory-query blockers in `../design/extensions.md` section 5 and `rule-adapters.md` section 8.1. It does not override EXT-04, the current extension manifest, asset routes or bridge contract. No mechanism is supported until an exact browser or OS configuration passes this specification and the project adopts the required design changes.

## 1. Security contracts

A console module may compute on bridge data and send schema-checked bridge messages. It must not start another connection, cause DNS resolution, navigate any browsing context, load bytes outside its bound package, obtain console credentials or exercise authority outside the private bridge port.

An inventory query may compute on one immutable snapshot and return bounded rows. After the worker declares itself ready, it must not read or write any pathname, open a network endpoint, discover credentials, use ambient interprocess communication (IPC), create another process, retain state across calls, or exceed 64 MiB total process memory and the 100 ms end-to-end deadline.

| Runtime | Granted capabilities | Excluded capabilities |
|---|---|---|
| Console module | One private `MessagePort` after binding; operations in the current grant and safe-operation catalogue | Network, navigation, storage, credentials, console DOM, authority through window messaging |
| Query worker | One bounded snapshot input handle, one bounded result handle and one bounded diagnostic handle | Path access, network, process creation, ambient IPC, credentials, writable database, caller environment |

The launcher supplies a fixed argument vector containing only the worker identity, an empty environment and a dedicated empty working directory that the worker cannot access after containment. It closes every inherited handle, descriptor and IPC endpoint except the three protocol handles. It does not inherit credential handles, agent tokens, key stores, session buses, Mach ports, named pipes or sockets. A capability binds the current recovery epoch and component grant generation where an extension supplies a collector table. A path, URL, numeric process identifier or self-reported digest never grants authority.

## 2. Console capsule candidate

### 2.1 Status and input contract

The candidate replaces the current publisher HTML and asset-tree execution model only if a later design decision adopts it. The server would accept prebundled, typed JavaScript, CSS, font and image inputs, generate one canonical HTML capsule, store its exact bytes immutably and record `{generator_version, capsule_sha256}` beside the package and component digests. Runtime imports and external URLs would be refused. CSP hashes would be computed from the stored executable and style bytes, not regenerated at response time.

The exact component schema, JavaScript and CSS parser versions, HTML escaping rules, MIME allow list, canonical ordering, binary encoding, decoded-size limits and treatment of `</script`, CSS URLs, source maps and malformed text are unspecified. A security-reviewed generator and fixtures for each parser and escaping boundary are required before this candidate can produce a capsule. A proposed generator is not a qualified asset-binding mechanism.

If adopted, a binding would identify `{package_sha256, component_sha256, generator_version, capsule_sha256, recovery_epoch, grant_generation, slot, operator_session}`. Its URL would contain the capsule digest and a single-use nonce. The server would serve only the stored bytes, recompute their digest before response, refuse query strings, ranges and redirects, and send `Cache-Control: no-store, no-transform` and `X-Content-Type-Options: nosniff`.

### 2.2 Binding state machine

1. `issued`: the server fixes the binding tuple, exact capsule URL, nonce and expiry. The parent console CSP permits only the fixed extension-route family. The host sets this exact URL as `iframe.src` and retains the expected `WindowProxy`.
2. `loading`: the server records the bound request and response completion as an emission receipt. That receipt proves only which bytes the server emitted. It does not prove which document the `WindowProxy` executed. Any bootstrap message before the first `load` closes the binding.
3. `loaded`: the host records the first `load`, creates a fresh per-navigation challenge and sends the challenge to the retained window. Any later `load`, unexpected message or timeout closes the binding.
4. `ready`: the bootstrap must echo the challenge, nonce and schema version. The host also requires `event.source` to be the retained window and `event.origin` to be `"null"`. A receipt mismatch, repeated response or invalid field closes the binding.
5. `active`: only if exact document binding is qualified may the host consume the binding, challenge, nonce and emission receipt, transfer one `MessagePort`, and send `init` through that port. Every authoritative request uses the port and the server-side binding admission fence.
6. `closed`: an unexpected bootstrap message, port error, timeout, navigation, disable, revocation, uninstall or grant write closes the port and invalidates queued dispatch. No state transition can reopen the binding.

The extension bridge needs `window.postMessage` for the challenge echo and the one port transfer. The host registers only this source-, nonce- and challenge-bound bootstrap receiver and retires it after transfer. Other extension-origin window messages are rejected and have no authority. The module retires its transfer receiver after it obtains the port. BroadcastChannel, MessageChannel ports not supplied by the host, `data:`, `blob:`, `about:` and other local-scheme contexts receive no binding authority.

The exact URL is enforced by the binding, the host's `iframe.src`, the retained window, the nonce and the per-navigation challenge. The parent cannot read an opaque window's current URL and must not claim that the emission receipt, challenge echo or `WindowProxy` check attests execution. A `WindowProxy` survives navigation. A replacement document can echo before the parent observes its `load`, or navigation can occur between a valid echo and port transfer. The current browser APIs therefore do not prove that the exact stored document receives the port. Exact document binding remains unqualified unless a supported primitive closes this race. The product must not mount a capsule or enter `active` while this blocker remains.

### 2.3 Connection boundary

The candidate capsule response uses these policies:

```text
Content-Security-Policy: sandbox allow-scripts; default-src 'none';
  script-src <exact hashes>; style-src <exact hashes>; img-src data:;
  font-src data:; connect-src 'none'; worker-src 'none'; frame-src 'none';
  child-src 'none'; object-src 'none'; media-src 'none'; manifest-src 'none';
  form-action 'none'; base-uri 'none'; frame-ancestors <console origin>;
  webrtc 'block'
Connection-Allowlist: (); redirects=block; webrtc=block
```

The host uses `<iframe sandbox="allow-scripts">`, disables every unneeded Permissions Policy feature, and applies the binding state machine. CSP remains defense in depth. `connect-src` does not cover WebRTC, DNS prefetch or navigation. The draft `webrtc` directive has no qualified cross-browser implementation. Chromium documents Connection Allowlist support, but Firefox and WebKit have no confirmed equivalent. No browser qualifies from API documentation alone.

### 2.4 Browser qualification

Run the production bytes, headers and state machine in every required Chromium, Firefox and WebKit release. Observe an authoritative DNS zone, external HTTPS and redirect servers, STUN and TURN servers, a WebRTC peer, console-server access logs, browser network instrumentation and host packet capture. Repeat with cold and warm caches. A pass has no module-initiated DNS query, packet or request after the capsule response. Authorized parent requests caused by accepted port messages remain bridge activity and must match their binding and catalogue entry.

The malicious capsule embeds bridge data into every available destination and attempts:

- Fetch, XMLHttpRequest, EventSource, WebSocket, WebTransport, beacon and hyperlink ping.
- Images, image sets, fonts, CSS import and URL, media, objects, embeds, manifests, favicons, imports, preload, prefetch, preconnect, DNS prefetch, speculation rules, workers and service workers.
- WebRTC peer, ICE, STUN, TURN and data-channel destinations.
- Self and top navigation, activation, meta refresh, forms, popups, downloads, custom protocols, redirects and error pages.
- Added path, query, fragment, encoding, authority, range and cache data on the exact capsule URL.
- Pre-load bootstrap messages, aborted initial navigation where an earlier document sends a message before a replacement document loads, navigation between echo and port transfer, forged, repeated and late window messages, sibling-window messages, BroadcastChannel, new MessageChannels, and `data:`, `blob:` and `about:` descendants.

Also prove every permitted pre-active transition, revocation fencing and refusal of tampered bytes, wrong hashes, wrong URLs, reused nonces, missing receipts, second loads and stale generations. A passing harness cannot enable product mounting until exact document binding is proved. An unknown policy directive, external sink observation or packet is a failure. Developer tools alone do not establish no egress.

## 3. Inventory query process candidate

### 3.1 Common lifecycle and deadline

The agent creates a worker for every query and transfers an anonymous immutable snapshot. It never passes the live SQLite database or a pathname. A child sends `ready` only after containment, handle closure, environment clearing and working-directory isolation complete; the supervisor sends snapshot bytes only after that acknowledgement.

The absolute monotonic deadline remains 100 ms and includes queueing, launch, containment, transfer, evaluation, serialization, kill and reap. The candidate reserves 25 ms for termination and reap, leaving at most 75 ms for queueing through serialization. The supervisor starts termination when the work budget expires. A result is successful only after clean exit within the total deadline. Qualification may reduce the work budget but cannot spend the cleanup reserve. No OS has yet proved the cleanup bound on every required configuration, so the 100 ms contract remains blocked.

On failure the supervisor kills the whole containment unit, waits for proof that it is empty, discards all output, then releases resource controls. No next query starts before that proof. A stable process handle identifies a worker. Supervisor restart must recover the same containment identity or prove it empty; a reusable PID is insufficient.

SQLite applies the existing connection, heap, value and result limits before prepare, retains the authorizer through stepping, disables extension loading, memory maps and disk temporary storage, and exposes only bounded functions. The 32 MiB SQLite heap limit does not cover Rust, stacks, snapshot decode or result encoding. The existing 64 MiB total-process limit remains literal and is not redefined as a platform controller value.

### 3.2 OS candidates and blockers

| OS | Candidate launch and cleanup | Blocking evidence |
|---|---|---|
| Linux | Preconfigure a cgroup v2 leaf with `memory.max=64M`, `memory.swap.max=0` and `pids.max=1`; use one `clone3` call with `CLONE_INTO_CGROUP` and `CLONE_PIDFD`; the static child closes ambient state, installs `no_new_privs` and a seccomp allow list, then acknowledges readiness. Kill through the pidfd; use `cgroup.kill` where present, otherwise kill the sole task; reap with `waitid(P_PIDFD)` and require `cgroup.events populated=0` before teardown | Kernel 5.10 lacks Landlock and `memory.peak`, so neither is required or assumed and this candidate does not raise the baseline. Seccomp must deny pathname, network, IPC, process and thread creation after startup. `memory.max` may overshoot and measures cgroup charges, not the AG-02 total-process metric. Atomic launch, literal 64 MiB enforcement and kill-plus-reap inside the reserve remain unproved |
| Windows | Create the documented Less Privileged AppContainer (LPAC) process suspended with no capabilities and an explicit handle list; assign it to a fully configured Job Object before resume; require its ready acknowledgement. Deny breakaway, set active-process limit one, terminate the job, wait on the process handle and query the job until it has no active process | LPAC still has implicit writable package storage and readable runtime paths, so no capabilities does not prove no pathname access. Job commit and private working set are different counters; a 64 MiB job-commit value does not prove the literal total limit. Suspended launch, cleanup reserve and supervisor-restart identity need qualification |
| macOS | Candidate only: a separately signed App Sandbox helper with no requested file or network entitlement, anonymous protocol handles and parent-owned termination | App Sandbox supplies a writable container, readable runtime paths and allowed system IPC, so no entitlements does not prove no pathname or ambient IPC access. `RLIMIT_RSS` is a reclaim preference, not a hard resident limit. Whole-unit identity across supervisor restart, process-creation denial, hard total memory and bounded kill/reap have no confirmed supported mechanism |

Qualification records the native AG-02 footprint metric and the controller's own counter as distinct values: proportional set size and cgroup charges on Linux, private working set and job commit on Windows, and `phys_footprint` on macOS. No conversion, headroom or equivalence is inferred. The process must stay at or below 64 MiB under the native metric at every observable point, and a kernel boundary must prevent unobserved excess. Linux's documented `memory.max` overshoot therefore remains a blocker even when sampled values pass.

### 3.3 Query qualification and failure

Run every case on every eligible OS configuration. A pass preserves enforcement latency and memory, returns a named error, emits no partial success, proves the containment unit empty and leaves no worker, handle, cgroup, profile or temporary object.

- Valid queries and admitted functions match `ricevanta-rulec` results.
- Writes, attach, pragmas, extensions, temporary objects, path and credential access, networking, DNS and ambient IPC fail.
- Process, thread, shell and dynamic-library creation cannot add authority.
- Oversized values, functions, rows, snapshots and results fail before allocation crosses a bound.
- Recursive queries, cross joins, non-yielding functions, blocked output and malformed frames meet both deadline budgets.
- SQLite, Rust, stacks, decoding and encoding count toward the literal total without charging the agent or another worker.
- Launch, ready, result, kill and restart races leave no zombie, escaped member or accepted late output.
- Eight queued requests get bounded service; the ninth is refused. Queue time consumes the 75 ms work budget.

Failures are `timeout`, `cleanup_timeout`, `memory_limit`, `step_limit`, `result_limit`, `sandbox_violation`, `worker_crash` or `protocol_error`. A cleanup timeout is a qualification failure, not an ordinary bounded query outcome. The supervisor keeps the unit quarantined, continues cleanup and disables further queries. A baseline records `unknown`; scheduled differential state stays unchanged; discovery does not grant compliance; policy health reports every failure. Backoff is bounded and never suppresses health reporting.

## 4. Alternatives, adoption work and safe slice

The current asset tree remains authoritative. This candidate studies a single capsule because an allowed asset URL can carry data and an opaque parent cannot inspect the dependency graph. A second origin does not stop WebRTC, DNS or navigation. CSP alone does not prove no egress. In-process SQL shares failures with enforcement; a resident worker retains state and idle memory; a virtual machine or full container is too heavy for the query deadline.

The safe research slice is the schema and parser design, stored-byte capsule generator prototype, explicit binding state machine, document-identity race research, common worker protocol and adversarial harnesses. Prototypes remain disabled and cannot establish support.

Adoption would require a reviewed decision update to EXT-04, replacement of the `console-module.entry` HTML contract, a typed-input schema, generator-version and capsule-digest fields, immutable storage rules, route and CSP changes, bridge state schemas and fixtures, licensing review for parsers, and aligned edits to `../design/extensions.md`, `policy-envelope.md` and the extension manifest schema. Until those changes are approved, central documents may link this file only as further design work.

## 5. Primary sources

- W3C: [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/) for `connect-src`, `webrtc`, sandbox and redirect behavior.
- WHATWG: [iframe sandbox](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-sandbox), [sandboxing flags](https://html.spec.whatwg.org/multipage/browsers.html#sandboxing-flag-set), [the WindowProxy exotic object](https://html.spec.whatwg.org/multipage/nav-history-apis.html#the-windowproxy-exotic-object) and [cross-document messaging](https://html.spec.whatwg.org/multipage/web-messaging.html#web-messaging).
- Chrome: [Connection allowlists](https://developer.chrome.com/blog/connection-allowlist-announcement).
- WICG: [Connection Allowlists draft](https://wicg.github.io/connection-allowlists/) for empty-list parsing and proposed coverage.
- Mozilla: [open CSP `webrtc` implementation bug](https://bugzilla.mozilla.org/show_bug.cgi?id=1783489).
- WebKit: [open CSP `webrtc` implementation bug](https://bugs.webkit.org/show_bug.cgi?id=255651).
- SQLite: [limits](https://www.sqlite.org/limits.html), [hard heap limit](https://www.sqlite.org/c3ref/hard_heap_limit64.html), [progress handler](https://www.sqlite.org/c3ref/progress_handler.html) and [authorizer](https://www.sqlite.org/c3ref/set_authorizer.html).
- Linux kernel: [cgroup v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html), [`clone3`](https://man7.org/linux/man-pages/man2/clone.2.html), [pidfds](https://man7.org/linux/man-pages/man2/pidfd_open.2.html) and [seccomp](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html).
- Microsoft: [launch an AppContainer or LPAC](https://learn.microsoft.com/windows/win32/secauthz/implementing-an-appcontainer), [Job Objects](https://learn.microsoft.com/windows/win32/procthread/job-objects) and [job memory limits](https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information).
- Apple: [App Sandbox](https://developer.apple.com/documentation/security/app-sandbox), [sandbox file access](https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox) and [`setrlimit`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setrlimit.2.html).
