# Endpoint mechanism research

This specification tests the unresolved endpoint mechanisms in `../design/dlp.md`, `../design/lineage.md` and `edr-response-actions.md`. It does not relax their contracts. Every v1.0.0 platform and browser remains required.

## 1. Evidence rules and conclusions

- **Documented** means a vendor API contract or upstream kernel contract states the property.
- **Inferred** means the property follows from documented parts, but no source promises the composition.
- **Measured** means a repeatable experiment passes on a required qualification unit. No experiment in this document has measured evidence yet.
- **Gap** means no public supported mechanism found in the cited sources supplies the required property. A test requirement does not close a gap.

| Contract | Strongest candidate | State |
|---|---|---|
| Exact-byte file gate | Windows minifilter staging; Linux FUSE staging; macOS FSKit passthrough staging | Candidate on all three OSes, with no documented macOS 15 candidate |
| Clipboard first and every read | Ownership plus lazy rendering | Rejected as complete on every OS; gap |
| Browser exact transfer | Vendor content-analysis connector | Candidate where the browser supplies it; fallback and Safari gap |
| macOS identity-bound termination | `proc_signal_with_audittoken` private SPI | Useful kernel evidence, but not a supported product candidate; public primitive gap |
| macOS script descendants | Endpoint Security ancestry plus audit-token signals | Observation candidate only; containment gap |
| Quarantine | Object-bound freeze, copy, verify and namespace removal | Candidate per OS, unresolved exclusion proofs |
| Lineage file lifetime | Native persistent object handle plus observation continuity | Candidate with explicit fallback |

## 2. Exact-byte file mediation

### 2.1 Documented limits

Apple documents authorization events for open and memory mapping, while write is a notification event. The event catalogue exposes no authorization event for each read or write through an existing descriptor or mapping ([Endpoint Security event types](https://developer.apple.com/documentation/endpointsecurity/es_event_type_t), [open](https://developer.apple.com/documentation/endpointsecurity/es_event_open_t), [mapping](https://developer.apple.com/documentation/endpointsecurity/es_event_type_auth_mmap)). Endpoint Security alone cannot supply the exact-byte gate.

Apple also publishes an FSKit passthrough sample that exposes an existing directory as a mounted file system. `FSPathURLResource` carries the source URL and whether the source is writable, while `FSVolume.ReadWriteOperations` delivers reads and writes to the extension ([passthrough sample](https://developer.apple.com/documentation/FSKit/building-a-passthrough-file-system), [path resource](https://developer.apple.com/documentation/FSKit/FSPathURLResource), [read and write operations](https://developer.apple.com/documentation/FSKit/FSVolume/ReadWriteOperations)). The sample and path resource require macOS 26. The APIs establish a public interception candidate, not the exact-byte composition or coverage on macOS 15.

A Windows minifilter can register for cached, paging and ordinary read and write operations, pend an operation, and receive section-synchronization operations ([operation registration](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_operation_registration), [pending operations](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/processing-i-o-operations), [operation parameters](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_parameters)). These are documented ingredients. They do not promise isolation of pages already mapped when a policy starts.

Linux fanotify does not report access or mutation through `mmap`, `msync` or `munmap` ([fanotify limits](https://man7.org/linux/man-pages/man7/fanotify.7.html)). FUSE direct I/O disables shared mappings by default, and FUSE write-through sends every write to the daemon ([FUSE I/O modes](https://kernel.org/doc/html/latest/filesystems/fuse/fuse-io.html)). Those properties support staging when every visible path traverses the FUSE mount.

### 2.2 Candidate design

Windows uses a minifilter-owned staging file on the system volume for each write-capable open of a protected destination. The original namespace exposes only the last approved revision. The driver redirects explicit, cached and paging writes to staging, refuses writable sections on the approved object, and refuses raw-volume and alternate-namespace access by non-exempt callers. The scanner hashes a read-only staging handle. A trusted commit copies the approved tuple to a same-directory temporary file through the minifilter, verifies the destination handle, then replaces the name. The candidate is inferred until tests prove cache, mapping, rename and network redirect behavior.

Linux exposes each protected mount through a root-owned FUSE gate and hides the backing mount from user mount namespaces. Direct I/O keeps shared mappings disabled. Writes remain in local staging; the writer's file handle reads its staged revision while other opens read the last approved revision. After approval, the committer writes an exact temporary object to the backing mount, verifies it and renames it. A BPF LSM rule denies non-committer access to the hidden backing mount. The candidate fails on a backing filesystem that cannot provide the required temporary-write and rename behavior.

On macOS 26, an FSKit extension exposes a protected source directory through a visible passthrough mount. It writes new content into root-owned local staging and publishes an approved temporary object to the backing directory only after tuple verification. APFS, SMB and removable sources are separate qualification classes. The design must mount or move the backing source at a root-only path before an untrusted process can access it. A user-visible source path would bypass FSKit. Policy activation must refuse while any process holds a descriptor or mapping to the backing source unless a public mechanism proves that every such reference can be drained or revoked. The Apple sample does not establish those properties.

`FSPathURLResource` is unavailable on macOS 15, which remains inside the required current-and-previous-major window. This research found no documented macOS 15 mechanism for wrapping an existing directory. The full macOS contract remains a release blocker, but the evidence does not justify declaring FSKit passthrough infeasible where it is available.

### 2.3 Minimal experiments

Run the Windows experiment on each required Windows and filesystem unit, the Linux experiment on each required kernel, filesystem and network-share unit, and the FSKit experiment on macOS 26 with APFS, SMB and every required removable filesystem. Record macOS 15 as lacking the candidate rather than treating a macOS 26 result as coverage.

1. Open and duplicate descriptors before and after policy activation. Create shared and private mappings, direct I/O and cached I/O. Keep one writer open indefinitely.
2. Write marker `A`, scan it, then race truncate, replacement, mapped writes and marker `B` before commit. A pass exposes only the prior approved revision or exact `A`; no reader or destination observes `B`.
3. Crash the core, scanner and staging daemon at every marker. Remove and reinsert media, disconnect a share and force cache writeback. A pass never commits unapproved bytes and either resumes one commit or leaves the prior revision.
4. Attempt access through aliases, hard links, raw volume handles, bind mounts, a second mount namespace and the original macOS source path. On macOS, retain descriptors and writable mappings from before the passthrough mount. Any path or retained reference that reaches staging or backing bytes without the gate fails the unit.

## 3. Clipboard reads

Windows delayed rendering calls the owner only while a format has no rendered handle. `SetClipboardData` installs a handle that later `GetClipboardData` calls retrieve without another owner callback ([clipboard operations](https://learn.microsoft.com/en-us/windows/win32/dataxchg/clipboard-operations)). Re-owning after the requester closes the clipboard has an unavoidable interval before the owner reacquires the clipboard. `GetOpenClipboardWindow` identifies the current opener, but it does not reserve the next open ([GetOpenClipboardWindow](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getopenclipboardwindow)).

On macOS, `changeCount` reports ownership changes, and a data provider supplies a type when requested ([changeCount](https://developer.apple.com/documentation/appkit/nspasteboard/changecount), [data provider](https://developer.apple.com/documentation/appkit/nspasteboarditem/setdataprovider(_:fortypes:))). Apple documents neither the requesting process nor a callback for every later read. Lazy provision and polling cannot meet the contract.

On X11 and Wayland, a manager can become the owner and answer later selection requests. Notification followed by ownership transfer cannot exclude a request that the compositor or X server accepts first. `ext-data-control-v1` is useful access, not a documented ordering guarantee. A compositor-integrated synchronous policy hook could qualify, but each required compositor needs such a hook. The GNOME source replacement candidate needs an in-process ordering proof.

The candidate for all platforms remains one-use lazy ownership, because it is useful for experiments and `warn`. It is not a release design.

Minimal experiment per required graphical session:

1. Copy a unique value while two readers wait. Release both readers in the same scheduler interval as the owner-change notification.
2. Allow reader A once, then have A and reader B request every advertised format repeatedly before and after A releases the clipboard.
3. Repeat through clipboard history, cross-device capture, remote sessions, owner exit and helper crash.
4. A pass requires the first read to wait for its verdict and every later read to obtain a new verdict or atomically consume one allowance. One unmediated read fails the mechanism.

## 4. Browser persistent channels

Chrome `webRequest` can block a WebSocket or WebTransport handshake. It cannot observe or intervene in messages after either session is established ([Chrome webRequest](https://developer.chrome.com/docs/extensions/reference/api/webRequest)). Blocking the handshake does not bind a later payload to inspected bytes. Content scripts also cannot cover retained page references, isolated worlds, service workers, shared workers and every network API with a documented tamper-proof boundary.

The content-analysis connector is the candidate where the browser documents the needed interception point. Firefox exposes managed clipboard, drag-and-drop, file-upload, print and download points and can fail closed on agent errors ([Firefox ContentAnalysis](https://mozilla.github.io/policy-templates/#contentanalysis)). Each connector still needs exact-byte fixtures because the policy surface alone does not prove transfer binding.

Chrome without Chrome Enterprise Core, Edge on Linux and Safari retain a gap. URL block lists can deny `ws` and `wss`, but there is no documented policy that disables every persistent or worker transfer while retaining ordinary browsing. Safari declarative rules expose request metadata rather than request bodies ([Safari declarative blocking](https://developer.apple.com/documentation/safariservices/blocking-content-with-your-safari-web-extension)). A TLS interception proxy would cover bytes but remains rejected by DLP-01.

Run the exhaustive experiment below only for the fallback adapters named by DLP-01: Safari on macOS, Chrome without Chrome Enterprise Core on macOS, Windows and Linux, and Edge on Linux. Connector units test the upload, paste, print and download channels that their adapter declares; a connector does not acquire a persistent-channel claim merely because the browser supports WebSocket or WebTransport.

1. Establish a WebSocket session before the policy, extension and helper start for every fallback adapter. For Chrome without Chrome Enterprise Core and Edge on Linux, also establish a WebTransport session. Send unique denied bytes from the page, service worker, shared worker and dedicated worker. Safari WebTransport may run as exploratory coverage, but it is not a qualification gate.
2. Repeat with `fetch`, `XMLHttpRequest`, `sendBeacon`, forms, file picker, drag and drop, paste, blob URLs and streams. Mutate the buffer after inspection.
3. Kill and disconnect each extension component and native helper while sends are queued.
4. A fallback pass requires each exact payload to have one verdict bound to one send. A successful send, a destination-wide allowance or a later close fails the adapter. A connector pass requires the same binding only at each connector interception point the adapter claims.

## 5. Response mechanisms

### 5.1 macOS identity-bound termination private SPI

Apple's open-source `libproc.h` declares `proc_signal_with_audittoken` and `proc_terminate_with_audittoken`, but the header explicitly labels all of its interfaces private and subject to change ([current header](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.h), [baseline header](https://github.com/apple-oss-distributions/xnu/blob/xnu-11215.1.10/libsyscall/wrappers/libproc/libproc.h)). XNU copies the token, resolves an exact process identity including pid version, reacquires that identity, checks signal permission and signals the retained process reference ([implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/proc_info.c)). The implementation is evidence that XNU has the required semantic internally. Private SPI cannot satisfy Ricevanta's requirement for a public supported primitive.

A runtime probe could characterize the private SPI by capturing `es_process_t.audit_token`, forcing PID reuse and testing stale-token refusal. Such a result cannot qualify or enable the product action. Ricevanta still needs a documented public API that binds the signal to process identity. No numeric-PID fallback is allowed, so macOS identity-bound termination remains a release blocker.

### 5.2 Script descendants

Endpoint Security reports fork, exec and exit events and supplies process audit tokens ([Endpoint Security](https://developer.apple.com/documentation/endpointsecurity), [process identity](https://developer.apple.com/documentation/endpointsecurity/es_process_t)). Audit-token signaling can safely terminate identities already known. The API does not provide an authorization event for fork, a public descendant containment object, or durable kernel membership comparable to a Windows job or Linux cgroup. Process groups and sessions remain escapable.

An observation prototype may start the interpreter suspended, journal every fork and exec identity in the system extension, and terminate known members leaf-first by audit token. It must not qualify unless event loss, extension crash and restart cannot omit a living descendant. Test `fork`, double-fork, `setsid`, exec storms and fork bombs while crashing the core and Endpoint Security extension. After cancellation, scan all processes and independently tagged side effects for five minutes. Any surviving descendant, sequence gap or unverifiable identity keeps `reconcile_required` and fails qualification. The current public mechanisms leave a hard macOS gap.

### 5.3 Quarantine

Windows should freeze a stream in the minifilter, deny new writes and section creation, drain in-flight operations, copy and verify through the same file object, then use handle-based disposition. POSIX deletion deliberately leaves data accessible through existing handles, and an existing mapped view can refuse deletion ([FileDispositionInformationEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information_ex)). Qualification must prove holder exclusion instead of treating namespace removal as quarantine.

macOS should test `fchflags` with `SF_IMMUTABLE` on the verified descriptor, then clone or copy, hash and perform a guarded namespace move. Apple states that immutable files cannot be changed and documents descriptor-based flag setting ([file flags](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html), [fchflags](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fchflags.2.html)). The sources do not establish draining of an in-flight write, dirty shared pages, exact-entry removal or revocation of existing readers. The candidate remains blocked.

Linux keeps the lease, BPF LSM guard and same-filesystem move candidate in `edr-response-actions.md`. File leases, fanotify and pathname checks do not cover existing mappings by themselves. The candidate remains blocked until the stated lock-order and in-flight-operation tests pass.

For every OS, race existing descriptors, duplicated handles, executable and writable mappings, hard links, rename, unlink and replacement at each marker. A pass preserves a byte-identical encrypted copy, removes only the verified entry, leaves no accessible plaintext alias, and survives a crash. `in_use` is valid only when the action makes no partial quarantine claim.

## 6. Lineage file identity

Use native identity only as continuity evidence for the local random incarnation.

| OS | Candidate evidence | Required fallback |
|---|---|---|
| Linux | Filesystem UUID plus the opaque `name_to_handle_at` handle. Linux documents comparison across paths and demonstrates stale handles after inode reuse; fanotify can report the same handle ([file handles](https://www.man7.org/linux/man-pages/man2/name_to_handle_at.2.html), [fanotify FID](https://man7.org/linux/man-pages/man7/fanotify.7.html)). | Allocate a new incarnation on unsupported filesystems, `ESTALE`, mount-identity uncertainty or an observation gap. Do not decode the opaque handle. |
| Windows | Volume identity plus 128-bit `FILE_ID_INFO` from a live handle, joined to USN journal continuity. Microsoft documents equality for open handles, but file IDs may be reused or change over time ([FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info), [reuse limit](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_id_extd_both_dir_information), [USN record](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-usn_record_v3)). | Allocate a new incarnation after journal deletion, wrap, gap, unsupported volume or any discontinuity. |
| macOS | Volume identity plus `ATTR_CMN_OBJPERMANENTID` when the volume reports support. Apple documents persistence across mounts and a root-visible generation field ([getattrlist](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man2/getattrlist.2)). Use Endpoint Security's `stat` only as an event-time lookup hint ([ES file stat](https://developer.apple.com/documentation/endpointsecurity/es_file_t/stat)). | Allocate a new incarnation when the attribute is unsupported, zero or unstable, or an event gap prevents continuity. FAT and exFAT require their own qualification. |

The identity experiment creates a file, opens aliases and hard links, renames it, unmounts and remounts, deletes it, forces identifier reuse, and creates a replacement with identical bytes and metadata. A pass joins aliases and renames while the original lives, never joins the replacement, and starts a new incarnation after every induced sensor or journal gap. Run it on every required filesystem unit.

## 7. Safe implementation slices

The following slices do not depend on an unresolved enforcement claim:

- Preserve the macOS PID-reuse fixture for any future public termination API. A private-SPI probe may collect research evidence but cannot enable the action.
- Add native file-identity probe fixtures and capability records. Keep the random incarnation authoritative.
- Build exact-byte adversarial test programs for descriptors, mappings, direct I/O and substitution before a gate implementation.
- Build browser and clipboard bypass fixtures that report failure without enabling a blocking claim.
- Prototype Windows, Linux and macOS 26 FSKit staging behind a disabled capability flag.

Do not implement clipboard blocking, fallback browser blocking, macOS general file blocking, macOS script completion or quarantine success from the current evidence. Those claims remain release blockers.
