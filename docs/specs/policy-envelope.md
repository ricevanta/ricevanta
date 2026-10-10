# Policy envelope

The one resource format for MDM desired state, EDR detection and DLP enforcement, the compiled bundle agents receive, and the signatures on bundles and commands. Conditions use the CEL profile (`cel-profile.md`); events use the OCSF profile (`ocsf-profile.md`). Machine-readable schema: `schemas/policy/v1alpha1/`. Decision: POL-02.

## 1. Resources

All resources share the Kubernetes object shape: `apiVersion`, `kind`, `metadata`, `spec`, and a server-written `status` that is never part of signed content or GitOps files.

| Kind | Purpose | Home of the detail |
|---|---|---|
| `Policy` | One rule: scope, trigger, detectors, condition, actions, enforcement | This file |
| `Exception` | An exemption that policies reference by name, so it survives policy updates and has its own audit trail | This file |
| `RulePack` | A versioned, signed package of native rules (Sigma, YARA, PII recognizers, secrets patterns) with its license record | Section 5 |
| `Baseline` | MDM desired state: configuration items an `mdm` policy applies | `baseline.md` |
| `SoftwarePackage` | One installer artifact: hash, expected signer, detection rule, install arguments, reboot and interaction | `../design/mdm.md` section 4.1 |
| `ReportTemplate` | Declarative report: parameters, datasets, layout | `report-template.md` |
| `Extension` | An installed extension package: source URL and SHA-256, requested grants, approved under `../design/extensions.md` section 2.2, target scopes | `../design/extensions.md` sections 2 and 8 |
| `DeviceGroup` | Static members and label selectors for scopes, RBAC and rollouts | `../design/mdm.md` section 1.1 |
| `ExportDestination` | SIEM destinations | `event-export.md` section 1 |
| `NetworkAccessProfile`, `RadiusGateway` | RADIUS outcome attributes; gateway registrations (secrets never in GitOps) | `radius-gateway-profiles.md` section 2; `../design/radius.md` section 5 |

`metadata.name` is a DNS-1123 label unique per organization and kind. `metadata.labels` are identifying key-value pairs that selectors can match; `metadata.annotations` are free text; `metadata.description` is shown in the console.

## 2. Policy

```yaml
apiVersion: ricevanta.io/v1alpha1
kind: Policy
metadata:
  name: dlp-block-confidential-upload
  labels: { domain: dlp, team: finance }
  description: Block uploads of restricted documents to unmanaged destinations
spec:
  domain: dlp                      # mdm | edr | dlp | lineage | pki | network
  mode: enforce                    # enforce | monitor | disabled
  priority: 500                    # 0 to 1000; higher wins on conflict
  scope:
    include:
      - devices: { matchLabels: { fleet: corporate } }
      - users: { groups: [finance] }
    exclude:
      - devices: { names: [build-server-01] }
  trigger:
    events: [file_activity.create, clipboard_activity.write, http_activity.post]   # OCSF class.activity, section 2.1
  detectors:
    - ref: confidential-docs/*             # <pack>/<rule or *>[@<pack version>]
    - ref: pii-vn/national-id@1.2.0
  minConfidence: 0.9
  condition: >
    match.classification == "restricted" && !destination.managed
  actions:
    - type: block
    - type: alert
  enforcement:
    fail: open                     # open | closed (AG-06)
    unsupported: alert             # alert | report; the gap is always listed in the console
    deadline: 2s
  exceptions: [dlp-finance-sharepoint]
  severity: high                   # informational | low | medium | high | critical
  evidence:
    snippet: true                  # DLP-02: redacted, at most 200 characters; default true
  reference: internal-policy-11        # free text, DLP-03
  mitre: [T1567]
```

### 2.1 Field rules

- `scope.include` is a list of selectors joined by OR; each selector's fields are joined by AND; `exclude` always wins. Selector fields: `devices` (`names`, `groups`, `matchLabels`, `matchExpressions` with `In`, `NotIn`, `Exists`, `DoesNotExist`), `users` (`names`, `groups`), `os` (`macos`, `windows`, `linux`, each with an optional minimum version). The compiler resolves device and user group membership at compile time into the bundle's group snapshot; the agent matches users at evaluation time against that snapshot, so a group change takes effect at the next bundle.
- `trigger.events` names OCSF classes and activities as `<class>.<activity>`, where `<activity>` is the activity caption in lower snake case (`file_activity.create`, `process_activity.launch`); extension classes use `<extension>/<class>.<activity>`. `trigger.correlation` (edr only) adds `window`, `groupBy` (CEL field paths over `event`; absent means all matching events count together) and `threshold`; the agent adds events matching the policy's single-event part to the scope's upload set, tagged in `metadata.rule_matches`, so the server receives them under the default telemetry profile (`../design/policy.md` section 4). `trigger: { state: { baseline: <name> } }` is for `mdm` only.
- `detectors` reference rules in `RulePack` resources as `<pack>/<rule>` or `<pack>/*`, optionally pinned to a pack version; a reference to a pack the scope does not receive, or a pinned version that lacks the rule, fails validation at publish; a wildcard that matches no rule is a validation warning and a compile report; a rule the adapter could not translate (`report.json`) is skipped with a report and the policy compiles without it; a pack later withdrawn from a scope excludes the policy from that scope's bundle with a report. An extension `classifier` is referenced as `ext/<extension id>/<component>` in `detectors`, and `spec.parsers: [{ mime, ref }]` assigns an extension `parser` to a declared MIME type in `edr` or `dlp`. Parser entries require a lowercase MIME type without parameters or wildcards and an exact `ext/<extension id>/<component>` reference; at most 32 entries are allowed. The compiler checks the installed component kind, declared MIME type and scope grant (`../design/extensions.md` section 3.3).
- `minConfidence` is the detector confidence below which the policy does not match (blueprint section 4); `condition` is CEL within the profile over the domain's variables, `true` when absent.
- `actions` are objects `{ type, params }` from the domain catalogue (section 4); order is not significant.
- `mode: monitor` evaluates and records the outcome and performs no action; `disabled` compiles nothing. Neither takes part in conflict resolution.
- `priority` resolves conflicts between enforcing policies that match the same event across point and core placements: the highest priority decides; at equal priority the stricter decision wins (`block` over `warn` over `allow`). A policy whose exception matches leaves conflict resolution for that event rather than voting `allow`, so it cannot suppress another policy. Placement changes where a predicate runs, never its priority or exception semantics.
- Per-domain field rules, enforced by the schema: `mdm` and `pki` policies carry no `detectors`, `enforcement` or `evidence`; `lineage` policies carry no `detectors` or `enforcement`; `network` policies carry no `detectors` or `evidence` and have `enforcement.fail` fixed at `closed`, the schema rejecting `open`; `edr` and `dlp` policies may carry all three and `parsers`; other domains carry no `parsers`. Required fields are `domain`, `scope` and `trigger`. Defaults: `mode: enforce`, `priority: 500`, `minConfidence: 0.9`, `severity: medium`, `enforcement.fail: open` except `closed` for `network`, `enforcement.deadline: 2s`, `enforcement.unsupported: alert`, `evidence.snippet: true`. An `Exception` requires `domain`, `scope` and `justification`. A file that carries `status` is rejected by `ricevanta apply`.
- `reference` is free text of at most 1,024 characters, used as the classification category reference (DLP-03).
- Schema checks: `python3 schemas/policy/v1alpha1/validate.py` validates schema definitions, the positive and negative fixtures under `schemas/policy/v1alpha1/fixtures/`, and the Policy and Exception YAML examples in this file. The fixtures cover extension classifiers, parsers, category references and network fail mode.
- A policy with no `scope` applies nowhere and cannot be published. Size caps live in the schema.

### 2.2 Enforcement placement

The compiler labels every enforcing policy as point-enforceable or core-evaluated (AG-06) and builds one conflict plan for both placements. A policy is point-enforceable only when its condition and every referenced exception are evaluable at that point, including trusted expiry where needed. It has no detectors and uses only the rule-only subset: `&&`, `||`, `!`, and the comparisons `==`, `!=`, `in`, `startsWith` and `endsWith` over `event.file.path`, `event.actor.process.file.path`, `event.actor.process.file.signature.certificate.subject`, `destination.kind` and `user.uid`, with `device.labels`, `device.groups` and user group selectors resolved per device at compile time (the kernel sees a uid, not a group). Such predicates compile into the path, process, signer, destination-kind and uid rules installed in the Endpoint Security extension, the driver and the BPF maps. A point returns a final decision only when the compiler proves that every unresolved core-policy and exception outcome leaves the global decision and actions unchanged. Otherwise the point supplies its matching candidates to the core and holds the operation under the existing deadline and fail-mode contract. A local allow never bypasses an unresolved core block, and a local block never overrides a possible higher-priority core allow. Everything else, including `matches`, command lines and destination hosts (which BPF cannot see at connect time), is evaluated in the core even when the policy has no detectors. The console shows the predicate placement and whether the global conflict plan requires the core.

### 2.3 Changes that weaken enforcement

For `dlp`, `edr` and `network` policies the compiler compares the compiled outcome before and after a diff and classifies it as a protected action under BE-02 when any device leaves enforcement or any outcome becomes less strict, whether the diff arrives from the console, the API or GitOps. That covers attaching an exception, setting `mode` to `monitor` or `disabled`, adding or widening `exclude`, narrowing `include` or `trigger.events`, editing `condition`, raising `minConfidence`, removing detectors, downgrading an action, lowering `priority`, lengthening `deadline`, changing `fail` from `closed` to `open`, deleting the policy including by `prune`, publishing or raising the priority of a policy whose actions include `allow`, and creating or widening an `Exception`; for `network`, any change that lets a request reach `accept` that it did not reach before, including a new or higher-priority `accept`. A `DeviceGroup` membership or device label change through `/api/v1` that removes a device from an enforcing `dlp` or `edr` policy is classified the same way; directory-synced membership changes apply and raise an alert (`../design/policy.md` section 2.4). An inventory-driven change that removes a device from an enforcing `dlp` or `edr` policy, such as a lower OS or version report, raises the same alert and audit event as a directory change, and the compiler refuses an OS or version report lower than the device's last recorded value until an operator confirms it. Disabling, uninstalling or revoking an extension component that a compiled `dlp` or `edr` policy or a qualified browser adapter depends on is also a weakening change; revoking a publisher key is not held for approval, and the compiler raises an alert for every enforcing policy it weakens (`../design/extensions.md` section 2.5). Publishing a policy whose actions include `isolate_host`, `revoke` or `kill_process` is protected; its automatic executions are not.

Required compliance is also enforcement. A diff that weakens a required baseline check, its enforcing `mdm` report-policy scope or its exceptions is protected under BE-02 even when every item is read-only and no network policy changes. `baseline.md` section 5 binds the exact before and after required-set revisions and affected device uids. The compiler and `jobs` retain the approved required set until approval; an unapproved compliance diff cannot let an unchanged network policy reach `accept`.

## 3. Exception

```yaml
apiVersion: ricevanta.io/v1alpha1
kind: Exception
metadata:
  name: dlp-finance-sharepoint
spec:
  domain: dlp
  scope: { include: [ { users: { groups: [finance] } } ] }
  condition: destination.host.endsWith(".sharepoint.com") && destination.managed
  expires: "2027-01-31T00:00:00Z"
  justification: Approved finance workflow, ticket SEC-142
```

An exception matches when its scope and condition hold; `domain` fixes the variable environment its condition is validated against. A matching exception removes the referencing policy from the decision for that event and records an audit event naming the exception and its revision. The compiler records each exception's variable dependencies. A context-only exception may run before scanning when all its inputs exist; an exception using `match` waits for this operation's classification and coverage. Missing inputs or an evaluation error never grant an exemption: the exception does not match, and a policy-health event records the error. The policy then evaluates normally, including its fail mode for a policy or classification error.

An expiring exception needs a fresh signed time anchor from `jobs`, bound to the organization, device, accepted recovery epoch and a fresh request nonce. The agent records a suspend-inclusive monotonic start before requesting the anchor and accepts the response only for that outstanding request within 120 seconds. If the signed server time is `T` and the request began at monotonic `M`, the expiry check uses the conservative upper time bound `T + (current_monotonic - M)`. This includes delivery delay and later suspend time; the local wall clock cannot extend the exemption. At or beyond `expires`, the agent synchronously persists an expired marker for that exception revision before the next decision. A later clock change or anchor cannot reactivate that revision. A new approved exception revision with a later expiry is a distinct grant.

After reboot, a lost anchor or uncertain monotonic continuity, expiring exceptions are inactive until a fresh anchor arrives. Non-expiring exceptions and cached enforcing policy remain active offline. A point lacking the same expiry guard must ask the core or treat the expiring exception as inactive; it cannot retain an unchecked allowance while the core is down. Server compilation removes expired exceptions and schedules recompilation at the earliest expiry. Missed-check-in and clock-drift alerts report loss of contact; they provide no expiry guarantee. The time-anchor encoding, signed-request flow, durable marker protocol and native suspend-inclusive clock choices remain implementation blockers in `../analysis.md` section 3. The console flags expiring exceptions a week ahead.

## 4. Execution semantics per domain

| Domain | Trigger | Evaluated by | Actions and parameters |
|---|---|---|---|
| `edr` | Telemetry events; `correlation` for server-side rules | Agent (single-event), server (correlation, EDR-01) | `alert`; `kill_process`; `quarantine_file`; `isolate_host` with `allow` and `release_after`; `block_process` with `by: hash`, `by: path` or `by: signer`; `collect` with `package` (triage package name) |
| `dlp` | Authorization events on file, clipboard, peripheral, browser and network channels | Agent, synchronously within `deadline` | `allow`; `warn`; `block`; `alert`; `redact_clipboard` |
| `mdm` | `state`, naming a `baseline` | Agent on check-in and on change; the server records compliance | `apply`; `report` (compliance only) |
| `lineage` | Lineage events | Server | `alert`; `tag` with `label` (classification inheritance) |
| `pki` | Certificate lifecycle events | Server | `alert`; `revoke` with `reason` |
| `network` | RADIUS authorization | Server (`radius` role) | `accept` with `profile` (a `NetworkAccessProfile`); `reject`; `alert` |

`warn` asks the user through `ricevanta-session` with parameters `timeout` (default 60 s, expiry cancels), `justification` (`required`, `optional`, `none`), `message` and `unattended` (`block` default, `allow`). Qualified hold points that can wait for a person hold the transfer. Qualified file-system and clipboard gates deny, then consume a one-time allowance on `Continue` for the exact-byte retry under `../design/dlp.md` section 6.3; file allowances expire after 60 s. Unresolved gates remain required release blockers under that design's sections 6.4 and 6.5. The user's choice and justification are recorded. On process authorization `warn` is `allow` plus a user notification and an audit event, and the compiler reports that downgrade on the policy. Count correlation, a count of matching events per `groupBy` key within `window` reaching `threshold`, arrives with the matcher in v0.4.x; the remaining Sigma correlation types (`value_count`, `temporal`, `temporal_ordered`, `value_sum`, `value_avg`, `value_percentile`; `rule-adapters.md` section 3) arrive with the rule adapters in v0.8.x (`../roadmap.md`), the release that completes correlation under SH-01.

## 5. RulePack

`spec.format` (`sigma`, `yara`, `pii`, `secrets`, `dictionary`, `fingerprint`, `osquery`, `falco`; `dictionary` and `fingerprint` are defined in `dlp-detectors.md` section 4 and `../design/dlp.md` section 4), `spec.version` (SemVer), `spec.license` (SPDX identifier, author and attribution text, required), `spec.source` (URL and upstream commit), and `spec.content`: a reference to an archive in the blob store with its SHA-256, holding the native rule files under `rules/` and, after adaptation, the translation under `compiled/` with a `report.json` giving every rule's status per OS and its reason codes (`rule-adapters.md` section 2). Publishing a pack to a scope is a protected action (BE-02); publishing signs a pack manifest (section 7) that the compiler verifies before it places the pack in a bundle (POL-07). Untranslatable rules are listed in the console and never silently dropped. Sigma rules under DRL 1.1 carry their author through to every match (`../licensing.md`).

## 6. Compiled bundle and device assignment

A compilation scope is the set of devices that resolve to the same set of policies, exceptions, rule packs and baselines; the compiler partitions the organization's devices into such sets and `scope_id` is the hash of the set's resolved resource list, so devices with identical policy receive one bundle. The server compiles each scope into one bundle:

```
bundle/
├── manifest.json        organization, bundle_uid, scope_id, bundle_format, issued, files[{path, sha256, size}]
├── envelope.json        DSSE signature over manifest.json (section 7)
├── policies/<domain>.json   compiled policies: resolved scope, placement label, CEL source, actions, enforcement, exception references
├── exceptions.json
├── groups.json          snapshot of user and device group membership the scope was resolved against
├── rulepacks/<pack>/<version>/<pack_digest>/   native rules and the adapter's translation
├── dlp/catalogue.json   classification categories, labels, thresholds and regulatory references (../design/dlp.md section 5.1)
├── baselines/<name>.json
├── budgets.json         resource budgets (AG-08), including each extension module's granted budget, the telemetry profile (EV-01) and the telemetry collection set (../design/edr.md section 1.1) for the scope
├── intel.json           intel sets the scope receives, their size caps and the sequence the bundle was compiled against (../design/edr.md section 8.3)
├── extensions.json      enabled agent-bound components: id, version, package digest, component, kind, interface version, file hashes, granted capabilities and monotonic component grant_generation; separate browser registration digest and registration_generation where applicable
├── extensions/<id>/<version>/   browser adapters and WebAssembly modules named in extensions.json
└── variables.json       CEL variable declarations the conditions were validated against (cel-profile.md section 5)
```

Each resolved rule reference carries the immutable identity `{pack, version, pack_digest, rule_key}`, where `pack_digest` is the SHA-256 of the exact published pack manifest payload. A published `(pack, version)` is immutable; different content requires another version. After verifying the pack manifest, scope compilation attaches the full identity to resolved matcher entries, correlation references, match tags and findings. Pack-local compiled templates omit their own manifest digest and receive it from the verified scope context, so the manifest and compiled-output hashes have no cycle. Concurrent versions use separate artifact paths and cannot overwrite or satisfy each other. Unpinned authoring references resolve to an identity at compilation; changing the published version never reinterprets queued events.

Extension components reach agents only this way. Content components are compiled like their native kinds (an extension's rule pack lands under `rulepacks/`); browser adapters and modules sit under `extensions/` and are listed in `manifest.json.files` like every other member, so the bundle signature covers them. Every entry in `extensions.json` carries the signed bundle's `recovery_epoch` beside its component `grant_generation`, which the server increments on every grant write even when later capabilities equal an earlier grant. The browser registration generation remains a separate field. The agent never verifies an extension publisher's key (`../design/extensions.md` section 2.4).

The policy response carries three artifacts: the assignment DSSE envelope, the policy-signing certificate chain, and the opaque zstd-compressed tar bytes. The assignment payload contains the SHA-256 of the final archive bytes. Inside the archive, `manifest.json` is the exact payload of `envelope.json`; `manifest.json.files` lists every other archive member and excludes `manifest.json` and `envelope.json`. No signed object contains its own hash or the hash of its signature.

The agent verifies the artifacts in this order:

1. Validate the supplied signing certificate chain against the pinned root and the issuing-CA, subject, key-usage and CRL-freshness rules of `../design/pki.md` section 4, then verify the assignment signature and its organization, device, bundle, recovery epoch and sequence fields. A higher epoch requires the verified quorum transition chain before any assignment can install.
2. Hash the opaque archive bytes and compare the result with `bundle_sha256` in the assignment before opening the archive.
3. Read only `manifest.json` and `envelope.json` through a bounded archive reader, reject duplicate paths, links, non-canonical paths and any path that leaves the bundle directory, and verify that the manifest fields equal the assignment's organization, scope and bundle identifiers.
4. Verify that `envelope.json` has the bundle-manifest payload type and contains the exact bytes of `manifest.json`, then verify its signature with the already validated signing certificate and require its recovery epoch to equal the assignment's epoch.
5. Extract only members listed once in `manifest.json.files`, enforcing each declared size, hash and a total decompressed-size limit of 256 MB by default. Reject missing, duplicate or extra members other than the two control members and install only after every check succeeds.

Because an agent cannot know which scope it belongs to, `jobs` issues each device a signed assignment alongside the bundle: `{ organization, device_uid, scope_id, bundle_uid, bundle_sha256, recovery_epoch, sequence, issued }` in a DSSE envelope. `sequence` is one counter per organization inside the current recovery epoch, incremented on every assignment, so a device moved to another scope still sees a higher value. The agent installs a bundle only when the assignment's `device_uid` is its own, `(recovery_epoch, sequence)` is lexicographically greater than the installed pair, and the bundle's hash matches. A bundle served without a valid assignment is refused, so a stolen `agent`-role TLS key cannot serve another scope's bundle (`../architecture.md` section 4). The signing certificate is verified under `../design/pki.md` section 4 at install time. Bundles and assignments have no expiry: a cached bundle stays in force offline (AG-05). Every check-in carries the installed assignment envelope (`../architecture.md` section 3.4), which `jobs` verifies before reading its pair.

Restore follows `../design/backend.md` section 6.1. The external authority journal, not device reports, supplies the floors and all deny facts. Before the new epoch can sign, recovery replays committed revocations, disables, consumed enrollment and recovery tokens, consumed approvals and target pairs, command and report counters, compliance-statement counters, CRL numbers, assignment counters, extension grant and registration generations and signer state. A missing or ambiguous item stays `recovery_pending`; deny and consumption win, while a grant requires a new protected request and approval. The offline recovery transition binds the installation, organization, prior journal head, new head and epochs. An agent accepts a higher epoch only with the complete transition chain and the distinct custodian signatures required by the pinned root-signed recovery quorum manifest (`../design/backend.md` section 6.1). The agent stores the accepted epoch and transition hash synchronously before accepting replacement authority. An unavailable or unproved transition permits cached enforcement only; a disconnected agent cannot learn unseen deny facts. It keeps its cached policy while refusing new assignments, commands, releases, intel and extension grants from an old or unproved epoch.

## 7. Signatures

Bundle manifests, assignments, rule-pack manifests, commands, dispatch grants, compliance statements (`baseline.md` section 4.4), intel deltas (`../design/edr.md` section 8.3) and release objects use DSSE envelopes (specification under Apache-2.0, verify). Their `payloadType` values are `application/vnd.ricevanta.bundle-manifest+json`, `application/vnd.ricevanta.assignment+json`, `application/vnd.ricevanta.rulepack-manifest+json`, `application/vnd.ricevanta.command+json`, `application/vnd.ricevanta.command-dispatch-grant+json`, `application/vnd.ricevanta.compliance-statement+json`, `application/vnd.ricevanta.intel-delta+json` and `application/vnd.ricevanta.release+json`. Every installation-authority payload carries `recovery_epoch`; project release manifests use their separate release-key trust and version contract (`../design/agent.md` section 8). Each monotonic value is compared as `(recovery_epoch, counter)`. `payload` is the base64 document; each signature carries `keyid`, the SHA-256 fingerprint of the signing certificate, used only as a hint to pick the certificate, and `sig` over the DSSE pre-authentication encoding. Verification always checks the certificate chain, not the `keyid`.

The shared policy and command signing key cannot sign escrow acknowledgements or retirement authorizations because `api` also holds it and therefore cannot prove jobs-only durable-escrow verification. Escrow-acknowledgement and retirement-authorization issuance and acceptance and recovery-route retirement remain blocked until independently reviewed contracts adopt a dedicated jobs-only key and certificate profile, its trust, custody, rotation, recovery and retained-key rules, and acknowledgement and fresh retirement-authorization rules (`../design/mdm.md` section 12 and `mdm-evidence-recovery.md`).

A command payload binds `organization`, `device_uid`, `command_uid`, `recovery_epoch`, `command_seq`, `type`, `params`, `approval_id` where BE-02 applies, `issued` and `expires`, with `expires` at most 7 days after `issued`. `command_seq` is a per-device counter inside the epoch that orders execution and lets the server reconcile delivery. A protected-action request has an immutable `request_uid`, frozen device targets, exact canonical command fields and one preallocated immutable `command_uid` per frozen device. Approval binds the request uid, epoch, the hash of those approved fields and the complete set of `(device_uid, command_uid)` pairs, and authorizes one command for each pair and no other command or target.

A release object lets a device that cannot reach the server leave isolation or be uninstalled. Its payload binds `organization`, `device_uid`, `recovery_epoch`, `purpose` (`unisolate` or `uninstall`), `nonce`, `request_uid`, `approval_id` where BE-02 applies, `issued` and `expires`, with `expires` at most 7 days after `issued`. The nonce is 128 random bits that the agent generates when a local administrator asks its command-line tool for one, keeps in `state.db`, displays, and replaces at every request. The operator reads it from the device and files the matching request (`edr.unisolate_host` with the nonce among the approved fields, or the uninstall request of `../design/agent.md` section 9); the approval binds the device uid and the nonce, and `jobs` signs the object with the policy signing key only for an approved request, issuing it in place of a command. The operator types or pastes the object into the tool. The agent verifies the signature and the chain to the pinned root (`../design/pki.md` section 4), the device uid, the accepted recovery epoch, the purpose, the stored nonce and `expires`, discards the nonce and stores the SHA-256 of the object in `state.db`, so the object is accepted once and no other device, purpose or later nonce accepts it. An offline device cannot refresh its CRL, so the agent refuses a certificate listed in its cached CRL but does not apply the `nextUpdate` freshness refusal to release objects; a revoked key still cannot release a device without the nonce shown on it.

For `type: extension.respond`, canonical `params` bind the immutable package digest, component name and artifact digest, interface version, component `(recovery_epoch, grant_generation)`, allowed actions, canonical allowed entity identities and module input. The approval binds those same fields. A mutable extension id or version is descriptive only and cannot substitute for them. Before issuing a fresh dispatch grant, `jobs` reloads the installed extension and requires both values to equal the current component generation. Any grant write or recovery epoch makes the older command stale even when the new capability values match an earlier set.

Command creation uses the journal publication barrier of `../design/backend.md` section 6.1 and locks the approved target pair and the device counter in one transaction. The transaction verifies the approval and exact field hash, allocates `command_seq`, persists the signed command, and marks that target pair consumed. A retry by `request_uid`, `device_uid` and `command_uid` returns the same persisted command and sequence. A consumed pair, a different command uid, changed fields or a device outside the frozen target set cannot create another command. A bulk action therefore produces one authorized immutable command per frozen device while consuming each target authorization exactly once.

Each long poll carries a fresh 256-bit `poll_nonce`, which the agent associates with a monotonic start time. Before returning a command, the `agent` role requests a dispatch grant from `jobs`. A grant binds `{ organization, device_uid, recovery_epoch, poll_nonce, command_envelope_sha256, command_uid, command_seq, open_seqs, grant_uid, valid_for_ms }`, where the hash covers the exact signed command envelope returned with the grant and `open_seqs` lists the sequences in that epoch of this device's commands that are non-terminal on the server: issued, unexpired and without a verified terminal result. `jobs` reloads the command, target and approval from authoritative rows, verifies their binding, checks `expires` against database time, refuses a grant for a command whose signed result it has already verified, and sets `valid_for_ms` to the smaller of the command's remaining lifetime and 120,000 ms. The grant is the freshness guard and the journal below is the replay guard: the agent accepts a command only on the outstanding poll that created the grant's nonce, before `valid_for_ms` has elapsed from the poll's monotonic start, and when the grant's epoch equals the command and accepted local epoch and its hash, command identity and signatures match the received envelope. For a command with at least 120 s of life left, the 50-second default hold leaves at least 70 seconds for delivery; if the budget elapsed during a longer hold, the agent rejects the response and polls again with a new nonce. The local wall clock never decides freshness. A compromised delivery role can delay or drop a response, but cannot obtain a grant after server expiry or reuse one on another poll, command or device. The cost is one `jobs` round trip and one signature per delivery, which puts the jobs leader on the command path; its latency and throughput are measured in `platform-qualification.md` section 7.

Before acknowledgement or execution, the agent writes a `FULL`-synchronous journal row keyed by `command_uid`, containing `recovery_epoch`, `command_seq`, the command hash and the state (`received`, `running`, `succeeded`, `failed`, `refused` or `cancelled`). A command whose uid has a terminal row is answered from that row and never executed again, which is the replay guard; a `received` or `running` row with the same hash accepts a fresh grant and continues; a row with the same uid and a different hash is refused and reported. Terminal rows are kept for 30 days, longer than any command's lifetime, so a command can neither be granted nor re-executed after its row is compacted. An epoch transition cancels unstarted prior-epoch work and retains reconciliation duties for any running action; the server does not mix epochs in `open_seqs`. The agent executes in increasing `(recovery_epoch, command_seq)`: a command waits while a lower sequence named in the grant's `open_seqs` has no terminal journal row, and a lower sequence absent from `open_seqs` is void (expired or cancelled on the server), so a dropped predecessor never blocks and an undo never runs before the action it undoes. Execution starts only inside an open grant window for the command: a waiting command whose window elapses stays `received`, is re-granted on a later poll while the server still holds it unexpired, and is otherwise marked undelivered, so a held command never starts after the server's view of its expiry. Each command type defines idempotency and reconciliation for `received` and `running` rows after a crash or cancellation; the agent never blindly repeats or declares completion of a side effect in `running` state, and a command type without a tested recovery contract blocks release. Cancellation is a command of its own type naming the uid it cancels; it is exempt from the ordering rule, so it reaches a running command, and the cancelled type's reconciliation decides whether a running action can stop. An `extension.respond` row owns the immutable plan hash and per-step rows defined in `extension-agent-runtime.md` section 6. A fresh grant is required after restart; revocation forbids unstarted steps but never removes reconciliation duties for a running step.

Dropped commands are detected on the server, not by the agent. Command results and the check-in's journal report are JWS-signed by the device identity key, and `jobs` verifies the signature before it marks a command delivered or terminal, so a role that forwards them can drop a report but cannot forge one; each report carries a per-device `(recovery_epoch, report_counter)` that must exceed the last verified pair, so an older report cannot be replayed. The report carries the highest journaled command pair, the non-terminal uids and the terminal uids since the last verified report; `jobs` compares it with the commands it issued, marks a command the device has not journaled by its `expires` as undelivered, raises an audit event, and the console shows the device's open commands. A device that reports an epoch, sequence or uid the server never issued is flagged.

Verifier acceptance fixtures cover these invariants:

- Reusing one approval for a second command, changing approved fields, substituting a command uid or adding a bulk target creates no command; an identical retry returns the original signed command and sequence.
- Each device in a frozen bulk request receives exactly its preallocated command uid once, and partial transaction retries neither duplicate nor omit a consumed target authorization.
- A command replayed on a later poll is answered from its journal row without execution; a grant after `valid_for_ms` or for another device, nonce or hash is refused and reported.
- An undo command delivered before the command it undoes waits until that command's row is terminal, and runs under a fresh grant when a grant's `open_seqs` marks the predecessor void; a command whose grant window elapsed while it waited never starts without a new grant.
- An unsigned or forged journal report or command result is refused by `jobs` and leaves the command's server state unchanged.
- A crash between the journal write and execution resumes through the command type's reconciliation without repeating its side effect, and a command the device never journaled is marked undelivered on the server after its expiry.
- An `extension.respond` signature or grant with a substituted package digest, component, artifact, grant generation, action set or entity identity is refused. Crashes around plan persistence and every step boundary resume the stored plan without rerunning the module or a completed step; an unsafe unknown side effect halts for reconciliation.

## 8. GitOps

A GitOps directory holds one resource per file under `policies/`, `exceptions/`, `rulepacks/`, `baselines/`, `software/`, `groups/`, `destinations/`, `reports/`, `networkprofiles/`, `gateways/`, `extensions/`. An `Extension` resource carries `spec.source.url`, `spec.source.sha256`, `spec.grants` and `spec.targets`; applying it installs the package through the flow of `../design/extensions.md` section 2.2. `ricevanta apply <dir>` validates every file against its schema (`Policy` and `Exception` under `schemas/policy/v1alpha1/`; `Extension` under its required resource schema, `schemas/extension/v1alpha1/extension-resource.json`, absent and distinct from the package manifest schema; `ExportDestination` under `schemas/export/v1alpha1/export-destination.json` (`export-destination-schema.md`; Go validation and CI integration remain unimplemented); `ReportTemplate` under required, absent schemas in `schemas/report/v1alpha1/` (`report-template.md`); `Baseline`, `DeviceGroup` and `SoftwarePackage` follow `baseline.md` and `../design/mdm.md`; `NetworkAccessProfile` and `RadiusGateway` follow `radius-gateway-profiles.md`; the `RulePack` schema follows `../design/policy.md` section 6) and the CEL profile and applies the three-way diff of BE-05; resource validators other than `Policy`, `Exception` and `ExportDestination` remain blocked by the missing contracts in `../analysis.md` section 3; resources absent from a directory that declares `prune: true` in `ricevanta.yaml` are deleted, otherwise left in place; `--dry-run` prints the diff; protected diffs (section 2.3) become approval requests and the apply reports them as pending.

## 9. Versioning

Resource versions follow `../architecture.md` section 7. Within a version fields are only added, with defaults that keep stored resources valid. `bundle_format` is an integer versioned with `/agent/v1`.

## 10. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: one shape for every domain, so the console, the API, GitOps and the compiler share one validator; exceptions outlive the policies that use them without weakening other policies; the assignment binds a bundle to a device and an order, so replay and cross-scope substitution fail; enforcement-weakening changes cannot bypass approval; the placement label makes the enforcement-point split visible.

Trade-offs: one envelope with per-domain semantics needs per-domain schema constraints; group membership is frozen per bundle, so a group change waits for the next compilation; the assignment adds one small signed document per device per change.

Dependencies: the DSSE specification (Apache-2.0), JSON Schema 2020-12, the CEL and OCSF profiles.

Limits: `warn` is a notification on process channels and deny-then-approve on qualified file-system and clipboard gates; missing required gates remain release blockers (`../design/dlp.md` sections 6.4 and 6.5); correlation is count-based until v0.8.x; a policy cannot reference a rule from a pack the scope does not receive.

Alternatives considered: per-domain formats (rejected by SH-02: a later migration); inline exceptions as in Purview (rejected: they die with the policy and share its audit trail); the scope id inside the bundle alone (rejected: the agent cannot verify its own scope, so a stolen TLS key could serve any scope's bundle); OPA-style JWT bundle signatures (rejected: DSSE is simpler and shared with in-toto and Sigstore); a bundle expiry as in TUF (rejected for policy by AG-05; kept for commands and release manifests).
