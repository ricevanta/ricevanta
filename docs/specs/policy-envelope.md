# Policy envelope

The one resource format for MDM desired state, EDR detection and DLP enforcement, the compiled bundle agents receive, and the signatures on bundles and commands. Conditions use the CEL profile (`cel-profile.md`); events use the OCSF profile (`ocsf-profile.md`). Machine-readable schema: `schemas/policy/v1alpha1/`. Decision: POL-02.

## 1. Resources

All resources share the Kubernetes object shape: `apiVersion`, `kind`, `metadata`, `spec`, and a server-written `status` that is never part of signed content or GitOps files.

| Kind | Purpose | Home of the detail |
|---|---|---|
| `Policy` | One rule: scope, trigger, detectors, condition, actions, enforcement | This file |
| `Exception` | An exemption that policies reference by name, so it survives policy updates and has its own audit trail | This file |
| `RulePack` | A versioned, signed package of native rules (Sigma, YARA, PII recognizers, secrets patterns) with its license record | Section 5 |
| `Baseline` | MDM desired state: configuration items an `mdm` policy applies | MDM-01; the MDM design, written before v0.2.x (`../roadmap.md`) |
| `DeviceGroup`, `ExportDestination` | Targets, SIEM destinations | The backend design with inventory (v0.2.x) and the events export design (v0.8.x), `../roadmap.md` |

`metadata.name` is a DNS-1123 label unique per organization and kind. `metadata.labels` are identifying key-value pairs that selectors can match; `metadata.annotations` are free text; `metadata.description` is shown in the console.

## 2. Policy

```yaml
apiVersion: ricevanta.io/v1alpha1
kind: Policy
metadata:
  name: dlp-block-confidential-upload
  labels: { domain: dlp, regulation: vn-pdpl }
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
  references:
    - { regulation: vn-pdpl, article: "11" }   # DLP-03
  mitre: [T1567]
```

### 2.1 Field rules

- `scope.include` is a list of selectors joined by OR; each selector's fields are joined by AND; `exclude` always wins. Selector fields: `devices` (`names`, `groups`, `matchLabels`, `matchExpressions` with `In`, `NotIn`, `Exists`, `DoesNotExist`), `users` (`names`, `groups`), `os` (`macos`, `windows`, `linux`, each with an optional minimum version). The compiler resolves device and user group membership at compile time into the bundle's group snapshot; the agent matches users at evaluation time against that snapshot, so a group change takes effect at the next bundle.
- `trigger.events` names OCSF classes and activities as `<class>.<activity>`, where `<activity>` is the activity caption in lower snake case (`file_activity.create`, `process_activity.launch`); extension classes use `<extension>/<class>.<activity>`. `trigger.correlation` (edr only) adds `window`, `groupBy` (CEL field paths over `event`; absent means all matching events count together) and `threshold`; the compiler adds the correlated events to the scope's upload set so the server receives them under the default telemetry profile. `trigger: { state: { baseline: <name> } }` is for `mdm` only.
- `detectors` reference rules in `RulePack` resources as `<pack>/<rule>` or `<pack>/*`, optionally pinned to a pack version; a reference to a pack the scope does not receive, or a pinned version that lacks the rule, fails validation at publish; a wildcard that matches no rule is a validation warning and a compile report; a rule the adapter could not translate (`report.json`) is skipped with a report and the policy compiles without it; a pack later withdrawn from a scope excludes the policy from that scope's bundle with a report.
- `minConfidence` is the detector confidence below which the policy does not match (blueprint section 4); `condition` is CEL within the profile over the domain's variables, `true` when absent.
- `actions` are objects `{ type, params }` from the domain catalogue (section 4); order is not significant.
- `mode: monitor` evaluates and records the outcome and performs no action; `disabled` compiles nothing. Neither takes part in conflict resolution.
- `priority` resolves conflicts between enforcing policies that match the same event: the highest priority decides; at equal priority the stricter decision wins (`block` over `warn` over `allow`). A policy whose exception matches leaves conflict resolution for that event rather than voting `allow`, so it cannot suppress another policy.
- Per-domain field rules, enforced by the schema: `mdm` and `pki` policies carry no `detectors`, `enforcement` or `evidence`; `lineage` policies carry no `detectors` or `enforcement`; `network` policies carry no `detectors` or `evidence`; `edr` and `dlp` policies may carry all three. Required fields are `domain`, `scope` and `trigger`. Defaults: `mode: enforce`, `priority: 500`, `minConfidence: 0.9`, `severity: medium`, `enforcement.fail: open`, `enforcement.deadline: 2s`, `enforcement.unsupported: alert`, `evidence.snippet: true`. An `Exception` requires `domain`, `scope` and `justification`. A file that carries `status` is rejected by `ricevanta apply`.
- A policy with no `scope` applies nowhere and cannot be published. Size caps live in the schema.

### 2.2 Enforcement placement

The compiler labels every enforcing policy as point-enforceable or core-evaluated (AG-06). A policy is point-enforceable when it has no detectors and its condition uses only the rule-only subset: `&&`, `||`, `!`, and the comparisons `==`, `!=`, `in`, `startsWith` and `endsWith` over `event.file.path`, `event.actor.process.file.path`, `event.actor.process.file.signature.certificate.subject`, `destination.kind` and `user.uid`, with `device.labels`, `device.groups` and user group selectors resolved per device at compile time (the kernel sees a uid, not a group). Such policies compile into the path, process, signer, destination-kind and uid rules installed in the Endpoint Security extension, the driver and the BPF maps and decide without the core. Everything else, including `matches`, command lines and destination hosts (which BPF cannot see at connect time), is evaluated in the core within `enforcement.deadline` under the declared fail mode. The console shows the label on each policy.

### 2.3 Changes that weaken enforcement

For `dlp` and `edr` policies the compiler compares the compiled outcome before and after a diff and classifies it as a protected action under BE-02 when any device leaves enforcement or any outcome becomes less strict, whether the diff arrives from the console, the API or GitOps. That covers attaching an exception, setting `mode` to `monitor` or `disabled`, adding or widening `exclude`, narrowing `include` or `trigger.events`, editing `condition`, raising `minConfidence`, removing detectors, downgrading an action, lowering `priority`, lengthening `deadline`, changing `fail` from `closed` to `open`, deleting the policy including by `prune`, publishing or raising the priority of a policy whose actions include `allow`, and creating or widening an `Exception`. Publishing a policy whose actions include `isolate_host`, `revoke` or `kill_process` is protected; its automatic executions are not.

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

An exception matches when its scope and condition hold; `domain` fixes the variable environment its condition is validated against. A matching exception removes the referencing policy from the decision for that event and records an audit event naming the exception. Exceptions with `expires` stop matching after that time: the compiler drops an expired exception from new bundles using server time, and the agent also checks its own clock, so a clock set back on an offline device prolongs an exception only until the next bundle, which the missed-check-in alerts bound; a device whose reported clock drifts is flagged. The console flags expiring exceptions a week ahead.

## 4. Execution semantics per domain

| Domain | Trigger | Evaluated by | Actions and parameters |
|---|---|---|---|
| `edr` | Telemetry events; `correlation` for server-side rules | Agent (single-event), server (correlation, EDR-01) | `alert`; `kill_process`; `quarantine_file`; `isolate_host`; `block_process` with `by: hash` or `by: signer`; `collect` with `package` (triage package name) |
| `dlp` | Authorization events on file, clipboard, peripheral, browser and network channels | Agent, synchronously within `deadline` | `allow`; `warn`; `block`; `alert`; `redact_clipboard` |
| `mdm` | `state`, naming a `baseline` | Agent on check-in and on change; the server records compliance | `apply`; `report` (compliance only) |
| `lineage` | Lineage events | Server | `alert`; `tag` with `label` (classification inheritance) |
| `pki` | Certificate lifecycle events | Server | `alert`; `revoke` with `reason` |
| `network` | RADIUS authorization | Server | `accept`; `reject`; `vlan` with `profile` (attribute profile name); `alert` |

`warn` presents a prompt with an override where a channel has one (browser upload, clipboard, removable media through the session helper); the user's choice and justification are recorded. On channels that cannot prompt within the OS deadline (file-system and process authorization) `warn` is `allow` plus a user notification and an audit event, and the compiler reports that downgrade on the policy. Correlation in v0.1.x is a count of matching events per `groupBy` key within `window` reaching `threshold`; the remaining Sigma correlation types (`value_count`, `temporal`, `temporal_ordered`) arrive with the rule adapters in v0.8.x (`../roadmap.md`), the release that completes correlation under SH-01.

## 5. RulePack

`spec.format` (`sigma`, `yara`, `pii`, `secrets`, `osquery`, `falco`), `spec.version` (SemVer), `spec.license` (SPDX identifier, author and attribution text, required), `spec.source` (URL and upstream commit), and `spec.content`: a reference to an archive in the blob store with its SHA-256, holding the native rule files under `rules/` and, after adaptation, the translation under `compiled/` with a `report.json` naming every rule the adapter could not translate and why. Publishing a pack to a scope is a protected action (BE-02). Untranslatable rules are listed in the console and never silently dropped. Sigma rules under DRL 1.1 carry their author through to every match (`../licensing.md`).

## 6. Compiled bundle and device assignment

A compilation scope is the set of devices that resolve to the same set of policies, exceptions, rule packs and baselines; the compiler partitions the organization's devices into such sets and `scope_id` is the hash of the set's resolved resource list, so devices with identical policy receive one bundle. The server compiles each scope into one bundle:

```
bundle/
├── manifest.json        organization, bundle_uid, scope_id, bundle_format, issued, files[{path, sha256, size}]
├── envelope.json        DSSE signature over manifest.json (section 7)
├── policies/<domain>.json   compiled policies: resolved scope, placement label, CEL source, actions, enforcement, exception references
├── exceptions.json
├── groups.json          snapshot of user and device group membership the scope was resolved against
├── rulepacks/<pack>/    native rules and the adapter's translation
├── baselines/<name>.json
├── budgets.json         resource budgets (AG-08) and the telemetry profile (EV-01) for the scope
└── variables.json       CEL variable declarations the conditions were validated against (cel-profile.md section 5)
```

The policy response carries three artifacts: the assignment DSSE envelope, the policy-signing certificate chain, and the opaque zstd-compressed tar bytes. The assignment payload contains the SHA-256 of the final archive bytes. Inside the archive, `manifest.json` is the exact payload of `envelope.json`; `manifest.json.files` lists every other archive member and excludes `manifest.json` and `envelope.json`. No signed object contains its own hash or the hash of its signature.

The agent verifies the artifacts in this order:

1. Validate the supplied signing certificate chain against the pinned root and the issuing-CA, subject, key-usage and CRL-freshness rules of `../design/pki.md` section 4, then verify the assignment signature and its organization, device, bundle and sequence fields.
2. Hash the opaque archive bytes and compare the result with `bundle_sha256` in the assignment before opening the archive.
3. Read only `manifest.json` and `envelope.json` through a bounded archive reader, reject duplicate paths, links, non-canonical paths and any path that leaves the bundle directory, and verify that the manifest fields equal the assignment's organization, scope and bundle identifiers.
4. Verify that `envelope.json` has the bundle-manifest payload type and contains the exact bytes of `manifest.json`, then verify its signature with the already validated signing certificate.
5. Extract only members listed once in `manifest.json.files`, enforcing each declared size, hash and a total decompressed-size limit of 256 MB by default. Reject missing, duplicate or extra members other than the two control members and install only after every check succeeds.

Because an agent cannot know which scope it belongs to, `jobs` issues each device a signed assignment alongside the bundle: `{ organization, device_uid, scope_id, bundle_uid, bundle_sha256, sequence, issued }` in a DSSE envelope. `sequence` is one counter per organization, incremented on every assignment, so a device moved to another scope still sees a higher value. The agent installs a bundle only when the assignment's `device_uid` is its own, its `sequence` is greater than the installed one, and the bundle's hash matches; a bundle served without a valid assignment is refused, so a stolen `agent`-role TLS key cannot serve another scope's bundle (`../architecture.md` section 4). The signing certificate is verified under `../design/pki.md` section 4 at install time. Bundles and assignments have no expiry: a cached bundle stays in force offline (AG-05). Every check-in carries the installed assignment envelope (`../architecture.md` section 3.4), which `jobs` verifies against the signing certificate before reading its sequence, so a device cannot report a sequence it was never issued. After a server restore from backup, `jobs` refuses to issue assignments for 24 hours or until an administrator confirms a floor; the floor is the highest verified sequence presented since the restart, a later verified higher value raises it, and the counter resumes above the floor so every device accepts its next assignment.

## 7. Signatures

Bundle manifests, assignments, commands and dispatch grants use DSSE envelopes (specification under Apache-2.0, verify). Their `payloadType` values are `application/vnd.ricevanta.bundle-manifest+json`, `application/vnd.ricevanta.assignment+json`, `application/vnd.ricevanta.command+json` and `application/vnd.ricevanta.command-dispatch-grant+json`. `payload` is the base64 document; each signature carries `keyid`, the SHA-256 fingerprint of the signing certificate, used only as a hint to pick the certificate, and `sig` over the DSSE pre-authentication encoding. Verification always checks the certificate chain, not the `keyid`.

A command payload binds `organization`, `device_uid`, `command_uid`, `command_seq`, `type`, `params`, `approval_id` where BE-02 applies, `issued` and `expires`, with `expires` at most 7 days after `issued`. `command_seq` is a per-device counter that orders execution and lets the server reconcile delivery. A protected-action request has an immutable `request_uid`, frozen device targets, exact canonical command fields and one preallocated immutable `command_uid` per frozen device. Approval binds the request uid, the hash of those approved fields and the complete set of `(device_uid, command_uid)` pairs, and authorizes one command for each pair and no other command or target.

Command creation locks the approved target pair and the device counter in one transaction. The transaction verifies the approval and exact field hash, allocates `command_seq`, persists the signed command, and marks that target pair consumed. A retry by `request_uid`, `device_uid` and `command_uid` returns the same persisted command and sequence. A consumed pair, a different command uid, changed fields or a device outside the frozen target set cannot create another command. A bulk action therefore produces one authorized immutable command per frozen device while consuming each target authorization exactly once.

Each long poll carries a fresh 256-bit `poll_nonce`, which the agent associates with a monotonic start time. Before returning a command, the `agent` role requests a dispatch grant from `jobs`. A grant binds `{ organization, device_uid, poll_nonce, command_envelope_sha256, command_uid, command_seq, open_seqs, grant_uid, valid_for_ms }`, where the hash covers the exact signed command envelope returned with the grant and `open_seqs` lists the sequences of this device's commands that are non-terminal on the server: issued, unexpired and without a verified terminal result. `jobs` reloads the command, target and approval from authoritative rows, verifies their binding, checks `expires` against database time, refuses a grant for a command whose signed result it has already verified, and sets `valid_for_ms` to the smaller of the command's remaining lifetime and 120,000 ms. The grant is the freshness guard and the journal below is the replay guard: the agent accepts a command only on the outstanding poll that created the grant's nonce, before `valid_for_ms` has elapsed from the poll's monotonic start, and when the grant's hash, command identity and signatures match the received envelope. For a command with at least 120 s of life left, the 50-second default hold leaves at least 70 seconds for delivery; if the budget elapsed during a longer hold, the agent rejects the response and polls again with a new nonce. The local wall clock never decides freshness. A compromised delivery role can delay or drop a response, but cannot obtain a grant after server expiry or reuse one on another poll, command or device. The cost is one `jobs` round trip and one signature per delivery, which puts the jobs leader on the command path; its latency and throughput are measured in `platform-qualification.md` section 7.

Before acknowledgement or execution, the agent writes a `FULL`-synchronous journal row keyed by `command_uid`, containing `command_seq`, the command hash and the state (`received`, `running`, `succeeded`, `failed`, `refused` or `cancelled`). A command whose uid has a terminal row is answered from that row and never executed again, which is the replay guard; a `received` or `running` row with the same hash accepts a fresh grant and continues; a row with the same uid and a different hash is refused and reported. Terminal rows are kept for 30 days, longer than any command's lifetime, so a command can neither be granted nor re-executed after its row is compacted. The agent executes in increasing `command_seq`: a command waits while a lower sequence named in the grant's `open_seqs` has no terminal journal row, and a lower sequence absent from `open_seqs` is void (expired or cancelled on the server), so a dropped predecessor never blocks and an undo never runs before the action it undoes. Execution starts only inside an open grant window for the command: a waiting command whose window elapses stays `received`, is re-granted on a later poll while the server still holds it unexpired, and is otherwise marked undelivered, so a held command never starts after the server's view of its expiry. Each command type defines idempotency and reconciliation for `received` and `running` rows after a crash or cancellation; the agent never blindly repeats or declares completion of a side effect in `running` state, and a command type without a tested recovery contract blocks release. Cancellation is a command of its own type naming the uid it cancels; it is exempt from the ordering rule, so it reaches a running command, and the cancelled type's reconciliation decides whether a running action can stop.

Dropped commands are detected on the server, not by the agent. Command results and the check-in's journal report are JWS-signed by the device identity key, and `jobs` verifies the signature before it marks a command delivered or terminal, so a role that forwards them can drop a report but cannot forge one; each report carries a per-device counter that must exceed the last verified one, so an older report cannot be replayed either. The report carries the highest journaled `command_seq`, the non-terminal uids and the terminal uids since the last verified report; `jobs` compares it with the commands it issued, marks a command the device has not journaled by its `expires` as undelivered, raises an audit event, and the console shows the device's open commands. A device that reports a sequence or uid the server never issued is flagged.

Verifier acceptance fixtures cover these invariants:

- Reusing one approval for a second command, changing approved fields, substituting a command uid or adding a bulk target creates no command; an identical retry returns the original signed command and sequence.
- Each device in a frozen bulk request receives exactly its preallocated command uid once, and partial transaction retries neither duplicate nor omit a consumed target authorization.
- A command replayed on a later poll is answered from its journal row without execution; a grant after `valid_for_ms` or for another device, nonce or hash is refused and reported.
- An undo command delivered before the command it undoes waits until that command's row is terminal, and runs under a fresh grant when a grant's `open_seqs` marks the predecessor void; a command whose grant window elapsed while it waited never starts without a new grant.
- An unsigned or forged journal report or command result is refused by `jobs` and leaves the command's server state unchanged.
- A crash between the journal write and execution resumes through the command type's reconciliation without repeating its side effect, and a command the device never journaled is marked undelivered on the server after its expiry.

## 8. GitOps

A GitOps directory holds one resource per file under `policies/`, `exceptions/`, `rulepacks/`, `baselines/`, `groups/`, `destinations/`. `ricevanta apply <dir>` validates every file against its schema (`Policy` and `Exception` under `schemas/policy/v1alpha1/`; the `RulePack`, `Baseline`, `DeviceGroup` and `ExportDestination` schemas are added with their designs) and the CEL profile and applies the three-way diff of BE-05; resources absent from a directory that declares `prune: true` in `ricevanta.yaml` are deleted, otherwise left in place; `--dry-run` prints the diff; protected diffs (section 2.3) become approval requests and the apply reports them as pending.

## 9. Versioning

Resource versions follow `../architecture.md` section 7. Within a version fields are only added, with defaults that keep stored resources valid. `bundle_format` is an integer versioned with `/agent/v1`.

## 10. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: one shape for every domain, so the console, the API, GitOps and the compiler share one validator; exceptions outlive the policies that use them without weakening other policies; the assignment binds a bundle to a device and an order, so replay and cross-scope substitution fail; enforcement-weakening changes cannot bypass approval; the placement label makes the enforcement-point split visible.

Trade-offs: one envelope with per-domain semantics needs per-domain schema constraints; group membership is frozen per bundle, so a group change waits for the next compilation; the assignment adds one small signed document per device per change.

Dependencies: the DSSE specification (Apache-2.0), JSON Schema 2020-12, the CEL and OCSF profiles.

Limits: `warn` is a notification, not a prompt, on file-system and process channels; correlation is count-based until v0.8.x; a policy cannot reference a rule from a pack the scope does not receive.

Alternatives considered: per-domain formats (rejected by SH-02: a later migration); inline exceptions as in Purview (rejected: they die with the policy and share its audit trail); the scope id inside the bundle alone (rejected: the agent cannot verify its own scope, so a stolen TLS key could serve any scope's bundle); OPA-style JWT bundle signatures (rejected: DSSE is simpler and shared with in-toto and Sigstore); a bundle expiry as in TUF (rejected for policy by AG-05; kept for commands and release manifests).
