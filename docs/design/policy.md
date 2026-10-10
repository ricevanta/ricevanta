# Policy design

How policies and rules move from an author to an enforcement decision: the authoring surfaces and the one validation path, compilation per scope and per domain, signing and distribution, installation and evaluation on the agent, the rule adapter framework, rule packs, testing and coverage, policy health and evaluation cost. The scope is blueprint section 4 and the "Central policy management" and "Rule-pack management" items of section 3.8 (`../blueprint.md`). Every format fact lives elsewhere: resources, execution semantics, the bundle, signatures, GitOps and versioning in `../specs/policy-envelope.md`; the condition language in `../specs/cel-profile.md`; events and the Sigma and Falco maps in `../specs/ocsf-profile.md`; per-format adapter rules in `../specs/rule-adapters.md`. Decisions: SH-02, POL-01 to POL-07, EDR-01, DLP-03, EXT-01, EXT-02, BE-02, BE-04, BE-05, AG-06, AG-08, AG-09 in `../decisions.md`. This file settles conflicts C7, C8 and C11 of `../analysis.md` on the policy side, its section 4 facts on `cel-go` defaults, the CEL profile's excluded cases and pySigma's license, and has no bullet of its own in section 3. Claims marked "verify" rest on a source that was not fully confirmed.

## 1. Data flow

```
console editor ─┐
ricevanta CLI  ─┼─> /api/v1 ─> policy: parse ─> schema ─> CEL (cel-go + cel crate) ─> cross-references
GitOps (CLI or  │                 └─> dry-run compile of affected scopes ─> weakening check (BE-02) ─> revision
server poll)   ─┘                        │                                     └─> approval request when protected
RulePack import ─> adapters (Go) ─> ricevanta-rulec (Rust engines) ─> report.json, tests ─> registry
                                         │
change events (resources, packs, groups, devices, grants, exception expiry)
  └─> compile queue ─> api: resolve scopes ─> per-domain compilers ─> bundle ─> sign (api) ─> store
        ├─> jobs: per-device assignment, organization `(recovery_epoch, sequence)` ─> NOTIFY ─> transport (agent role) ─> agents
        └─> server-evaluated sets: detection (correlation), lineage, pki, radius (network), mdm (native channels)
agent: verify assignment and bundle ─> diff per enforcement point ─> incremental install (AG-09)
  └─> evaluate: enforcement points (rule-only), core (matcher, CEL, conflict, exceptions), ricevanta-scan (detectors)
        └─> OCSF findings, policy_activity, rule matches for server correlation ─> events
```

The `policy` server module (BE-04) owns every box from parsing to the stored bundle and the rule-pack registry; `transport` serves bundles; the agent's `policy` module (`agent.md` section 1) owns verification, installation and evaluation.

## 2. Authoring and validation

### 2.1 Surfaces

All three surfaces call the same `/api/v1` handlers (BE-05), so a resource that validates in one validates identically in the others (`../specs/platform-qualification.md` section 4).

- Console editor: a YAML editor with schema-driven completion and a form view generated from the JSON Schema, CEL completion from the domain's variable declarations, the dry-run result inline, and the approval state of a protected change. Views are in `console.md`.
- `ricevanta` CLI: `validate`, `diff` (dry run), `apply`, `test` and `rulepack import`; output is the API's JSON or a text rendering.
- GitOps: the directory layout and three-way diff of `../specs/policy-envelope.md` section 8, applied by the CLI or by the server polling a repository. Each revision records the repository URL and commit. A resource last written by a GitOps source is read-only in the console; a console or API write to it needs an explicit ownership override, which is audited, and the next GitOps apply reports the drift and restores the repository state.

### 2.2 One validation path

Every write runs these stages in order and stops at the first failing stage, returning every error of that stage with its JSON path:

1. Parse: YAML 1.2 with duplicate keys, anchors, aliases and custom tags refused, under the schema's size caps.
2. Schema: JSON Schema 2020-12 from `schemas/policy/v1alpha1/`, which carries the per-domain field rules and defaults of `../specs/policy-envelope.md` section 2.1.
3. CEL: `cel-go` parses and checks each condition against the domain's declared variables with the profile's library only, then applies the profile limits and the cost estimate of `../specs/cel-profile.md` section 3. `cel-go` leaves `CrossTypeNumericComparisons` off and sets no cost limit unless configured (cel-go v0.31.0 source: `cel/options.go`, `cel/program.go`), so the server environment states both explicitly. `ricevanta-rulec` (POL-05) then parses the same bytes with the agent's `cel` crate; a condition is refused unless both parsers accept it and both runtimes return identical results on the profile fixtures and the condition's own examples. This second parse matters: the crate's conformance harness ignores the cel-spec `parse::whitespace` cases (new lines, tabs, carriage returns, form feeds) that the profile admits as lexical whitespace.
4. Cross-references: detector references resolve as `../specs/policy-envelope.md` section 2.1 defines; exceptions exist and share the policy's domain; baselines exist; network attribute profiles exist in the `radius` module; triage package names exist in `detection`; extension components exist, are enabled, are granted for every scope the policy reaches and serve the interface version the reference needs (`extensions.md` section 2.3); `mitre` values exist in the loaded ATT&CK dataset.
5. Dry-run compile of every scope the change affects (section 3): compile errors, budget overruns (section 9), placement labels, per-OS unsupported rules and every `warn` downgraded to a notification on process authorization (DLP-08).
6. Weakening classification (section 2.4).

A write passing all six stages becomes a revision, or an approval request when stage 6 marks it protected.

### 2.3 Dry run, diff and revisions

Every write endpoint accepts a dry run, which runs the six stages and stores nothing. The result is the diff a reviewer reads: per scope, the policies, exceptions, rule-pack versions and extension components added, removed or changed; the device count per OS that changes outcome; the unsupported rules per OS; and the protected classification with the reasons from section 2.4. `ricevanta apply --dry-run` prints it; the console shows it before submit and in every approval request.

Every accepted write stores an immutable revision: the resource without `status`, a per-resource `generation` that increases by one, the author, the surface, the GitOps commit where there is one, and the approval id. Writes carry `resourceVersion` for optimistic concurrency, so two editors cannot overwrite each other. A rollback writes the old content as a new revision and passes the same validation and weakening check; it is never a reinstall of an older bundle (`../specs/platform-qualification.md` section 4).

### 2.4 Weakening detection

For `dlp` and `edr` policies, a change is protected (BE-02) when it matches any change listed in `../specs/policy-envelope.md` section 2.3, judged on the resource diff, or when the dry-run compile shows a device leaving enforcement of a policy or an outcome becoming less strict on any scope. The first test needs no semantics: an edited `condition` counts as weakening without any attempt to prove implication between CEL expressions. The second catches indirect effects, such as a pack update that removes a rule an unpinned wildcard reference used. A manual `DeviceGroup` membership or device label change through `/api/v1` that removes a device from an enforcing `dlp` or `edr` policy is classified the same way. Directory-synced membership changes (SCIM and LDAP, BE-01) cannot wait for approval without breaking sync, so they apply, and each removal from an enforcing policy raises an alert and an audit event naming the policy and the device or user. Inventory-driven changes raise the same alert and audit event, and the compiler refuses an OS or version report lower than the device's last recorded value until an operator confirms it (`../specs/policy-envelope.md` section 2.3). Publishing or raising an `allow` policy, and publishing one with `isolate_host`, `revoke` or `kill_process`, follow the same section.

## 3. Compilation

### 3.1 Scope resolution

A compile reads one consistent snapshot of its inputs: resource revisions, published pack versions, extension grants with their generations, and device and user group membership through the `devices` and `identity` interfaces. It records their versions in a compile record. Compilation is deterministic: canonical JSON, sorted keys, a fixed archive member order and fixed timestamps, so the same inputs produce the same bundle hash and an unchanged scope yields no new bundle.

For each device the compiler evaluates every policy's `scope` selectors (`../specs/policy-envelope.md` section 2.1): device names, groups, labels and expressions; OS and minimum version from inventory, so an OS upgrade is a membership event; an OS or version report lower than the device's last recorded value is held for operator confirmation, and an inventory-driven removal from an enforcing `dlp` or `edr` policy is alerted and audited (section 2.4). The result is the device's resolved set of policies with the exceptions, pack versions, baselines and extension components they reference. Devices with equal sets form one compilation scope whose `scope_id` is the hash of the set (`../specs/policy-envelope.md` section 6). User selectors do not partition devices: the agent matches the user at evaluation time against the bundle's group snapshot, which holds only the user groups that the scope's policies name.

### 3.2 Conflicts and exceptions

The compiler applies the envelope's rules unchanged (`../specs/policy-envelope.md` sections 2.1 and 3) and prepares them for evaluation. For each trigger class it orders every enforcing policy across point and core placements by priority and then strictness. The first matching policy whose exceptions do not match fixes the priority level, and every matching policy at that level contributes its decision, the strictest winning. The compiler records policy and exception input dependencies in one conflict plan. A final point decision is permitted only when unresolved core outcomes cannot change the global decision or actions; otherwise the point supplies candidates to the core. Core-only context predicates run even without detectors. Policies in `monitor` mode record outcomes without voting. Exceptions run only after their required variables exist, and exception errors grant no exemption (`../specs/policy-envelope.md` sections 2.2 and 3). Exceptions leave new bundles after server expiry; installed bundles enforce the trusted expiry guard independently of reconnection.

### 3.3 Per-domain compilers

| Domain | Compiler output | Consumer |
|---|---|---|
| `mdm` | Desired state per device from each `Baseline`, split by delivery channel: agent-applied items into `baselines/`, Apple MDM and DDM declarations and OMA-DM settings handed to the `mdm` module through its interface; `check.query` SQL validated by `ricevanta-rulec` against the inventory table map (`../specs/baseline.md`); scheduled osquery-pack queries | Agent `mdm` module; server `mdm` module for native channels (MDM-01) |
| `edr` | Single-event policies with their matcher programs and CEL conditions into `policies/edr.json` and `rulepacks/`; correlation programs (`../specs/rule-adapters.md` section 3) handed to `detection` with the resolved `{pack, version, pack_digest, rule_key}` identities whose matches the agent tags and uploads | Agent core; server `detection` (EDR-01) |
| `dlp` | Channel decision tables with placement labels (AG-06), point rules per enforcement point, detector references, parser and classifier assignments, the scanner package (`pii` and `secrets` detectors, YARA sources) | Enforcement points, agent core, `ricevanta-scan`, `ricevanta-ext` |
| `lineage` | Server-evaluated rule set over lineage events | `lineage` module |
| `pki` | Server-evaluated rule set over certificate lifecycle events | `pki` module |
| `network` | Authorization table for RADIUS: scope-resolved policies with conditions over `device`, `user`, `certificate`, `gateway`, `access` and the authentication event, plus `NetworkAccessProfile` names | `radius` replicas, held in memory and refreshed on a version notification, so a request never reads shared state (BE-03) |

Server-evaluated sets are compiled from the same resources and validated by the same path. They are signed only where an agent consumes them, since the server modules read them from the `policy` module's interface rather than from an untrusted channel.

### 3.4 Incremental compile

The module keeps a dependency index: resource to scopes, pack version to policies, group and label to selectors, extension component to policies, and device to scope. A change event (a revision, a pack publication, a membership or inventory change from the bus, a grant write, an exception expiry, a signing-certificate rotation) marks the affected scopes dirty in a compile queue table. Events within a debounce window (default 2 s) coalesce, so a GitOps apply of 50 files compiles each affected scope once. Per-domain outputs are memoized by the hash of their inputs, so a DLP change does not rebuild the EDR matcher. Any `api` replica takes a scope's compile lease from the queue (BE-03: coordination only through PostgreSQL), because `api` holds the signing key (`../architecture.md` section 3.1); `jobs` and other modules only enqueue.

### 3.5 Bundle, signature, assignment and distribution

The compiler writes the bundle layout of `../specs/policy-envelope.md` section 6 with a new UUIDv7 `bundle_uid` and the current `bundle_format`, stages the signed manifest in `api` with the organization's policy signing key under the authority-journal publication barrier of `backend.md` section 6.1 (`../architecture.md` section 4; certificate rules in `pki.md` section 4) and stores the archive with its compile record. The module keeps the last 10 bundles per scope and every bundle a device reports as installed. `jobs` then issues a signed assignment with the next organization-wide `(recovery_epoch, sequence)` to each device whose bundle changed (`../specs/policy-envelope.md` section 6) and sends the policy-version notification. `transport` holds each scope's current bundle bytes in memory on the `agent` role and serves them by ETag. Agents learn of a new assignment from the check-in response and from the command long poll, which returns early with the new epoch and sequence, so a blocking change reaches online devices without waiting for the next check-in.

## 4. Agent side

1. Verification follows `../specs/policy-envelope.md` section 6 in the agent's `policy` module (`agent.md` section 1), including the CRL freshness rule of `pki.md` section 4; a refusal keeps the installed bundle and emits a `policy_activity` refusal event.
2. Preparation builds every runtime structure before anything is installed. CEL programs are parsed once by the `cel` crate, with the `matches` pattern cache filled (the crate compiles the pattern on every call: `cel/src/common/types/string.rs` at 0.15.0). The matcher evaluator gets per-class dispatch tables, one `aho-corasick` automaton over the prefilter literals and compiled regular expressions. Point rule sets are built per enforcement point. YARA sources are compiled by a `ricevanta-scan` instance into its compile cache, keyed by rules hash and YARA-X version. Detectors, osquery schedules, baselines and extension components each go to their own consumer. A preparation failure refuses the bundle as a whole.
3. Installation diffs each enforcement point's installed rules against the new set by rule key and content hash and sends only adds, removes and replaces (AG-09). Adds go before removes, so during the change both old and new blocking rules apply and no window opens with neither. Each point acknowledges a generation, and `state.db` records it. After a crash the core rediffs against the generation each point reports, so installation is idempotent.
4. A point that refuses its delta keeps its previous rules. The device reports the bundle as partially applied with the point and reason, and the core retries at the next fetch. The check-in carries the installed epoch and sequence and the generation per point.
5. Evaluation of a trigger event: class dispatch, point and core context predicates, classification when a policy or exception needs it, detector results with `minConfidence`, the CEL condition, ready exceptions, then the global ordered decision of section 3.2 and the actions. Context-only exceptions may run early when their inputs exist. The conflict plan decides whether a point can finish locally; a policy without detectors can still require core context. For server correlation, the core tags an event matching a referenced base rule with `{pack, version, pack_digest, rule_key}` in `metadata.rule_matches` and adds it to the upload set, so the server counts the exact version without re-evaluating rules.

## 5. Rule adapter framework

### 5.1 Structure

Adapters are Go packages in the server `policy` module, one per `RulePack` format (SH-04 keeps adapters with their server module). Each implements four steps behind one interface: parse the native files, translate each rule into its target, write `report.json` with one entry per rule, and list the fixtures it found. Event formats (Sigma, Falco) translate into the matcher program, which the agent's core evaluates with one engine (POL-04). Content formats (`pii`, `secrets`, `yara`) keep their patterns and run in `ricevanta-scan`. `osquery` becomes scheduled queries over the agent's inventory tables, run under the isolated query contract of `../specs/rule-adapters.md` section 8 and `mdm.md` section 3 (POL-06). Engine-exact checks (regular-expression compilation in the `regex` crate, YARA-X compilation, SQLite statement preparation, `cel` crate parsing, fixture evaluation) run in `ricevanta-rulec`. This is a Rust binary built from the agent workspace with the agent's own matcher, scanner detectors, YARA-X, SQLite and CEL crates, shipped in the server image and called by `policy` as a subprocess over stdin and stdout with CPU-time, memory and wall-time limits (POL-05). The subprocess runs under a dedicated uid with no network, no inherited environment or credentials, and the Linux restrictions of `dlp.md` section 2.1. A pattern that validates on the server therefore compiles on the agent of the same release; an agent of an earlier supported minor release that fails a compile reports the rule as unsupported on that device.

| Format | Input baseline | Target | Map |
|---|---|---|---|
| `sigma` | Sigma specification 2.1.0, filters, correlation | Matcher program on the agent; correlation on the server | Required `schemas/ocsf/sigma-logsources.yaml`, absent; blocks translation |
| `falco` | falcosecurity/rules format, `syscall` source | Matcher program on the Linux agent | Required `schemas/ocsf/falco-fields.yaml`, absent; blocks translation |
| `yara` | YARA rules, compiled by YARA-X | `ricevanta-scan` | External variables only |
| `pii` | Presidio recognizer YAML plus built-in validators | `ricevanta-scan` detectors | None |
| `secrets` | Gitleaks TOML | `ricevanta-scan` detectors | None |
| `osquery` | osquery query packs | Scheduled queries over the agent's inventory tables (`mdm.md` section 3); `evidence_info` events | Required `schemas/policy/osquery-tables.yaml`, absent; blocks query validation |
| ATT&CK | Enterprise STIX 2.1 bundle | Taxonomy for validation and coverage | None |

Exact accepted syntax, the unsupported list per format with its reason codes, the fixtures each upstream provides and the upstream tooling decisions are in `../specs/rule-adapters.md`. pySigma and sigma-cli are LGPL-2.1, not MIT; they are references only and are neither run nor linked.

### 5.2 Unsupported syntax and capabilities

The report holds one entry per source rule with a status per OS and closed-list reason codes (`../specs/rule-adapters.md` section 2); an adapter never drops a clause. Two further sources of "unsupported" complete the picture: the compiler marks a policy whose action a channel cannot perform (the `warn` downgrade on process authorization of `../specs/policy-envelope.md` section 4), and each device reports `Unsupported(reason)` for capabilities its OS or configuration lacks (`agent.md` section 2), such as BPF LSM inactive or a browser adapter whose self-test failed. The console joins all three per rule, per policy, per OS and per device (section 8). A policy with `enforcement.unsupported: alert` raises an alert for each device where any of its rules or actions is unsupported; `report` lists it only. Neither setting hides the gap.

## 6. Rule packs

### 6.1 Lifecycle

| Step | What happens | Who |
|---|---|---|
| Import | Archive upload, GitOps `RulePack` resource, a `content` extension component, or a first-party pack from the server image; the archive goes to the blob store with its SHA-256 | Holder of the import permission |
| Validate | Archive rules of the bundle reader, license record present, every rule through its adapter and `ricevanta-rulec`, `report.json` written | `policy` |
| Test | Every shipped fixture runs in `ricevanta-rulec` (section 7); a failing fixture blocks publish, and a rule without one shows as untested | `policy` |
| Attribute | Per rule: author, license and upstream id stored and carried into compiled output | `policy` |
| License review | Section 6.3 | Approver |
| Sign | At publish, `api` signs a pack manifest binding name, version, format, archive, compiled-output and report hashes, adapter version and license record (POL-07) | `api` |
| Publish | Binding a pack version to device scopes; a protected action (BE-02) whose request shows the report summary, test results, license classification and per-scope dry-run diff | Requester and a different approver |
| Update | A new version goes through every step again; the request shows the rule diff (added, removed, changed, newly unsupported) | As publish |
| Withdraw | Unbinding a version from scopes; policies that reference it are excluded from those scopes' bundles with a report, protected where that weakens an enforcing `dlp` or `edr` policy | As publish |
| Retire | A version stops being publishable; policies pinned to it fail validation on their next write and are excluded from bundles with a report, a weakening change for `dlp` and `edr` | As publish |

The compiler places a pack into a bundle only when its manifest signature verifies and the archive matches the signed hash, so an edited registry row or a swapped blob cannot change rules without a new signed publish. Agents do not verify pack manifests: the bundle signature covers the pack files (`../specs/policy-envelope.md` section 6).

### 6.2 Registry

The registry is a set of `policy` tables: pack versions with status (`imported`, `validated`, `published`, `retired`); rules per version with immutable `{pack, version, pack_digest, rule_key}`, upstream id, title, author, license, ATT&CK techniques, per-OS status and cost; reports; fixture results; and publications binding a pack version to scope selectors. A published `(pack, version)` cannot be overwritten; `pack_digest` identifies its exact signed manifest payload (`../specs/policy-envelope.md` section 6). Several versions of a pack coexist, since a policy may pin one (`<pack>/<rule>@<version>`) while unpinned references follow the published version. A publication marks the affected scopes dirty (section 3.4); the next bundle carries every version that the scope's policies reference, plus every `osquery` pack version published to the scope, which runs without a referencing policy because its output is evidence rather than a decision. Bundle paths contain the pack, version and digest, and correlation programs retain each resolved base-rule identity for late uploads. Changing an unpinned reference cannot reinterpret an older event under a newer rule.

### 6.3 Licenses and attribution

Each pack carries `spec.license` (`../specs/policy-envelope.md` section 5), and Sigma rules may carry their own `license`, which overrides the pack's for that rule. The registry classifies each SPDX identifier against the rules in `../licensing.md`:

- Accepted: Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, 0BSD, CC0-1.0, Unlicense, CC-BY-4.0 and DRL-1.1, the last two with attribution.
- Review required: any other identifier and any GPL-family license. Bundles redistribute the rules to every endpoint, so the publish approver records an attestation that the license permits that redistribution.
- Blocked: non-commercial licenses and `NOASSERTION`. Rules under them are `excluded` with `license_blocked`.

Attribution follows `../licensing.md`. The rule author (Sigma `author`, the Falco and YARA rule metadata) travels in the compiled rule into every finding's `analytic.author`, which the console's alert, investigation and finding views and every exported event show. The pack's attribution text appears on the pack page and in the release `NOTICE` for first-party packs. The ATT&CK notice shows on the coverage view.

### 6.4 First-party and third-party packs

First-party packs live in `rulepacks/<pack>/` with `pack.yaml` (the `RulePack` resource without its content reference), `LICENSE`, `NOTICE` with upstream attribution, `SOURCE` with the upstream URL and commit, `rules/`, `filters/` where the format has them, `tests/`, and a committed `report.json` baseline. The release builds them into first-party `content` components signed by the project's extension publisher key, ships them in the server image and installs them at first start (`extensions.md` sections 2.2 and 8.1). A server upgrade imports the new versions into the registry. Publishing them to scopes stays a protected action by default; an access policy may exempt project-signed pack updates, and that exemption is itself audited.

Third-party packs arrive as `content` components of a signed extension (EXT-01, EXT-02; `extensions.md` section 3.1): the extension owns the `RulePack` resource, and every step of section 6.1 still applies, including publish approval. The console shows the publisher name and key fingerprint, the pack license and each rule's author wherever the pack or a match from it is displayed.

### 6.5 Propagation

A published version marks every scope whose policies reference the pack, through an unpinned or wildcard reference, dirty. The incremental compiler rebuilds only the matcher programs, detector tables or query schedules that changed, and agents install only the changed rules (section 4). A rule removed or narrowed by the update shows in the publish diff, and for `dlp` and `edr` the update is classified under section 2.4.

## 7. Testing and coverage

### 7.1 Fixtures

Fixture formats per rule format are in `../specs/rule-adapters.md`. Every format uses the same layout: `tests/<rule key>/` with inputs and an `expect.yaml` that lists the rule keys expected to match and not to match, with a match count, offsets or result rows as the format needs. Inputs are OCSF events in NDJSON for `sigma` and `falco`, synthetic sample files for `yara`, `pii` and `secrets`, and table rows for `osquery`. Policy fixtures in `tests/policies/<policy>/` add the evaluation context (`device`, `user`, `session`, `match`, `destination`) and the expected decision, actions and `policy_activity` events. Test content is synthetic; real personal data, secrets and malware are never committed.

### 7.2 CI harness for first-party packs

Every change to `rulepacks/` or to an adapter runs these steps for every pack, through `ricevanta-rulec` and the Go adapters:

- translate, compile and run every fixture through the agent's engines, plus the converted upstream samples where the format has them;
- evaluate every CEL condition in the packs and policy fixtures with both runtimes and compare outputs byte for byte (`../specs/cel-profile.md` section 4);
- check budgets against the default ceilings (section 9) and measure translation time;
- validate the license record and every ATT&CK identifier;
- compare `report.json` with the committed baseline, failing when any rule's status worsens on any OS unless the same change updates the baseline.

### 7.3 Operator-run tests

From the console and with `ricevanta test`, an operator runs a pack's or policy's fixtures on the server through `ricevanta-rulec`, or uploads fixtures for an imported pack. A draft rule or policy can also run against stored events, bounded to 7 days, 1,000,000 events and 60 seconds by default. The result lists matches per device and rule and never stores a finding.

### 7.4 Coverage

- ATT&CK matrix: each Enterprise technique per scope and OS, with the counts of enforcing, monitoring and unsupported rules and policies referencing it. Rules disabled by resource governance or failing on a device count as not covering it there.
- DLP channel coverage: classification and detector by channel (file, clipboard, removable media, browser upload, paste, print and download, cloud sync, network) by OS. Each cell shows enforce, monitor, deny-then-approve or notify-only (`warn` under DLP-08) or unsupported, joined from placement labels, the capability matrix in `../platform-support.md` and device capability reports, with the browser adapter status (qualified or community) shown on browser cells.

## 8. Policy health

Health is computed per policy, per rule, per pack and per device from four inputs:

- compile results per scope: errors, warnings, budget overruns and `warn` downgrades;
- the adapter reports, per rule and OS;
- device reports: installed epoch and sequence and per-point generation against the assigned ones, partial installs, `Unsupported(reason)` per capability, and units throttled or disabled by resource governance (AG-08);
- `policy_activity` events (`../specs/ocsf-profile.md` section 2): evaluation errors, exceptions applied, fail-open and fail-closed decisions, refused commands, and the installation and governance activities proposed for that class (bundle installed, bundle refused, rule unsupported on device, unit throttled, unit disabled). Monitor-mode outcomes are recorded as `evaluated`; enforcing evaluations emit their findings, not one health event per evaluation.

A policy is healthy when it compiled and every device in scope runs it with no unsupported rule; degraded when some devices run it partially, lag behind the assigned sequence by more than two check-in intervals, or report unsupported rules or disabled units; failing when it does not compile. The console views (policy list with placement label and health, pack registry with reports, per-device policy tab, coverage) are in `console.md`.

## 9. Evaluation cost

Every compiled rule carries static cost units: one per literal comparison, prefix, suffix, set membership, CIDR or numeric test; the pattern length divided by 16, rounded up, per `contains` or keyword test without a prefilter literal; ten per regular expression; and a weight per YARA rule from its string and condition count. CEL conditions use the `cel-go` estimate. The compiler sums cost per scope and per pack and checks these defaults from `budgets.json`, which are operator policy values re-derived from the first measurements like the memory budget in `agent.md` section 6:

| Bound | Default ceiling |
|---|---|
| Matcher rules (Sigma and Falco) per bundle | 10,000 |
| Matcher cost units per trigger class | 200,000 |
| `pii` and `secrets` detectors per bundle | 2,000 |
| YARA rules per bundle | 20,000, with slow patterns refused |
| Scheduled osquery queries per bundle | 200, interval floor 300 s |
| CEL policies per bundle | 2,000 |
| `ricevanta-rulec` call | 120 s CPU time, 1 GiB memory, one call per `api` replica at a time |
| Correlation state per correlation rule on the server | 100,000 group keys |

Targets, measured by the footprint benchmark in CI (AG-09) with the first-party packs installed rather than assumed: matcher evaluation under 20 µs per event at the 99th percentile, the policy share of the core's 44 MB idle budget under 10 MB, translation of a full SigmaHQ import under 120 s and an incremental compile of one changed policy under 2 s per scope.

A bundle over a ceiling fails at dry run with the most expensive rules listed, and the installed bundle stays. On the agent, each rule pack and each CEL policy set is a unit of work under AG-08: the core samples evaluation time one event in N and accounts matcher memory per pack. A pack over budget is throttled first: its evaluations move to a bounded low-priority backlog, so detection lags instead of dropping. A pack whose backlog stays full is disabled until the next bundle or an operator re-enable. Each step emits a `policy_activity` event and shows the pack as degraded. Rule sets in enforcement points and authorization decisions are exempt (AG-06, AG-08). A content detector over its time takes the policy's fail mode through the scan deadline. On the server, correlation state over its key bound evicts the oldest key and reports the rule as degraded, and a `ricevanta-rulec` call over its limits fails the import or test step with the limit named.

## 10. Release placement

The policy envelope, CEL profile and OCSF profile exist from v0.1.x (SH-02). The matcher program, `ricevanta-rulec` and the Sigma adapter for single-event rules over the v0.4.x logsources ship with EDR in v0.4.x, with count correlation. The `pii`, `secrets` and `yara` formats ship with DLP in v0.5.x. The remaining modifiers and correlation types, filters, the Falco and osquery adapters, third-party pack import and the coverage views complete in v0.8.x (`../roadmap.md`). Under SH-01, v0.8.x is the release that completes the adapters.

## 11. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: one validation path serves the console, the CLI and GitOps, and the dual CEL parse catches runtime divergence at write time rather than on an endpoint. One matcher engine serves Sigma and Falco, so shared prefilters keep per-event cost proportional to candidate rules rather than to installed rules. `ricevanta-rulec` makes server validation and operator tests run the agent's own engines. Per-rule, per-OS reports make every gap visible. Signed pack manifests, publish approval and license classes make rule packs reviewed content rather than files. Incremental compile and incremental install keep a policy change cheap on the server and on the endpoint.

Trade-offs: the server image carries a Rust binary beside the Go server, built for both server architectures. Translating rather than running upstream engines means each upstream syntax change needs adapter work, bounded by pinned input versions. Presidio context matching runs without lemmatization. Placeholders, YARA externals and table maps are Ricevanta definitions that operators learn. Coalescing compile events delays a change by the debounce window.

Dependencies: `cel-go` and the `cel` crate (POL-01), the `regex` and `aho-corasick` crates, YARA-X, `rusqlite` with bundled SQLite, cel-spec, the OCSF schema, the Sigma specification, the osquery table specs and the ATT&CK STIX data. all with rows in `../licensing.md`.

Limits: Sigma and Falco rules match only fields the logsource maps cover; non-syscall Falco sources, evented osquery tables, named-entity recognizers and YARA modules without endpoint data are unsupported by design; `warn` is a notification on process channels and deny-then-approve on file-system and clipboard channels (DLP-08); agents of an older supported minor release may support fewer rules than the server validated; operator backtests run on stored events only, which the default telemetry profile limits to findings and bounded context (EV-01).

Alternatives considered:

- Translating Sigma into CEL conditions: rejected. Sigma's case-insensitive wildcard matching, list semantics and keyword search would need functions outside the CEL profile, and thousands of separate CEL programs cannot share a literal prefilter.
- Running pySigma or sigma-cli: rejected. They are Python, LGPL-2.1, and produce backend queries rather than an evaluator over OCSF.
- Validating patterns in Go only: rejected. Go RE2 and the Rust `regex` crate differ in syntax and in the Unicode meaning of shorthand classes, and Go cannot compile YARA-X without cgo.
- YARA-X Go bindings in the server: rejected. They need cgo, which the server avoids for the reason EXT-05 gives.
- Embedding osquery: rejected (POL-06).
- Shipping serialized YARA-X rules: rejected, since no cross-version compatibility is documented.
- Server-side re-evaluation of base rules for correlation: rejected. It needs every event of the trigger classes uploaded and a second evaluator; agent-side tagging uploads matches only.

## Sources

- Sigma: [rules specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md), [modifiers](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-modifiers.md), [correlation](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md), [filters](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-filters-specification.md), [pySigma license](https://github.com/SigmaHQ/pySigma/blob/main/LICENSE), [processing pipelines](https://sigmahq.io/docs/digging-deeper/pipelines.html)
- YARA-X: [differences with YARA](https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/), [YARA-X vs YARA](https://virustotal.github.io/yara-x/docs/intro/yara-x-vs-yara/), [API](https://docs.rs/yara-x/latest/yara_x/), [license](https://github.com/VirusTotal/yara-x/blob/main/LICENSE)
- Presidio: [repository](https://github.com/data-privacy-stack/presidio), [pattern_recognizer.py](https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/pattern_recognizer.py)
- Gitleaks: [repository and configuration](https://github.com/gitleaks/gitleaks)
- osquery: [configuration](https://osquery.readthedocs.io/en/stable/deployment/configuration/), [SQL additions](https://osquery.readthedocs.io/en/stable/introduction/sql/), [CLI flags and watchdog](https://osquery.readthedocs.io/en/stable/installation/cli-flags/), [license](https://github.com/osquery/osquery/blob/master/LICENSE)
- Falco: [rules](https://falco.org/docs/concepts/rules/), [conditions](https://falco.org/docs/concepts/rules/conditions/), [supported fields](https://falco.org/docs/reference/rules/supported-fields/), [falcosecurity/rules](https://github.com/falcosecurity/rules)
- MITRE ATT&CK: [Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/), [versions](https://attack.mitre.org/resources/versions/), [attack-stix-data](https://github.com/mitre-attack/attack-stix-data)
- CEL: [cel-go](https://github.com/google/cel-go), [cel-spec](https://github.com/cel-expr/cel-spec), [cel-rust conformance and ignored list](https://github.com/cel-rust/cel-rust/tree/master/conformance)
- Rust `regex` crate: [documentation](https://docs.rs/regex/latest/regex/)
- OCSF 1.9.0: [Live Evidence Info](https://schema.ocsf.io/1.9.0/classes/evidence_info)
