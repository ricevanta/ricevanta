# Baseline and compliance

The `Baseline` resource that carries MDM desired state, the item kinds and the channel each one uses per OS, how the agent and the native MDM servers converge and check items, and how a device's compliance state is computed, stored, signed and consumed. The policy that applies a baseline, its scope and its signatures are in `policy-envelope.md`; the mechanisms behind each item kind are in `../design/mdm.md`. Decisions: POL-02, MDM-01, MDM-03, MDM-06 and MDM-09.

## 1. Resource

A baseline is a list of items for one OS. An `mdm` policy names it in `trigger.state.baseline` and chooses the execution semantics with its action: `apply` converges and reports every item, `report` checks and reports without changing the device (`policy-envelope.md` section 4).

```yaml
apiVersion: ricevanta.io/v1alpha1
kind: Baseline
metadata:
  name: windows-endpoint
  labels: { source: ricevanta }
spec:
  os: windows                      # macos | windows | linux
  allowedGroups: [managed-windows] # required when any item can apply state
  minOsVersion: "10.0.22621"       # optional; devices below it report every item not_applicable
  items:
    - id: session-lock
      kind: windows.csp
      settings:
        locUri: ./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/InteractiveLogon_MachineInactivityLimit
        format: int
        value: 900
      required: true               # counts toward compliance; false is informational
      severity: medium             # informational | low | medium | high | critical
      grace: 24h                   # default 24h; 0 for critical
      references:
        - { framework: nist-sp-800-53, id: AC-11 }
        - { framework: cis-controls, version: "8", id: "4.3" }
    - id: no-telnet-client
      kind: check.query
      settings:
        query: SELECT name FROM programs WHERE name LIKE 'Telnet%'
        expect: size(rows) == 0
      required: true
      severity: low
```

```yaml
apiVersion: ricevanta.io/v1alpha1
kind: Policy
metadata: { name: mdm-windows-endpoint }
spec:
  domain: mdm
  scope: { include: [ { devices: { groups: [managed-windows] }, os: { windows: {} } } ] }
  trigger: { state: { baseline: windows-endpoint } }
  actions: [ { type: apply } ]
```

### 1.1 Field rules

- `id` is a DNS-1123 label unique within the baseline. `<baseline>/<id>` is the display and exception name, not the evidence key. Evidence and grace state use organization, device uid, baseline uid, canonical baseline revision SHA-256, item id and item settings SHA-256 (sections 3 and 4).
- `kind` is one of the kinds in section 2 that is valid for `spec.os`; `settings` requires validation against per-kind schemas under `schemas/policy/v1alpha1/baseline/<kind>.json`; those files are absent and block baseline validators (`../analysis.md` section 3).
- `allowedGroups` is required when any item kind can apply state. It is the maximum device-group scope approved for that exact baseline revision. It is absent on a baseline made only of `check.query` and `check.collector` items.
- `references` are identifiers only (framework, document, version, control or recommendation number). Benchmark text, rationale and audit procedures copied from a licensed benchmark are refused at publish when the source is marked non-redistributable in `../licensing.md` (section 5).
- A `windows.csp` item may set `authority: agent` when the agent can read its effective state (registry, WMI or API); the agent's signed result then decides the item and the OMA-DM `Get` result is informational. The default `authority: native` takes the native channel's result (section 6).
- An `Exception` with `domain: mdm` names items as `<baseline>/<id>` in its condition through the `item` variable; a matching exception records the item as `excepted`, which counts as passing and is audited (`policy-envelope.md` section 3).
- Size caps: 2,000 items per baseline, 64 KiB per item's `settings`, 1 MiB per compiled baseline. `check.query` text is at most 4,096 characters.
- Two enforcing policies that apply items setting the same target (the same CSP URI, registry value, declaration identifier, dconf key, file path or package) to different values on one device fail compilation unless their priorities differ; the higher priority wins and the console shows the losing item as `overridden`. Equal priorities with different values are a validation error, since no general "stricter" order exists across settings.

## 2. Item kinds

The channel follows MDM-01 and MDM-03: Apple settings travel over the Apple MDM server, Windows settings that a configuration service provider (CSP) exposes travel over OMA-DM, and everything else is the agent's.

| Kind | OS | Channel | Apply | Check | Removal |
|---|---|---|---|---|---|
| `apple.declaration` | macOS | Apple MDM, DDM | Declaration (type and payload) in the device's declaration set | Declaration status and subscribed status items | Declaration leaves the set |
| `apple.profile` | macOS | Apple MDM | Profile served by the `device` role and named by a `com.apple.configuration.legacy` declaration | Declaration status; `ProfileList` | Declaration leaves the set and macOS removes the profile |
| `windows.csp` | Windows | OMA-DM | SyncML `Add` or `Replace` of `locUri` with `format` and `value` | SyncML `Get` in each session | SyncML `Delete` |
| `windows.registry` | Windows | Agent | Registry value outside `SOFTWARE\Policies` (refused there, MDM-03) | `RegNotifyChangeKeyValue` on the key, plus the periodic check | Restore the value recorded before first apply |
| `windows.service` | Windows | Agent | Service start type and state through the Service Control Manager | `NotifyServiceStatusChange` | Restore recorded start type |
| `linux.dconf` | Linux | Agent | Key file in `/etc/dconf/db/ricevanta.d/`, lock entries in its `locks/` directory, `dconf update`; the agent owns `/etc/dconf/profile/user` entry `system-db:ricevanta` | Read of the compiled database; file watch | Remove the key and lock, `dconf update` |
| `linux.polkit` | Linux | Agent | Rules file `/etc/polkit-1/rules.d/60-ricevanta-<id>.rules` | Content hash; file watch | Remove the file |
| `linux.sysctl` | Linux | Agent | `/etc/sysctl.d/90-ricevanta.conf` and a write to `/proc/sys` | Read of `/proc/sys` | Remove the line, restore recorded runtime value |
| `linux.systemd` | Linux | Agent | Unit enable, disable, mask or a drop-in under `/etc/systemd/system/<unit>.d/` through the systemd D-Bus API | Unit state | Revert to recorded state |
| `linux.pam` | Linux | Agent | Password quality (`pam_pwquality`) and lockout (`pam_faillock`) only, through the distribution tool: `authselect` features on RHEL and Fedora, `pam-auth-update` profiles on Debian and Ubuntu, `pam-config` on openSUSE; `/etc/pam.d` is never edited directly | Tool query and module options | Tool revert |
| `linux.file` | Linux | Agent | A whole drop-in file the agent owns, with mode and owner | Content hash; file watch | Remove the file |
| `linux.repository` | Linux | Agent | Package repository with its signing key (`signed-by` for apt, `gpgkey` with `gpgcheck=1` for dnf and zypper, a flatpak remote with GPG verification) | Repository definition hash | Remove definition and key |
| `software` | All | Agent; Apple MDM for the agent's own package | `ensure: present`, `absent` or `latest` of a `SoftwarePackage` (`../design/mdm.md` section 4) | Detection rule | Uninstall when `removeOnUnassign: true` |
| `os_update` | All | Apple MDM DDM, OMA-DM plus agent, agent | `../design/mdm.md` section 6 | OS-reported version and update state | Settings removed; no downgrade |
| `encryption` | All | Apple MDM, OMA-DM plus agent, agent | FileVault through `com.apple.MCX.FileVault2` with `com.apple.security.FDERecoveryKeyEscrow`; BitLocker through the BitLocker CSP with agent escrow; on Linux, enrollment of a TPM2 key slot and a recovery key on an existing LUKS2 root (`../design/mdm.md` section 8) | Volume protection state and an escrowed recovery secret | Settings removed; volumes stay encrypted |
| `check.query` | All | Agent | None | Read-only query over the inventory tables, CEL `expect` over `rows` | None |
| `check.collector` | All | Agent, `collector` extension module | None | Module rows, CEL `expect` over `rows` (`../design/extensions.md` section 3.3) | None |

An item whose kind the device cannot carry for an OS-imposed reason (an edition without the CSP, an OS release below the declaration's minimum, a Linux distribution without the PAM tool) reports `not_applicable` with the reason, which the console lists; it is never silently skipped. An item that needs a channel the device lacks (no Apple MDM enrollment, no OMA-DM enrollment) reports `fail` with reason `channel_missing`, because the missing channel is itself a compliance defect.

## 3. Execution

- The compiler places each item, its baseline uid and canonical revision hash in the bundle (`baselines/<name>.json`) for agent kinds and in the `mdm` module's per-device desired-state tables for Apple and OMA-DM kinds. The item settings hash covers the defaulted, validated JSON `{ kind, settings, authority }` serialized by RFC 8785. Every signed bundle also carries the full approved required-set bindings and their hash, including native-channel items whose payloads deliver separately. Agent kinds are covered by the bundle signature. Apple evidence needs origin, revision and freshness verification (section 4.3); Cryptographic Message Syntax (CMS) alone proves only origin. OMA-DM evidence rests on the `device` role's TLS key unless the agent cross-checks it (`../architecture.md` section 4).
- The agent applies agent kinds when a bundle installs and when it detects drift, records the prior value of every target before its first change in `state.db`, and restores that value when the item leaves the bundle. Drift detection is event-driven where the OS notifies (registry change notification, Service Control Manager notification, fanotify or inotify on owned files) and otherwise periodic, default every 60 minutes, a policy value.
- The `mdm` module converges native-channel kinds: it recomputes the declaration set and its token when an Apple item changes and sends the `DeclarativeManagement` command; it queues SyncML commands for the next OMA-DM session and asks the agent to start one (`../design/mdm.md` section 10).
- Every item result carries its evidence key, authority binding, outcome (`pass`, `fail`, `error`, `not_applicable`, `excepted`, `overridden` or `pending`), observed value or hash, reason and evaluation time. `pending` means no accepted evidence for the required revision. The authority binding is the installed assignment envelope hash for agent results, enrollment plus current declaration identifier and server token for DDM, or enrollment plus current query/session and request identity for native queries. A changed result is a `device_config_state_change` event; a compliance transition is a `compliance_finding` (`ocsf-profile.md` section 1).
- Agent item results travel with the installed assignment in the device-signed check-in and monotonic journal report (`policy-envelope.md` sections 6 and 7). `jobs` verifies the report pair and assignment envelope, resolves the signed bundle to the exact baseline revision and settings hash, and rejects a result outside that assignment. A valid result for an older assignment stays historical and cannot satisfy a newer desired revision. Exposed roles cannot replace the signed binding or replay a consumed report pair.

## 4. Compliance

### 4.1 Definition

Compliance assesses the current approved desired revision, not whichever revision the endpoint last installed. The required set contains every required item in every baseline an enforcing `mdm` policy applies or reports on the device, with the approved policy, baseline and exception revisions pinned. `jobs` hashes the sorted required-set bindings and evaluates only evidence for those bindings. Activating a new required revision makes its results `pending` and the device `unknown` until matching verified evidence arrives; approval does not prove installation or compliance. A pending replacement approval leaves the current approved set in force. A device is compliant when every required item passes, is excepted or is not applicable, and every server condition holds. Optional items never change the state.

| Server condition | Failing value |
|---|---|
| Lifecycle | Device not `active` (`../design/mdm.md` section 1.2) |
| Identity | Device identity certificate revoked, or expired beyond the renewal grace period (`../design/pki.md` section 2) |
| Freshness | No verified check-in within `staleAfter` (default 7 days, an organization setting) |
| Channels | A required native channel lost: Apple MDM enrollment on macOS, OMA-DM enrollment on Windows |
| Agent | Preflight reports a required capability failing on the device (`../platform-support.md`) |

### 4.2 Device state

| State | Meaning | Consumers treat as |
|---|---|---|
| `compliant` | All of section 4.1 holds | Compliant |
| `grace` | Only verified required-item failures within their fixed grace episodes remain | Compliant, shown distinctly with the earliest grace expiry |
| `noncompliant` | A required item failed beyond grace, or a server condition other than freshness fails | Noncompliant |
| `unknown` | No result yet for a required item, or freshness fails | Noncompliant |

Evaluate state in this order: a failing server condition other than freshness or an expired required-item failure is `noncompliant`; otherwise any unknown required evidence or failed freshness is `unknown`; otherwise an in-grace failure is `grace`; otherwise `compliant`.

Grace is a bounded episode per evidence key. `jobs` uses database time; the device uses monotonic time for local evaluation. `fail` and `error` start an episode on the first accepted failure at `first_failure`, with `deadline = first_failure + grace`; later failures never move that deadline. Missing, stale, unbound or `pending` evidence is `unknown` and receives no grace. Server-condition failures receive no grace.

| Input for the same required revision | Episode transition |
|---|---|
| First verified failure | Open one episode; `grace: 0` expires immediately |
| Verified pass, excepted or not applicable before deadline | Item passes, but retain the episode and deadline |
| Failure again before deadline | Resume the same episode and remaining grace |
| Deadline while item is failing | Item becomes noncompliant; retain the expired episode |
| Deadline while the latest accepted item evidence still passes | Close the episode; the next verified failure may start a new episode |
| Verified pass after an expired failing episode | Close the episode and item passes |
| Evidence becomes unknown, process restarts or server restores | Keep the episode; never reset or extend its deadline |

The server journals episode starts, deadlines and closure before publishing the resulting compliance statement, so recovery cannot restore a later deadline or reset an expired episode. The agent stores its local episode and its server deadline binding in `state.db`; a restart with no trusted elapsed-time continuity cannot award additional local grace and treats a failing item as outside grace until a fresh server statement resolves the episode. New revision evidence starts its own state and cannot inherit an old pass or grace episode; resetting a deployed requirement through revision or scope changes is protected by section 5.

### 4.3 Computation and storage

The `mdm` module computes state in `jobs` when verified evidence arrives, the approved required set changes or grace and freshness timers expire. It stores revision-bound results, accepted authority bindings, consumed native query identities, grace episodes, required-set hash and device state with reasons, entry time and per-device `(recovery_epoch, statement sequence)` in its schema. The recovery contract of `../design/backend.md` section 6.1 must preserve consumption floors and episode deadlines; missing evidence is `unknown`, never a restored pass or fresh grace. Each transition is a `compliance_finding`. Exposed roles never compute authority.

Verification checks origin, current required revision and ordering or freshness separately. Agent evidence follows section 3. Apple queries require `jobs` to verify the raw body and CMS signature, a unique outstanding `CommandUUID` bound to the current enrollment, required-set hash, monotonically allocated query generation and requested fields, and database-time validity within `staleAfter` from query issuance. `jobs` keeps at most one current query binding per required item; a newer query supersedes the older binding before dispatch. `jobs` atomically consumes the query with its accepted result; exact duplicate bodies are idempotent and cannot refresh evidence time. Superseded, expired, foreign, already consumed with different bytes or older-generation results cannot replace current evidence. OMA-DM queries bind to the current session and request in the same way, but their unsigned results still trust `device`; an `authority: agent` item uses only the signed agent evidence.

Apple declaration evidence must name the current declaration identifier and server token. Neither the token, CMS, a `FullReport` flag nor the receiving role's timestamp proves that an unsolicited status report is newer than a stored failure. A consumed body hash blocks an exact replay but does not prove that a withheld, previously unseen pass is fresh. Until an independently reviewed mechanism binds these reports to fresh device evidence and orders them despite a compromised `device` role, unproved native status cannot raise compliance or renew evidence freshness; required items without other qualified current evidence stay `unknown`. The mechanism and its schemas are unresolved v1.0.0 release blockers (`../design/mdm.md` section 9.1); native MDM support remains required.

### 4.4 Compliance statement

`jobs` signs each new device state with the organization's policy signing key as a DSSE envelope of payload type `application/vnd.ricevanta.compliance-statement+json`: `{ organization, device_uid, recovery_epoch, required_set_sha256, state, reasons_sha256, sequence, issued, stale_after }`. The required-set hash binds the assessed revisions; `reasons_sha256` binds item outcomes and grace deadlines; a newly signed statement does not refresh the evidence behind it. `jobs` re-signs the current state with a new `sequence` and `issued` time for every check-in response, so the response carries a fresh statement; the agent verifies it under `../design/pki.md` section 4 and refuses a `(recovery_epoch, sequence)` not above the installed pair or an epoch without the verified recovery transition (`policy-envelope.md` section 6). While the agent's check-ins succeed, it treats a statement whose `issued` is older than `stale_after` (the organization's `staleAfter`) as `unknown`, so an `agent` replica that withholds newer statements cannot keep `device.compliant` true. The agent's CEL variable `device.compliant` is true only when the latest statement says `compliant` or `grace`, its required-set hash matches the installed bundle's requirement bindings, and its local required agent-kind items pass or remain within their fixed episodes. A desired revision not yet installed cannot borrow local passes from an older assignment, and an exposed role cannot raise the value. With no successful check-in, the last statement stays in force with local evaluation (AG-05); the freshness rule does not apply offline.

### 4.5 Consumers

- Console: device page with per-item results, evidence and references; fleet view by baseline, item and state; reports through the `mdm.compliance` data source (`report-template.md`).
- RADIUS: the `radius` module's materializer in `jobs` reads the stored state and the latest signed statement through the `mdm` module's Go interface (BE-04) into the authorization snapshot that `radius` replicas hold in memory (`../design/radius.md` section 2); `noncompliant` and `unknown` take the authorization outcome the RADIUS policy names (`../design/radius.md`).
- Policies: CEL conditions read `device.compliant` (`cel-profile.md` section 5), on the server from the stored state and on the agent as in section 4.4.
- Events: `compliance_finding` for every transition and SIEM export through the event pipeline.

## 5. Authoring

- First-party baselines for each OS ship as the project's `content` extension `io.ricevanta.baselines` (`../design/extensions.md` section 3.1), signed by the project publisher key. Their items are written from Apple, Microsoft and distribution documentation, with references to public control identifiers: NIST SP 800-53 controls, CIS Controls safeguards, DISA STIG rule identifiers and CIS Benchmark recommendation numbers. CIS Benchmark text is not redistributable (`../licensing.md`), so items carry the recommendation number and never its text.
- Sources whose license permits reuse are imported as item content with attribution: the macOS Security Compliance Project rules, published under CC BY 4.0 (verify the license file), and DISA STIG content (verify its distribution statement). Each source needs a row in `../licensing.md` before an item uses it.
- Operators author their own `Baseline` resources through the console, the API or GitOps (`baselines/`), including items that cite benchmarks they license. `ricevanta baseline import` translates an XCCDF 1.2 benchmark the operator holds into items of the kinds in section 2 where a rule's check maps to one (registry, file content, sysctl, package, service and CSP tests) and writes a report naming every rule it could not translate and why; unsupported rules are never silently dropped (blueprint section 4).
- A baseline made only of `check.query` and `check.collector` items is read-only. Publication is unprotected only when the revision cannot weaken an existing required compliance set. A change to a deployed required check's query, collector, `expect`, authority, required flag, grace, applicability or pinned reference requires approval; semantic equivalence is not assumed. Deleting or replacing such a check or baseline, excepting it, disabling or narrowing its enforcing `report` policy, or removing a device from its required scope is also protected, including changes through labels, group rules and inventory. The protection applies even if no network policy changes. Every baseline with an apply-capable item is a protected action. This includes declarative profiles and configuration service provider values as well as `windows.registry`, `windows.service`, every `linux.*` apply kind, `software`, `os_update` and `encryption`. The closed rule prevents an apparently declarative item from bypassing approval when its bytes can select an executable, grant privilege, change authentication or replace root-owned configuration. `linux.file` refuses an executable mode and special file, but still requires approval because configuration content can cause code execution. `linux.systemd` permits only the structured unit state and drop-in fields in its schema; arbitrary unit-file replacement is refused. `linux.polkit` and `linux.pam` are always protected.
- Approval binds the organization, resource uid, canonical revision SHA-256, operation and sorted `allowedGroups` group uids. A compliance-weakening request additionally binds the exact before and after required-set revisions, affected policy and exception revisions, prior required-set hash and frozen device uids; a changed diff or added device requires a new approval. The revision hashes the validated JSON `{ apiVersion, kind, metadata: { name, labels }, spec }` with defaults materialized, resource references pinned to immutable revisions and group uids, and `allowedGroups` sorted without duplicates, serialized by [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html). Benchmark references remain literal identifiers. Array order elsewhere is preserved; server status and revision counters are excluded. Names alone never identify an approved group or software revision.
- Publishing a revision approves its content, not its deployment. An apply request also binds the applying policy's canonical revision hash, prior deployment revision and frozen device uids. Editing or deleting an item in an apply-capable baseline, removing the baseline or an applying policy, changing `allowedGroups` or changing the applying scope creates a new protected request. A manual membership change, dynamic-group rule or inventory change that newly delivers the baseline leaves the added device pending until a protected target-expansion request is approved. Existing approved targets continue converging on their approved revision while a replacement is pending. Removal is protected because restoring prior state can change privilege or authentication.
- The compiler, native-channel desired-state writer and compliance computation recheck the applicable content, deployment and compliance-weakening approvals on every required-set change. They refuse unapproved revisions and scope removals or exceptions that would weaken required compliance, targets outside the frozen approved set and, for apply-capable baselines, targets outside `allowedGroups`. An unapproved diff cannot make RADIUS gain an accept by changing `device.compliant`. A `software` item also passes the independent `SoftwarePackage.allowedGroups` check (`../design/mdm.md` section 4.2). Approval cannot authorize later bytes or a newly matching device. Console, API and GitOps use the same protected diff and report an unapplied change as pending (BE-02).
- Baselines are validated by the same validator as every other resource (POL-02). Baselines do not accept a script item or an interpreter command. Some approved configuration kinds contain executable syntax, such as polkit rules, or select privileged executables through systemd. Those kinds retain their per-kind restrictions and approval requirement; a free-form operator script uses `edr.run_script` (`edr-response-actions.md` section 2).

## 6. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: one resource carries settings for three OSes while each item names the channel that applies it; per-item grace, required flags and server conditions make "compliant" one computed value with reasons that the console, RADIUS and CEL all read; signed statements keep an exposed role from raising a device's compliance on the agent; Apple native evidence counts only after origin, revision and freshness checks; references give regulated customers a control mapping without bundling licensed text.

Trade-offs: a per-kind schema for each mechanism is more to maintain than a free-form script; apply-capable baselines, later scope expansion and weakened required compliance need independent approval; equal-priority conflicts are rejected rather than merged; Apple and OMA-DM items converge on the native channel's schedule, which the server shortens by push and agent-triggered sessions.

Dependencies: the policy envelope and CEL profile, the Apple MDM and OMA-DM servers, the agent inventory tables, extension `collector` modules for `check.collector`.

Limits: unsolicited Apple native status still lacks a qualified freshness and ordering mechanism and cannot grant compliance until that blocker is resolved. `check.query` sees only the inventory tables the agent collects (`../design/mdm.md` section 3); XCCDF import translates only the check types listed above; Linux root encryption cannot be added in place, so `encryption` on an unencrypted Linux root fails with a reinstall remediation. OMA-DM has no message signature, so Windows native item results rest on the `device` role unless the item is marked `authority: agent`. Agent-kind item results are the device's own signed report: a device under a hostile local administrator can misreport them, and only server conditions and native-channel results are independent of it.

Alternatives considered: script-based checks as the primary format (rejected: no declared target for conflict detection, and scripts run as root are protected actions); bundling CIS Benchmark content (rejected: not redistributable); OVAL as the native format (rejected: large, with test types the agent would partially implement; XCCDF import maps the supported subset); compliance computed on the agent alone (rejected: freshness, revocation and lifecycle are server facts, and RADIUS needs the server's answer).

Executable configuration sources: systemd [service commands](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml) and [execution identity](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml), and polkit [authorization rules](https://polkit.pages.freedesktop.org/polkit/polkit.8.html). Their ability to execute code or grant privilege is why every apply-capable kind requires protected approval.
