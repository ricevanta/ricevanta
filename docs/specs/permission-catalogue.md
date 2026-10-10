# Permission catalogue

The catalogue defines console and administrative API permission names, scope kinds and approval requirements. The machine-readable home is [`schemas/permissions/v1/catalogue.json`](../../schemas/permissions/v1/catalogue.json), checked against its [JSON Schema](../../schemas/permissions/v1/catalogue.schema.json). The proposed standard-library-only Go package validates and serves these metadata in process. It does not authorize requests.

This slice closes the permission-list gap in `analysis.md` section 3. It leaves role definitions, effective-permission calculation, access-policy evaluation, database storage, HTTP routes, console controls, command schemas and the authority-journal implementation to independently reviewed slices. Listing a blocked action does not qualify its implementation or remove a release gate.

## 1. Authority and coverage

BE-02 governs role-based access control (RBAC) and approval; BE-09 governs fresh authentication; BE-12 governs committed authority and recovery. `design/backend.md` sections 1 and 1.1 own module boundaries and identity authority. `design/console.md` sections 3 and 5 own the views. The catalogue gives every entry a `source`, `uses` and `note`; those fields identify its origin, operation selector and additional checks.

The permission namespace is a product area, not necessarily a Go module. No new backend module follows from a permission prefix.

| Requested area | Permission namespace | Owner module | Scope choice |
|---|---|---|---|
| MDM, inventory, devices and updates | `mdm` | `mdm` or `devices`, per entry | Device groups for devices and actions; organization for shared definitions |
| EDR | `edr` | `detection` | Device groups; organization for intelligence feeds |
| DLP | `dlp` | `dlp` | Device groups for findings and evidence; organization for classification and fingerprint definitions |
| Lineage | `lineage` | `lineage` | Device groups |
| PKI | `pki` | `pki` | Device groups for device certificates; organization for infrastructure certificates and issuance configuration |
| RADIUS | `radius` | `radius` | Device groups for attributable activity; organization for gateways and profiles |
| Policy and rule packs | `policy` | `policy` | Device groups for policies and publication targets; organization for shared pack content and GitOps configuration |
| Events and reports | `events` | `events` | Device groups for results and telemetry; organization for shared templates, exports, holds and retention |
| Audit | `audit` | `audit` | Organization |
| Users and identity | `identity` | `identity` | Organization |
| RBAC and approvals | `authz` | `authz` | Organization; target checks remain separate |
| Extensions | `extensions` | `extensions` | Organization, except responder execution on device groups |
| Settings and backup status | `platform` | `platform` | Organization |

Reports retain `events.reports.run`; users use `identity`, RBAC uses `authz`, and settings use `platform`. Separate `reports`, `users`, `rbac` and `settings` modules would contradict BE-04. The seven names already explicit in the designs remain exact: `dlp.evidence.read`, `identity.tokens.manage`, `identity.authority.approve`, `authz.approvals.read`, `audit.events.read`, `policy.ownership.override`, `events.reports.run`.

`uses` strings without a prefix are operation IDs required by the console design. `operation#selector` identifies a branch or extra field of that operation, not a new operation ID. `api:kebab-case` is a semantic API operation awaiting the OpenAPI slice. `view:kebab-case` identifies a console view whose operation ID remains unsettled. Neither notation invents HTTP paths. A row can cover list and detail reads of one resource; distinct mutations have distinct permissions, except the explicitly named `identity.tokens.manage` aggregate.

Enumeration resides only in the JSON, including rule-pack retirement, quarantine validation and promotion, export cursor replay and backfill, endorsement-key allow-list administration, and implied software publication, baseline operations, enrollment decisions, each escrow secret read, recovery and uninstall, each response command, fingerprint registration, reclassification, infrastructure PKI, network profiles, rule tests and backtests, report schedules, identity mappings, direct approver assignments, callback completion and configuration. The schema's closed verb set is the union of those rows. The reviewed [coverage manifest](../../schemas/permissions/v1/fixtures/coverage.json) binds prose-defined actions to exact selectors and records the complete design/spec source inventory; its [schema](../../schemas/permissions/v1/coverage.schema.json) is a test contract, not runtime authorization data. There is no wildcard permission, default grant, resource-name glob, case folding, plural alias or prefix inheritance.

`getSession`, login, logout, own approval-request status, awaiting-my-decision metadata and self-service re-authentication use authenticated subject ownership, not a synthetic permission. First-start setup, offline custodian recovery, agent enrollment and renewal, ACME, SCEP, RADIUS protocol authentication and export workers use their own protocol principals. They cannot acquire console access through a catalogue name. The connector completion row records the existing dedicated callback authority, not ordinary administrator authority.

## 2. Names, fields and lifecycle

A name is exactly three ASCII tokens separated by two periods. Each token has 1 through 32 bytes, starts with `a` through `z`, and continues with lowercase letters, digits or `_`. Total length is 5 through 98 bytes. Names reject whitespace, NUL, Unicode, hyphens, wildcards and invalid UTF-8; callers never trim or normalize. `ValidateName` checks this grammar only. A syntactically valid unknown namespace or verb passes that function but cannot enter a catalogue or succeed in lookup.

The root has exactly `format_version` (integer 1), `revision` (1 through 4,294,967,295), and `permissions` (1 through 2,048 entries). Names are unique and strictly ascending by ASCII bytes. The complete shipped catalogue also needs the coverage check in the plan; structurally valid fragments need not enumerate every area.

| Entry field | Contract |
|---|---|
| `name` | Grammar above, with the schema's closed namespace and verb sets |
| `owner` | BE-04 module; namespace-to-owner mapping enforced by schema |
| `scope` | `organization` or `device_group` |
| `protection` | `none`, `always` or `conditional`, derived from `rule` |
| `approval` | `none`, `access_policy` or `identity_authority`, derived from `rule` |
| `rule` | Closed identifier from section 4; metadata, never executable policy |
| `grant` | `role`, `direct` or `connector`; exact special-name constraints in schema |
| `status` | `active` or `retired` |
| `introduced` | Catalogue revision that introduces the name, between 1 and root revision |
| `retired_in` | Present only when retired; greater than introduced and no greater than root revision |
| `uses` | 1 through 32 unique printable ASCII strings, each 1 through 160 bytes |
| `source` | Printable ASCII repository path and section, 1 through 160 bytes |
| `note` | Printable ASCII explanation, 1 through 512 bytes |

All entry fields except `retired_in` are required. Unknown fields, nulls and wrong types are errors. Metadata permits only bytes 0x20 through 0x7e. Object member order and insignificant JSON whitespace have no semantic meaning. Escaped strings compare after decoding. The strict wire profile additionally rejects repeated object keys, invalid UTF-8, unpaired Unicode surrogates, trailing values and integer tokens written with fractions, signs or exponents. JSON Schema sees decoded instances and cannot enforce those byte rules.

`format_version` changes only for an incompatible document shape or validation contract, with a new directory. `revision` increments for every catalogue-content change, including notes and retirement. Formatting alone leaves revision unchanged, but both canonical and embedded bytes change together. Overflow fails the release; it never wraps. The product version is not the catalogue version.

An active name never changes meaning, scope, owning module, grant kind or approval semantics in place. A semantic change gets a new name; the old row becomes a permanent tombstone with `status: retired` and `retired_in`. Retain the old metadata for audit interpretation, never reuse or delete the name, and never silently map it to a successor. Consumers reject retired grants, retain historical references and require explicit reauthorization for a replacement. During rolling upgrades, a replica rejects names it does not know; rollout must establish catalogue compatibility before new grants are enabled. An older binary is not allowed to resurrect a retired permission through rollback; the authority and release slices must enforce their version and recovery fences.

## 3. Scope and composed requirements

An organization permission accepts only effective scope `all`. A device-group permission accepts `all` or a nonempty set of immutable device-group uids in the future effective-grant contract. Unknown or empty groups grant nothing. This package exposes scope kind only; it does not accept or parse grant scopes.

For a device-group permission, the consumer resolves current entity access on every read, count, aggregate, list, export and mutation. A resource affecting groups requires coverage of every resolved device, including before and after a membership or policy change. Neither group edit rights nor a shared resource's organization scope grants access to devices. Every manual membership write, including `updateDevice`, requires `mdm.groups.update` as well as the device write permission and applies `group_change`. Label or ownership edits that indirectly change group membership apply the same checks. Device-group definitions are organization permissions because editing membership changes the RBAC boundary itself; a later evaluator must enforce delegated-assignment and no-self-escalation rules before those writes exist.

A request touching multiple entries requires all applicable permissions, never any one of them. A metadata read does not grant execution or disclosure rights. The entry note names extra requirements; the following cross-cutting rules also apply:

- DLP snippets need both finding and evidence reads. Fingerprint originals, malformed quarantined-event bodies, keys and credentials never become readable through generic metadata or report permissions.
- A device detail tab needs the source permission for its data. Reading a device does not grant its alerts, certificates, DLP findings, policy state or footprint.
- Report execution needs `events.reports.run` and every source read. Stored results additionally need `events.reports.read`, current source permissions and the immutable entity footprint checks of `report-template.md` section 4. Templates and schedules grant no source access. Audit datasets require organization-wide `audit.events.read`.
- Certificate reads and revocations select the device or infrastructure row by authoritative certificate profile. Device scope cannot reveal service, signing or CA certificates. Unattributable RADIUS and pipeline activity requires scope `all`, never an arbitrary group.
- `createExport` needs `events.exports.create` for ordinary data and every source read; audit export needs `audit.events.export` and `audit.events.read`. Exported report results keep the report checks. Destination administration cannot read payloads through dead-letter metadata.
- `edr.kill_and_ban` also needs policy update rights for the entire affected scope; `extension.respond` needs its wrapper permission and every permitted child permission and approval, even if a returned plan omits that child.
- Rule-pack retirement is an organization mutation requiring `policy.rulepacks.retire`, protected on every invocation. It also requires `policy.policies.update` across every affected device before and after the change. Resolve all publications and pinned and unpinned policy dependencies globally, including references outside the caller's visible lists; never retire just the visible subset. Freeze the version digest, dependency closure, scopes and compile diff, apply `policy_change` to every affected policy and recheck before commit. Unknown targets fail closed. Withdrawal retains its separate permission and selected-scope semantics.
- Quarantine validation and promotion require separate permissions. Both add `events.quarantine.read` and every source read over the complete authenticated-device footprint; promotion also requires `events.quarantine.validate`. Validation returns bounded diagnostics only. Promotion freezes raw-line hashes, device/batch bindings and schema/mapping versions, then reruns validation under the commit fence. A mapping fix cannot rewrite authenticated identity or revive expired authority. Fresh inventory and compliance require current provenance; historical security telemetry may retain old provenance without granting current authority. Apply deduplication, legal-hold capture and export gates; neither permission exposes raw quarantined bodies.
- Cursor replay and PostgreSQL backfill require their distinct `events.destinations.replay` and `.backfill` permissions, each protected on every invocation, plus destination metadata, `events.exports.create` and all source reads over the complete selected payload footprint. Audit selection adds `audit.events.read` and `audit.events.export`; DLP snippets add `dlp.evidence.read`. Resolve every device before and after selection, require scope `all` for infrastructure or unattributable data, and reject partial coverage. Freeze destination/configuration revision, range, filter, projection and footprint; recheck authority at dispatch. S3 intentional replay uses a new namespace and retry uses its stored plan. Ordinary export workers retain their protocol authority.
- Endorsement-key allow-list import, update and delete are separate organization permissions protected on every invocation. Freeze the exact before/after list and affected enrollment groups and require `mdm.enrollments.read` over all affected requests and devices. Metadata reads expose public-key fingerprints only. Allow-list changes never grant enrollment approval, issuance or lost-key recovery; those retain their exact permissions and proofs.
- The coverage manifest records composed requirements for ATT&CK replacement, fixture execution and upload, XCCDF baseline import, governed-pack re-enable, fingerprint-original handling, template corpus and managed tenants, indicator pins, rollout controls, callback-token revocation, external issuance reconciliation, collection and script cancellation, gateway issuance, extension ownership assignment, package revocation, archive-failure hold release and Apple push-topic replacement. Branch selectors add their permission to an existing operation's requirements. An empty affected scope is not a bypass: shared changes must resolve the full dependency closure, and unknown targets fail closed.
- GitOps ownership override adds no write authority. Dry runs require the same source visibility and scope as the proposed operation; they cannot leak out-of-scope outcomes.
- API-token creation intersects the creator's current grant and device scope. `grant: direct` is exclusive to `identity.authority.approve`; no role, mapping, directory group or ordinary token can carry it. `grant: connector` is exclusive to `extensions.ca_callback.complete` and never appears in an operator's effective grants.

The report source permission bindings use the source IDs in `report-template.md` section 3. The separate report catalogue must carry these bindings when its schema exists.

| Report source | Required read permission |
|---|---|
| `devices` | `mdm.devices.read` |
| `devices.software` | `mdm.inventory.read` |
| `mdm.compliance` | `mdm.compliance.read` |
| `edr.alerts` | `edr.alerts.read` |
| `edr.response_actions` | `edr.response.read` |
| `dlp.findings` | `dlp.findings.read`, with no snippets |
| `lineage.edges` | `lineage.edges.read` |
| `pki.certificates` | `pki.certificates.read`; infrastructure rows additionally require `pki.infrastructure.read` |
| `radius.authentications` | `radius.authentications.read` |
| `agents.versions` | `mdm.versions.read` |
| `agents.health` | `events.health.read` |
| `audit.events` | `audit.events.read` |

These are integration requirements, not capabilities of lookup. The later OpenAPI contract must bind each branch to all permissions and fix the request, response and scope types. A successful lookup proves only that a name is registered and active.

## 4. Approval classification

`protection: always` means protected by default for every invocation, not an unconditional bypass of BE-02's single-administrator setting. `approval: access_policy` selects the installation's applicable BE-02 approver group. The catalogue cannot name an installation group or decide whether an exemption is permitted. Identity authority is a fixed boundary outside configurable access policies.

| `rule` | Protection / approval | Consumer classification |
|---|---|---|
| `none` | none / none | No catalogue default approval; configured access policies may add one, except urgent revocation and decision operations below |
| `always` | always / access_policy | Every invocation is protected by default |
| `identity_authority` | always / identity_authority | Always different enabled directly assigned approver with unaffected fresh authentication; no single-administrator exemption |
| `fleet_gt_10` | conditional / access_policy | More than 10 distinct devices in the complete frozen request; 10 does not cross the threshold |
| `policy_change` | conditional / access_policy | Any protection predicate in policy-envelope section 2.3 or baseline section 5, including apply-capable delivery, weakened required compliance, indirect resource and membership effects, dangerous automatic actions and conservative unclassifiable diffs |
| `published_content` | conditional / access_policy | Publishing, changing canonical content or allowed groups of a published software package, baseline or script; deleting deployed content also uses policy_change |
| `gateway_widen` | conditional / access_policy | A gateway change widens accepted clients, identity evidence, transports or authorization reach; creation has its own always row |
| `grant_sensitive` | conditional / access_policy | Role, assignment or manual user-group change grants any permission named by an access policy; direct authority assignment requires its dedicated identity-authority operation |
| `group_change` | conditional / access_policy | OR of policy_change and grant_sensitive for manual user-group or device-group edits; include before/after policy effects and grants through group membership |
| `extension_dependency` | conditional / access_policy | Disable, uninstall or component revocation affects enforcing policy or a qualified browser adapter |
| `destination_change` | conditional / access_policy | Filter, projection, endpoint, credential, enable or disable changes; every change to an audit or archive destination |
| `hold_narrow` | conditional / access_policy | Release or narrow the retained evidence set |
| `audit_retention` | conditional / access_policy | Shorten audit retention; hold and archive gates remain independent |
| `child_union` | conditional / access_policy | OR of every allowed child's protection over the entire frozen scope; requires every applicable approval |

The catalogue treats recovery-token issuance, offline uninstall, urgent OS install, recovery-secret rotation, certificate-profile and external-CA changes, administrative service issuance, GitOps-source changes, settings, backup creation, connector registration and callback-token changes, index configuration, dead-letter replay, version retirement, quarantine promotion, cursor replay, backfill, endorsement-key writes, ATT&CK replacement, governed-pack re-enable, original deletion, callback-token revocation, external issuance reconciliation, archive-failure hold release and Apple push-topic replacement conservatively as protected by default. These inferred choices close gaps without relaxing BE-02; section 10 lists the review questions. Reject an unclassifiable security diff as protected, never as `none`.

Enrollment approval is PKI-02's exact request/CSR/device/profile decision with fresh authentication, not a BE-02 approval of an approval. Ordinary BE-02 decisions require `authz.approvals.approve` or `.reject` plus current policy eligibility. Identity-authority approve or reject requires the direct `identity.authority.approve` permission instead. Queue reads confer no decision rights. Decision operations do not recursively request another approval.

Publisher-key and certificate revocations cannot wait for approval. `extensions.trust.revoke` binds only `updateTrustList#add-publisher-key-revocation`. Id and version revocations bind `updateTrustList#add-id-revocation` and `updateTrustList#add-version-revocation` to `extensions.packages.revoke`, alongside `api:revoke-extension-id` and `api:revoke-extension-version`, with `extension_dependency` approval when an enforcing policy or a qualified adapter depends on the target. The generic `updateTrustList#add-revocation` selector is forbidden. `extensions.trust.revoke` cannot revoke an id or version, remove a revocation, add trust or transfer ownership; removing a revocation or adding trust requires the protected trust update operation, and ownership transfer requires `extensions.ownership.transfer`. Other resource removals still use their own rules. No permission authorizes offline custodian repair, signing-key export or access to a secret through report data.

The later request path must authenticate the principal, resolve active names, check grant kind and current scopes, classify every applicable rule, freeze the complete targets and exact before/after hashes, and create the request. A different eligible operator re-authenticates and decides. Immediately before mutation, signing and dispatch, the consumer reloads committed authority, requester and approver eligibility, exact hashes, epoch and one-use approval under BE-12's fence. Stale facts invalidate the request. Neither catalogue metadata nor a console control substitutes for any step; the fence remains an implementation blocker.

## 5. Go API and byte delivery

Package: `server/internal/authz/catalogue`, within `github.com/ricevanta/ricevanta/server`. Go 1.27.1 and its standard library are the only runtime dependencies. The implementer creates `catalogue.json` beside the Go package and embeds it as an unexported string with `//go:embed catalogue.json`.

The canonical file remains under `schemas/`. `TestBuiltinDrift` reads `../../../../schemas/permissions/v1/catalogue.json` relative to the package test directory and compares it byte-for-byte with the embedded string. Missing files fail, never skip. Full-repository checkout is required for tests; a compiled library needs no filesystem. Copy using `cp schemas/permissions/v1/catalogue.json server/internal/authz/catalogue/catalogue.json` from the repository root. No runtime override, environment path, network fetch or database copy exists.

This choice follows Go's [embed rules](https://pkg.go.dev/embed): patterns are package-relative and cannot traverse `..` or cross the module. A generated Go literal would need a generator and introduce escaping and formatting drift for no benefit. A separate schema Go module would add version and release coordination. Runtime file loading would permit host or database configuration to replace approval metadata. The duplicate JSON costs one small copy and a mandatory drift test.

```go
package catalogue

const MaxBytes = 1 << 20
const MaxEntries = 2048
const MaxDepth = 12

type Permission struct {
    Name, Owner, Scope, Protection, Approval, Rule, Grant, Status string
    Introduced, RetiredIn uint32 // RetiredIn is zero for active entries.
    Uses []string
    Source, Note string
}

type Catalogue struct { /* unexported immutable state */ }

func ValidateName(name string) error
func Parse(data []byte) (*Catalogue, error)
func Builtin() (*Catalogue, error)
func (c *Catalogue) Lookup(name string) (Permission, error)
func (c *Catalogue) Entries() []Permission
func (c *Catalogue) Revision() uint32
func (c *Catalogue) JSON() []byte
```

`Parse` returns nil on every error and owns a copy of successful input. `Builtin` parses once with `sync.Once`, returns the same immutable catalogue and cached error, and never panics on a bad embedded file. Consumers must stop initialization on error. It does not fall back to an empty catalogue. The complete built-in file must pass tests before release.

`Lookup` returns only active entries and a zero `Permission` on error. `Entries` returns all entries, including tombstones, sorted by name; callers must filter status for permission pickers. Every returned slice, nested `Uses` slice and JSON byte slice is a defensive copy. Modifying input bytes or any returned value cannot alter another caller's result. Concurrent reads need no caller lock. `JSON` returns exact accepted source bytes, not re-encoded JSON. It serves library consumers only; no HTTP handler belongs here.

A nil receiver and a zero `Catalogue` behave identically: `Entries` and `JSON` return nil, `Revision` returns 0, and `Lookup` applies name syntax first, then returns `ErrUnavailable`. Valid catalogues never expose mutable maps or parse state. The API takes no context because it performs bounded in-memory work and no I/O.

## 6. Errors and precedence

Sentinels use `errors.New` with the exact messages below. Wrapping may add a byte offset, entry index or field path, never raw input or secret values. Each failure matches exactly one sentinel through [`errors.Is`](https://pkg.go.dev/errors#Is); callers must not inspect error text. Do not join sentinels or expose decoder errors as a second classification.

| Sentinel | Exact message |
|---|---|
| `ErrLimit` | `permission catalogue limit` |
| `ErrJSON` | `permission catalogue JSON` |
| `ErrShape` | `permission catalogue shape` |
| `ErrVersion` | `permission catalogue version` |
| `ErrNameFormat` | `permission name format` |
| `ErrEntry` | `permission catalogue entry` |
| `ErrDuplicate` | `permission catalogue duplicate name` |
| `ErrOrder` | `permission catalogue order` |
| `ErrRevision` | `permission catalogue revision` |
| `ErrUnavailable` | `permission catalogue unavailable` |
| `ErrUnknownPermission` | `unknown permission` |
| `ErrRetiredPermission` | `retired permission` |

`ValidateName` returns nil or `ErrNameFormat`. `Lookup` checks name syntax, initialized catalogue, exact membership, then retirement, in that order. Unknown namespaces and verbs are syntactically valid but unknown to lookup. Retired rows never return partial metadata through lookup; historical displays use `Entries`.

`Parse` uses this whole-document phase order, not entry-by-entry shortcuts across phases:

1. Input over MaxBytes returns `ErrLimit` before any decoding, even if malformed.
2. Scan JSON left to right, validating UTF-8, escapes, decoded duplicate keys and a single complete value. The first lexical or syntax defect returns `ErrJSON`. Entering container depth 13 returns `ErrLimit` immediately if reached before a lexical defect; root container depth is 1. Reject a byte-order mark. `encoding/json` alone is insufficient: its [documented behavior](https://pkg.go.dev/encoding/json) accepts duplicate keys and replaces invalid UTF-8; typed decoding also matches keys without case sensitivity.
3. Check exact fields, required fields, types and integer-token spelling throughout. Root must be an object. Root revision and entry counts must meet their bounds. `format_version` must be an unsigned integer token in uint32 range; entry revision numbers must also be unsigned uint32 tokens. Violations return `ErrShape`, including missing required `name`. Optional `retired_in` presence and value relationships wait for later phases.
4. `format_version != 1` returns `ErrVersion`.
5. Validate every name's lexical grammar, in input order: `ErrNameFormat`.
6. Validate every entry against all remaining schema constraints in input order: enum values, namespace, verb, owner mapping, grant restriction, metadata lengths and ASCII, unique uses, rule/protection/approval agreement, positive introduced revision and status/retired_in presence and minimum. Any defect returns `ErrEntry`.
7. Duplicate decoded names anywhere return `ErrDuplicate`, even if their metadata differs or sorting also fails.
8. Names not strictly ascending return `ErrOrder`.
9. `introduced > revision`, or `retired_in <= introduced`, or `retired_in > revision` returns `ErrRevision`.

Stages 3 through 6 implement this particular schema in Go, not a general JSON Schema engine. Reject unknown metadata enums, never default them. Schema acceptance alone is insufficient: lexical wire checks, uniqueness by name, sorting and cross-field revision checks also apply. Bounded input and depth cap parser work; bound entries before allocating per-entry state, and never allocate from a hostile declared length. Every arbitrary byte slice or name must finish without panic.

## 7. Fixtures and required tests

[`fixtures/catalogues.json`](../../schemas/permissions/v1/fixtures/catalogues.json) wraps valid and invalid fragments, expected schema acceptance and the first Go sentinel. `wire_hex` cases represent invalid bytes without making the fixture file invalid JSON. [`fixtures/names.json`](../../schemas/permissions/v1/fixtures/names.json) uses the named active-and-retired fragment and records separate grammar and lookup outcomes. Empty expected error means success. The [fixture schema](../../schemas/permissions/v1/fixtures.schema.json) validates both wrappers; a JSON Schema validator checks each decoded fragment independently, including intentional failures. It does not claim to evaluate Go sentinels.

`fixtures/coverage.json` records each swept action's source section and exact text anchor, semantic selector, permission, owner, scope, approval rule, exact catalogue note, composed permissions and checks. `requires` lists unconditional extra permissions; alternatives and data-dependent reads remain in `checks` and section 3. Exemptions name subject-owned, protocol, automatic and out-of-band actions with their separate authority.

Validation has two modes. The default `python server/internal/authz/catalogue/schema_test.py` checks schemas, fixtures and catalogue bindings, including exact owner/note, derived protection/approval, active role grants, composed names and fixed names, without reading design or spec documents or comparing their digests. Go package tests also have no document-content or digest dependency and never invoke the Python source check. They retain catalogue parsing, fixture contracts and canonical-to-embedded byte equality. These checks cannot establish prose coverage.

The separate design-CI command `python server/internal/authz/catalogue/schema_test.py --check-sources` runs the default checks plus source-section anchors, console operation extraction, source-reference resolution and the ASCII-sorted, duplicate-free inventory of every `docs/design/*.md` and `docs/specs/*.md`. SHA-256 digests bind exact reviewed source bytes, including this spec. Added, removed or changed documents fail this mode only. The command is read-only and reports affected paths. The implementation plan assigns it to `.github/workflows/design.yml`; server CI uses only the default mode. Digests detect changed bytes, not semantic completeness, so a manual full-source sweep remains required.

Before regenerating, review every added document and every changed section against the pinned source bytes for operator actions, including indirect mutations. For removed documents, trace each action and exemption to its current authority or resolve its removal explicitly. Add exact permission bindings or a reasoned exemption before replacing the pins. If the pinned bytes cannot be recovered for comparison, review the complete document. An independent reviewer must confirm the action/exemption decisions and source inventory. A successful hash refresh alone is never review evidence.

After that source review, run this regeneration command from the repository root. It replaces only `documents`; it cannot generate or approve actions or exemptions. Run it after all spec edits, then run both validation modes. Any further source edit requires the same review and regeneration loop.

```sh
python - <<'PYCODE'
import hashlib
import json
from pathlib import Path

path = Path('schemas/permissions/v1/fixtures/coverage.json')
manifest = json.loads(path.read_text())
sources = sorted([*Path('docs/design').glob('*.md'),
                  *Path('docs/specs').glob('*.md')])
manifest['documents'] = [
    {'path': source.as_posix(),
     'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}
    for source in sources
]
blocks = []
for key, rows in manifest.items():
    encoded = ',\n'.join(
        '    ' + json.dumps(row, separators=(',', ': ')) for row in rows
    )
    blocks.append('  ' + json.dumps(key) + ': [\n' + encoded + '\n  ]')
path.write_text('{\n' + ',\n'.join(blocks) + '\n}\n')
PYCODE
```

Trust-list coverage checks exact selectors, not just the `updateTrustList` base operation. Each of the five revocation selectors in section 4 and `updateTrustList#trust-change` must bind exclusively to its named permission with the required rule, protection and approval; the trust-change branch remains `extensions.trust.update` with `always` / `access_policy`. Reject bare, generic, unknown, missing, duplicate or misbound trust-list selectors. [`fixtures/revocations.json`](../../schemas/permissions/v1/fixtures/revocations.json), validated by the fixture schema, supplies standalone three-entry fragments and expected `coverage_valid` results for this branch check. Every fragment must pass the catalogue schema; coverage rejection is separate from parser rejection. These fixtures check metadata bindings, not runtime dependency evaluation.

Coverage mutation tests remove each required entry, remove or rename its exact selector, change its owner/note/scope/rule/protection/approval/grant/status, and remove a composed permission. Each must fail for that defect. In design-source mode, also reject missing source anchors, stale digests and added or removed source files. In temporary copies, prove that an unrelated prose edit, source addition or source removal leaves default validation and Go tests passing while design-source validation fails. Catalogue binding mutations must fail default validation; embedded-byte mutations must still fail Go tests. Retirement vectors cover a pinned policy in another group, an unpinned dependency, unresolved targets and changed dependencies before commit. Quarantine vectors cover device-binding mismatch and stale validation; export vectors cover missing audit/evidence reads, partial device scope and changed projection; endorsement-key vectors cover missing affected-group access. These consumer vectors specify future authorization tests; the metadata validator checks their bindings and cannot execute a consumer that does not exist.

Required Go vectors include all shipped cases and these generated boundaries:

- MaxBytes-1, MaxBytes and MaxBytes+1 with valid JSON padded by spaces; oversize plus malformed JSON returns `ErrLimit`. Depth 12 reaches shape checking, depth 13 returns `ErrLimit`; lexical failure before the thirteenth container returns `ErrJSON`.
- Entry counts 0, 1, 2,048 and 2,049. Generate sorted distinct valid names and valid metadata for accepted limits; too many entries return `ErrShape`.
- Token lengths 1, 32 and 33; total lengths 5, 98 and 99; embedded NUL, invalid UTF-8, trailing newline, confusable Unicode, escaped ASCII, uppercase, wildcard and leading/trailing spaces.
- Root and entry revision 0, 1 and MaxUint32; overflow and non-integer token spellings; active with retirement, retired without retirement, equal introduced/retired revision and future introduced revision.
- Missing and unknown fields at both object levels, null and wrong primitive types, empty and duplicate uses, 32 and 33 uses, all ASCII metadata bounds, unknown namespace/verb/owner/scope/grant/rule and mismatched approvals.
- Duplicate root and nested keys, escaped duplicate keys, case aliases, lone surrogates, invalid UTF-8, BOM, trailing scalar/object, truncation and empty input. A valid surrogate pair in metadata reaches `ErrEntry` for non-ASCII, not `ErrJSON`.
- Every adjacent phase pair combined, including an invalid later name with an earlier bad scope, bad entry plus duplicate name, and duplicate name plus unsorted entries. Assert exactly one matching sentinel and nil output on parse failure.
- Lookup precedence on nil and zero catalogues; syntax before unavailable; unavailable before unknown; active success, retired failure and unknown failure. Input and returned-slice mutation, concurrent reads and exact JSON copies.
- Byte drift, missing canonical file, accidental removal of a permanent tombstone, changed meaning under an existing name, swept action contracts and the fixed seven names without opening source documents. Console operation extraction and source freshness belong to the separate design-source check. Lifecycle compatibility compares the proposed catalogue with the reviewed base revision, not just itself.

`FuzzValidateName` feeds arbitrary strings and checks equivalence with an independent byte-grammar oracle. `FuzzParse` feeds bounded arbitrary bytes; successful results must preserve exact bytes, pass lookup for every active entry and return the retirement sentinel for each tombstone. Reparse returned bytes and compare metadata and revision. Error paths return nil and one sentinel. Seed both targets with all fixtures, decoded wire bytes and generated boundaries.

## 8. Security trace and limits

The metadata trust path is reviewed repository JSON, byte drift test, compiled embedded bytes, strict parser, immutable lookup, then an independently authorized consumer. A signed release and trusted build remain assumptions. A process or build compromise can replace the catalogue; this package is not a code-integrity mechanism.

| Attacker | What the slice permits and prevents; remaining boundary |
|---|---|
| Stolen enrollment token | No console catalogue grant follows from token possession. PKI-02 still limits group, use, expiry and exact enrollment approval; the package cannot authenticate the token. |
| Compromised agent host | Malicious name strings fail grammar or lookup, but valid names grant no authority. The host can send its permitted telemetry; agent reports cannot turn a console permission into committed authority. |
| Compromised console session | Can discover permission metadata and request actions within current rights. Catalogue flags tell the consumer which approval path to invoke; fixed identity approval, fresh authentication and BE-12 consumption must prevent escalation. The package alone does not enforce them. |
| Rogue extension publisher | Cannot register permissions or replace embedded rows. A named permission never makes an operation bridge-safe. Grants, safe-operation catalogue, current binding, child-permission union and immediate revocation still govern execution. |
| Network position between agent and server | Cannot change compiled metadata through an upload or runtime override. Transport authentication remains outside this package; intercepted names have no bearer authority. |
| Database writer without signing keys | Cannot edit the binary's catalogue or make unknown/retired names valid. Can forge stored grants or approval rows; consumers must reject them through the unresolved authority-journal protocol, not trust lookup. |
| Server restored from backup | Catalogue comes from the selected binary, not restored rows. Unknown and retired grants fail, but an older binary can contain older metadata. Sealed recovery and release compatibility must prevent authority resurrection; this slice supplies neither fence. |

## 9. Benefits, trade-offs and dependencies

One machine-readable inventory makes permission pickers, API bindings and reviews compare exact names. Closed metadata and distinct errors make silent defaulting testable. Device scope remains distinct from organization administration, while fixed direct and connector grants cannot be mistaken for role entries.

The cost is a large explicit inventory, a copied embedded file and manual Go/schema parity checks. JSON Schema cannot express every wire and cross-entry invariant. Pure metadata cannot prove that a consumer uses the right permission, applies every predicate or checks all entities; endpoint integration remains a security review gate.

Dependencies are Go 1.27.1 only at runtime and Python `jsonschema==4.25.1` for design validation. The installed tools also include Rust 1.99.0 with cargo 1.99.0, Node 24.21.0 and pnpm 11.18.0; this slice invokes none of them in production. No Go dependency or licensing change is needed. Cryptography 50.0.0 is installed but unused.

[JSON Schema 2020-12](https://json-schema.org/draft/2020-12/json-schema-core) supplies the schema vocabulary. Permission grammar, byte bounds, error ordering and approval metadata are Ricevanta contracts, not standard claims. First-party sources confirm the Go behavior cited above; this spec introduces no unconfirmed platform claim marked `verify`.

Rejected freshness rule: checking document digests in Go tests or the default server validator couples package correctness to unrelated prose edits and repeatedly blocks parallel design work. Dropping digest checks entirely loses the source-review gate; design CI retains it separately.

Rejected alternatives: generated Go literals need a generator; runtime catalogue loading enlarges the authority surface; permission discovery from route names misses GitOps and indirect weakening; generic `write` or wildcard permissions hide distinct commands; expanding every action into a new module conflicts with BE-04; implementing access-policy evaluation here would depend on unresolved BE-12 guarantees.

## 10. Unresolved questions

These questions do not block the isolated catalogue library. They block consumers where named. Defaults below remain the catalogue choice unless independent review changes them.

- Should any conservatively protected implied operation in section 4 use a narrower predicate? The chosen default is approval for every invocation; an unprotected mutation is rejected as too permissive without a domain contract.
- Should shared policy definitions use organization scope with separate device-scoped publication permissions? The chosen default keeps policy CRUD device-scoped with full before/after target coverage; treating scope as a filter on the policy list alone is rejected.
- Which exact OpenAPI operation IDs, branch selectors and grant-scope wire schema implement the semantic `api:` and `view:` uses? Keep them semantic and require deny-by-default routing until that review; guessing paths is rejected.
- What no-self-escalation and dependency-closure rules govern manual group edits, role grants, shared report schedules and global settings? Require organization permission plus all affected authority checks; membership edits as unrestricted device CRUD are rejected.
- Which report source schemas carry the proposed reads, and how do mixed device/infrastructure PKI datasets declare organization scope? Use separate source requirements and reject mixed data without `all`; widening a device-only result is rejected.
- What signed revision, floor and convergence contract completes reclassification, and what qualified protocols complete escrow rotation, response actions and recovery? Retain their permissions but keep execution blocked; catalogue membership as qualification is rejected.
- How will release and authority recovery enforce the minimum compatible catalogue revision across rollback and rolling upgrades? Reject unknown and retired names locally; treating a restored database's revision as authority is rejected.

## Review focus

- Every explicit permission, prose-defined operator action and implied console mutation has an entry or an explicit subject/protocol exemption; no invented module becomes a Go owner.
- Verify before/after target coverage, report source intersections, infrastructure certificate separation and device-group membership escalation boundaries.
- Check BE-02 thresholds at 10 and 11, indirect weakening, immediate revocation, fixed identity approval and extension child unions.
- Check schema/Go parity, strict duplicate-key and Unicode handling, whole-document error precedence and immutable results.
- Confirm that no metadata flag, lookup, fragment or embedded file claims to implement authorization, authority recovery or native qualification.
