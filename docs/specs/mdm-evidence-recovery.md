# MDM evidence freshness and recovery-key transactions

The candidate evidence rules that prevent a compromised MDM listener from turning old Apple results into current compliance, and the candidate transaction that preserves Windows and Linux recovery while keys rotate or disk lock removes other routes. This specification refines MDM-06 and MDM-07. Baseline computation remains in `baseline.md`; platform mechanisms remain in `../design/mdm.md`.

Claims labelled **design inference** need the qualification experiments in section 5. The escrow candidate is incompatible with current key custody and FileVault trust boundaries. Until the central designs adopt the dependencies in section 6, an unproved evidence item stays `unknown` and recovery-route retirement is unavailable.

## 1. Threat and proof boundaries

The `device` role may drop, delay, duplicate and reorder Apple bodies or agent escrow submissions. It may replay observed bytes and acknowledge HTTP without forwarding a body. It cannot forge a device CMS signature, a device identity signature or a key held only by `jobs`. Endpoint compromise is outside this protocol proof.

For Apple messages with `SignMessage` enabled, `jobs` verifies the detached CMS signature over the exact raw HTTP body, validates the certificate chain and enrollment identity, and cross-checks the body UDID with that enrollment. Apple states that successful CMS validation proves that the message came from the signing certificate. CMS does not provide a server challenge, freshness, ordering or proof that the reported value still holds.

| Fact | Required proof |
|---|---|
| Origin | Valid CMS body and current enrollment certificate |
| Desired revision | Exact required-set and native declaration bindings or query field set |
| Fresh observation | Unconsumed current server challenge answered by the signed body |
| Ordering | Per-evidence-key generation, failure floor and atomic consumption in `jobs` |
| Evidence lifetime | Current-primary database clock measured against challenge issuance |

Only evidence that proves all five facts may raise compliance, replace a failure with a pass or refresh expiry. A valid failure may lower compliance without freshness, but section 2.1 orders that failure against later passes.

## 2. Apple evidence

### 2.1 Command queries and failure floors

Each evidence key has a row containing its current challenge generation, accepted-failure generation and body digest, and accepted evidence generation. `jobs` creates an `AppleEvidenceChallenge` under the BE-12 authority protocol before dispatch: organization, device uid, enrollment uid, recovery epoch, required-set hash, exact evidence-key set, command and requested fields, random `CommandUUID`, per-key generations, issued time and deadline. One challenge may cover many keys. A new challenge generation for a key commits after that key's current failure floor and supersedes its older raise challenges before it is visible to `device`.

An accepted response has valid CMS origin, the current enrollment and epoch, the exact `CommandUUID`, expected response shape and every requested field. One current-primary transaction locks the challenge and all evidence-key rows in sorted order. It reads the current-primary database clock inside that transaction, after the locks, and rejects a deadline that has passed. Listener time, HTTP receipt time and the transaction-start timestamp are not evidence.

The transaction validates the complete body before applying any result. For each key independently, an accepted failure advances that key's failure floor and supersedes every raise challenge whose generation is not later than the new floor. A body with conflicting outcomes for one key is invalid. It then accepts a pass for a key only when that key is in the exact challenge key set, its challenge generation was committed after the current failure floor, and its required-set binding still matches. A pass for one key cannot cover a missing, failed or superseded sibling key. The transaction consumes the one command challenge, stores the raw-body SHA-256 and the per-key outcomes, and produces no partial retry surface. An exact duplicate is idempotent and cannot refresh evidence time.

Challenge creation, generation allocation, supersession, failure-floor advance, consumption, body digest and accepted evidence are recoverable BE-12 journal after-images. No accepted evidence becomes visible until the journal commit is in the authenticated resolved prefix. Evidence time is the challenge issue time.

`SecurityInfo`, `DeviceInformation`, `ProfileList`, `CertificateList` and `InstalledApplicationList` may supply only fields their Apple schemas return. A command acknowledgement proves command processing, not fields outside its response.

### 2.2 Declarative status

Apple status reports are unsolicited. `FullReport: true` means the body contains the current full status set; Apple describes this as a safety-sync report sent about every 24 hours. `management.declarations` names processed declaration identifiers and server tokens. Status-subscription schema contains no nonce or on-demand full-report request.

The candidate challenge is a no-op revision of Ricevanta's `management.status-subscriptions` declaration with a new random server token. Its BE-12 after-image binds the recovery epoch, generation, required-set hash, exact evidence-key set, challenge declaration identifier and token, and every desired declaration identifier and server token. A required-set or desired-declaration change commits a superseding generation before new desired state is visible.

A CMS-signed full report may raise or refresh one bound key only when the same body contains `FullReport: true`, every bound evidence key, no error for that key, and `management.declarations` entries showing the challenge declaration and every current desired declaration with exact identifiers and tokens, `active: true` and `valid: valid`. Per-key failure floors, current-primary deadline checks, multi-key handling and BE-12 publication follow section 2.1.

**Design inference:** processing the challenge and desired declarations before one full report gives a lower bound on report creation, and the full report is one ordered current snapshot. Apple documents neither an on-demand full report nor this cross-item snapshot guarantee. Until section 5 proves both on every eligible macOS release, declarative status cannot raise compliance or refresh evidence. Other qualified authority may satisfy an item; otherwise it stays `unknown`.

## 3. Escrow authority and objects

The candidate requires a dedicated escrow-acknowledgement signing key held only by `jobs`. Its root-certified certificate has a Ricevanta escrow-ack extended key usage and may sign only DSSE payload types `application/vnd.ricevanta.escrow-ack+json` and `application/vnd.ricevanta.escrow-retirement-authorization+json`. The agent verifies the chain, signer, extended key usage and exact DSSE payload type. The policy signing key cannot serve this purpose because current BE-03 shares that key with `api`. Current key custody therefore cannot satisfy MDM-07.

`EscrowSubmission` is device-signed and binds organization, device uid, recovery epoch, transaction uid, operation, authority binding, platform, stable volume identity, route type and new route id, generation, frozen pre-operation inventory hash, exact retirement route ids, challenge, recipient escrow-certificate SHA-256 fingerprint, HPKE suite identifiers, ciphertext SHA-256 and report counter. HPKE `info` binds all fields except ciphertext hash and report counter. The server and endpoint retain referenced recipient private keys, acknowledgement keys, certificates, escrow records, encrypted local transaction material and wrapping dependencies until no open or retained transaction references them.

`jobs` verifies authority and consumes the report counter through BE-12. It opens the ciphertext, validates the secret format, stores the envelope-encrypted secret and route metadata, then reads back and opens the committed record. The BE-12 after-image contains the recoverable encrypted secret record, canonical acknowledgement payload, acknowledgement counter, references and consumption state, not hashes alone. After journal publication, `jobs` signs the persisted canonical payload. A retry reopens the committed encrypted secret and re-signs that same payload and counter under a currently valid escrow-ack key.

Immediately before any deletion, and again after restart or authorization expiry, the agent requests a fresh retirement authorization. `jobs` reloads current authority, reopens the committed encrypted secret, verifies the canonical acknowledgement and frozen retirement set, and signs their digests with a fresh nonce and short database-clock deadline. The agent commits and verifies that authorization before deleting one route. An acknowledgement alone never authorizes deletion.

## 4. Endpoint transaction

One exclusive transaction lock covers each stable volume identity. The `synchronous=FULL` journal states are `prepared`, `route_created`, `route_verified`, `submitted`, `ack_committed`, `retiring`, `complete` and `reconcile_required`.

1. `prepared`: freeze identity and inventory, generate the secret and challenge, and persist only locally sealed recovery material and metadata. Linux records an intended empty slot, but the number is not a stable identity across another writer's replacement.
2. `route_created`: add one route without removing another. Windows records an ordinary unique `VolumeKeyProtectorID`. The literal `BitLocker` result documented for hardware encryption is rejected unless qualification proves a unique, manageable identity. Linux exact-slot creation remains blocked by the exclusion requirement below.
3. `route_verified`: enumerate the same volume and verify the secret against the exact new route. Windows checks protector id, numerical-password type and returned password. Linux uses `cryptsetup open --test-passphrase --key-slot <slot>`. Both remain design inferences until qualification.
4. `submitted`: retry identical signed bytes while retaining all old routes.
5. `ack_committed`: verify and persist the jobs-only acknowledgement and challenge consumption.
6. `retiring`: obtain fresh retirement authorization, then delete only its frozen route ids one at a time. Journal intent before each deletion and the observed after-state after it. Normal rotation retires prior Ricevanta recovery routes. Lock retires every frozen unlock route except the new route.
7. `complete`: require the exact expected post-state, erase local transaction ciphertext, and durably record and perform a lock restart.

Cryptsetup's LUKS2 metadata lock makes one header read or write atomic but explicitly does not prevent negative logical effects from concurrent writers. A numeric slot can be removed and reused between Ricevanta's comparison and deletion. Linux retirement is blocked until Ricevanta either excludes every header-writing path across the whole compare-delete interval or uses a qualified primitive that atomically compares the expected slot material and header generation while deleting. Cryptsetup's per-command lock alone is insufficient.

Journal-proved expected partial progress between deletions resumes under a fresh readback-backed retirement authorization when the original approval still matches the exact plan. An unexpected route, identity, header generation or type, failed verification, unjournaled or ambiguous partial deletion, or mismatch with the original approval moves the transaction to `reconcile_required` and stops further deletion. A new protected approval must bind that observed partial after-state, surviving retirement set and continuation. The agent never rolls back a partial deletion. Before deletion starts, cancellation may remove the new route only after it proves at least one specific old route still unlocks the volume and obtains authority bound to that proof. Merely finding old route ids is insufficient. After deletion starts, cancellation cannot remove the new route.

Dynamic deletion, broad slot selectors and recovery from a hash without the encrypted after-image are forbidden.

### 4.1 Platform and crash cases

- A crash before route creation resumes from sealed `prepared` state. A crash after creation identifies exactly one route by opening the sealed secret and testing candidates; zero or multiple matches require reconciliation.
- A lost acknowledgement resubmits identical bytes. After an acknowledgement or crash, journal-proved expected progress resumes under a fresh readback-backed retirement authorization while the original approval still matches the exact plan.
- Exact absence after a recorded deletion completes that step only when route identity cannot have been reused. Any ambiguity stops.
- A restored server remains sealed without the journal, current epoch and all referenced keys and wrapping dependencies.
- BitLocker uses `PersistentVolumeID` and exact `DeleteKeyProtector` calls. The ordinary unique protector-id requirement and hardware-encryption rejection apply.
- A copied old LUKS header can restore a retired route and remains an OS limit.
- FileVault is separate. `RotateFileVaultKey` returns the new personal recovery key encrypted as CMS data and binds `CommandUUID`, but Apple exposes no endpoint acknowledgement of durable server storage. A compromised TLS-terminating `device` role can return HTTP success and discard the body. Honest crash and retry tests cannot prove safety against that role. Current trust boundaries cannot qualify FileVault rotation. Ricevanta needs an Apple protocol guarantee that prevents key loss or a response-path redesign that the exposed role cannot bypass.

## 5. Qualification and minimal slice

Apple tests cover valid and invalid CMS chains, UDID mismatch, duplicate and reordered bodies, query supersession, per-key failure races, mixed multi-key outcomes, current-primary deadline crossing and journal recovery. A hostile `device` fixture withholds a pass past a later failure. DDM tests rotate challenge and desired declaration tokens, mutate values around report creation and prove full-report timing and snapshot ordering. FileVault tests include a hostile TLS listener that acknowledges and discards the rotated-key body; success under current boundaries is not expected.

Windows tests inject failure at every journal and BE-12 boundary, exercise acknowledgement-key rotation and retained-key restore, return literal `BitLocker`, mutate protectors, partially delete routes, lose retirement authorization and reboot into offline recovery. Linux tests cover every required root LUKS2 unit, external cryptsetup and libcryptsetup writers, slot reuse, header restore, partial deletion and offline recovery. A test must demonstrate all-path exclusion or atomic compare-delete before Linux retirement qualifies. No output contains a secret.

The minimal future code slice is Apple `SecurityInfo` evidence only: per-key challenge and failure-floor rows, sorted locking, current-primary deadline checks, raw CMS verification, exact multi-key consumption and replay fixtures. It excludes DDM and recovery mutation. The slice remains blocked until the BE-12 executable storage and database protocol can journal and publish its recoverable authority after-images.

## 6. Design impact

Benefits: separate origin, freshness and ordering proofs prevent a listener replay from granting compliance; readback-backed acknowledgements prevent an upload receipt from authorizing key deletion; exact retirement sets limit destructive scope.

Trade-offs: current-primary and authority-journal writes add latency; jobs-only key custody and retained wrapping dependencies complicate backup; conservative races stop recovery-route cleanup for operator action.

Dependencies: BE-12 executable journal protocol; a jobs-only escrow-ack key, certificate profile, trust bundle and recoverable key manifest; durable encrypted after-images; a Linux all-path exclusion or compare-delete primitive; an Apple FileVault trust-boundary solution.

Limits: DDM snapshot ordering, FileVault durable receipt, Linux safe retirement and hardware-encrypted BitLocker protector identity remain unproved. Missing evidence stays `unknown`; an incomplete retirement stays unavailable or `reconcile_required`.

Alternatives rejected: CMS receipt time as freshness; the shared policy key for escrow acknowledgements; per-command cryptsetup locking as transaction exclusion; route-id presence as proof of recoverability; FileVault crash tests as proof against a malicious listener.

Adoption requires central changes to MDM-06, MDM-07, BE-03 and BE-12; the architecture key table; PKI certificate profiles; backend authority after-images and key-retention rules; agent trust verification; backup key manifests; baseline evidence rules; MDM design; analysis blockers; and platform qualification.

## Sources

- Apple: [message CMS and enrollment identity](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices), [command delivery and acknowledgement](https://developer.apple.com/documentation/devicemanagement/sending-mdm-commands-to-a-device), [status report schema](https://github.com/apple/device-management/blob/release/declarative/protocol/statusreport.yaml), [processed declaration status](https://github.com/apple/device-management/blob/release/declarative/status/management.declarations.yaml), [status subscriptions](https://github.com/apple/device-management/blob/release/declarative/declarations/configurations/management.status-subscriptions.yaml), [SecurityInfo schema](https://github.com/apple/device-management/blob/release/mdm/commands/information.security.yaml), [FileVault rotation](https://developer.apple.com/documentation/devicemanagement/rotate-filevault-key-command).
- Microsoft: [Win32_EncryptableVolume](https://learn.microsoft.com/en-us/windows/win32/secprov/win32-encryptablevolume), [create a numerical-password protector](https://learn.microsoft.com/en-us/windows/win32/secprov/protectkeywithnumericalpassword-win32-encryptablevolume), [delete one protector](https://learn.microsoft.com/en-us/windows/win32/secprov/deletekeyprotector-win32-encryptablevolume).
- Linux: [LUKS2 locking model and limitations](https://gitlab.com/cryptsetup/cryptsetup/-/blob/master/docs/LUKS2-locking.txt), [exact-slot creation](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup-luksAddKey.8.adoc), [exact-slot passphrase test](https://man7.org/linux/man-pages/man8/cryptsetup-open.8.html), [systemd exact wipe behavior](https://github.com/systemd/systemd/blob/main/man/systemd-cryptenroll.xml).
- Protocols: [HPKE](https://www.rfc-editor.org/rfc/rfc9180), [DSSE](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md).
