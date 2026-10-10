# Shared DSSE envelope primitive

A standard-library-only Go package signs and verifies Ricevanta's single-signature DSSE profile. Shared vectors fix the bytes that Go and a later Rust verifier must agree on. This slice supplies cryptographic integrity, not artifact authorization. SH-05 records the profile; [the plan](../plans/dsse-envelope.md) gates implementation on independent review.

## 1. Scope and location

Use `server/internal/signing/dsse` in module `github.com/ricevanta/ricevanta/server`, with Go 1.27.1. The package imports only the standard library and no Ricevanta module. Policy and extensions both import this leaf package. This realizes the reuse required by [backend design section 2](../design/backend.md#2-library-choices) without making extensions import the policy module. A policy-owned package would couple unrelated consumers; a public package would promise an external API before a consumer exists.

The profile narrows DSSE deliberately. The [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md) permits both base64 alphabets and defines verification over distinct trusted keys for thresholds. The [envelope specification](https://github.com/secure-systems-lab/dsse/blob/master/envelope.md) permits extra fields and optional key hints. Ricevanta requires standard padded base64, a closed field set, a hint and exactly one signature. This package is not a general DSSE consumer. The wire array is `signatures`, as in the upstream examples, not the singular `signature` spelling in its parsing-rule prose.

No server consumer, Rust implementation, certificate profile, journal protocol or recovery quorum ships in this slice. These omissions do not reduce v1.0.0 requirements on macOS ARM64, Windows x64 or Linux x64.

## 2. Exact Go API

```go
package dsse

type PayloadType string

const (
    TypeBundleManifest PayloadType = "application/vnd.ricevanta.bundle-manifest+json"
    TypeAssignment PayloadType = "application/vnd.ricevanta.assignment+json"
    TypeRulePackManifest PayloadType = "application/vnd.ricevanta.rulepack-manifest+json"
    TypeCommand PayloadType = "application/vnd.ricevanta.command+json"
    TypeCommandDispatchGrant PayloadType = "application/vnd.ricevanta.command-dispatch-grant+json"
    TypeComplianceStatement PayloadType = "application/vnd.ricevanta.compliance-statement+json"
    TypeIntelDelta PayloadType = "application/vnd.ricevanta.intel-delta+json"
    TypeRelease PayloadType = "application/vnd.ricevanta.release+json"
    TypeExtensionManifest PayloadType = "application/vnd.ricevanta.extension-manifest+yaml"
    TypeExtensionIndex PayloadType = "application/vnd.ricevanta.extension-index+json"
    TypeEscrowAck PayloadType = "application/vnd.ricevanta.escrow-ack+json"
    TypeEscrowRetirementAuthorization PayloadType = "application/vnd.ricevanta.escrow-retirement-authorization+json"

    MaxPayloadBytes = 16 * 1024 * 1024
    MaxEnvelopeBytes = 24 * 1024 * 1024
    MaxSignatures = 1
)

type Verified struct {
    PayloadType PayloadType
    Payload []byte
    KeyID string
    EnvelopeSHA256 [32]byte
}

func Sign(payloadType PayloadType, payload []byte,
    certificateSHA256 [32]byte, privateKey ed25519.PrivateKey) ([]byte, error)
func Verify(envelope []byte, expectedType PayloadType,
    publicKey ed25519.PublicKey) (Verified, error)
```

The signature declarations use `crypto/ed25519`. No other functions, methods or types are exported. `Verify` returns the payload decoded during the successful verification, never a second parse. `Verified` means signature-valid under the supplied key, not trusted, fresh or authorized. Its payload has independent storage, including a non-nil zero-length slice for empty payloads. `Sign` returns independently owned bytes. Neither function retains inputs or changes them. Callers must not mutate input slices during a call. Calls share no mutable state and require no context, clock, randomness or I/O.

On error, `Sign` returns nil and `Verify` returns `Verified{}`. Functions never panic on malformed values. Error wrapping may add static field context but never payloads, keys or full envelopes. Each failure matches exactly one sentinel through `errors.Is`; error text is not the test contract. Declare each sentinel with `errors.New` and the following exact message:

| Sentinel | Message |
|---|---|
| `ErrEnvelopeTooLarge` | `dsse envelope too large` |
| `ErrEnvelope` | `dsse envelope format` |
| `ErrSignatureCount` | `dsse signature count` |
| `ErrPayloadType` | `dsse unsupported payload type` |
| `ErrTypeMismatch` | `dsse unexpected payload type` |
| `ErrKeyID` | `dsse keyid format` |
| `ErrPayloadTooLarge` | `dsse payload too large` |
| `ErrBase64` | `dsse base64 format` |
| `ErrSignature` | `dsse invalid signature` |
| `ErrPublicKey` | `dsse public key length` |
| `ErrPrivateKey` | `dsse private key format` |

A public parse-only API would invite consumers to use unverified payloads. A generic `crypto.Signer` would add algorithm and custody behavior outside this slice. Both are rejected. Raw Ed25519 keys keep the primitive testable; custody-specific signing adapters need a separate reviewed API.

## 3. Payload types and caller intent

The constants in section 2 are the full closed list of named Ricevanta DSSE payload types. No registration API, wildcard, MIME normalization, parameters or aliases are accepted. The first eight come from [policy-envelope section 7](policy-envelope.md#7-signatures). Extension types come from [extension design sections 2 and 8](../design/extensions.md). The two escrow types come from [the escrow candidate](mdm-evidence-recovery.md); recognizing their names does not approve their key profile or enable issuance or acceptance.

The caller chooses one `expectedType` from its operation, not from the envelope. Both type strings must belong to the list and compare byte-for-byte before any signature verification. Rejecting a mismatch prevents a valid signature for one artifact kind from being treated as another kind. Inferring the expected type from untrusted input defeats that boundary and is rejected. The type does not select a key or authorize its use.

[Architecture section 4](../architecture.md#4-keys-and-what-they-sign) leaves these contracts open. Consumers remain blocked; the primitive does not invent strings:

| Key or artifact | Open question |
|---|---|
| Journal signing key | What exact payload types cover live authority heads, audit heads, prepare records and commit records? |
| Audit checkpoint key | What payload type identifies an audit checkpoint? |
| Offline recovery custodian keys | What types identify authority repairs, signer replacements and recovery transitions, and what wire format carries the quorum? |
| Release signing keys | What type identifies a project release manifest or package attestation? `TypeRelease` is specified for the organization's offline release object, not an assumed project-update schema. |
| Root CA | Does the recovery quorum manifest use DSSE or another signed format, and what type applies if DSSE is chosen? Certificates are not DSSE payloads. |
| Policy signing key | What type identifies a full intel snapshot or an exception-time anchor if those artifacts use DSSE? The named delta type does not settle their encoding. |

Issuing CAs sign certificates; RADIUS sealing and platform code-signing identities do not need a type in this profile. Publisher manifests and the index have named types, but the publisher certificate format remains open: how does a raw publisher key acquire the certificate fingerprint required by the shared envelope rule? Project release trust uses compiled keys and also needs an explicit hint contract. Neither uncertainty permits treating a raw-key hash as a certificate hash.

## 4. Parsing and limits

`Verify` accepts one UTF-8 JSON object and only JSON whitespace before or after it. It rejects a byte-order mark, a second value, trailing non-whitespace, comments and invalid JSON. The exact root fields are `payloadType` (string), `payload` (string) and `signatures` (array). Every signature element must be an object with exactly `keyid` and `sig`, both strings. Missing, unknown, duplicate or differently cased keys fail, including identical duplicate values and escaped names that decode to the same key. Every null and every wrong JSON value type fails.

Field order and JSON whitespace are unrestricted. Legal JSON escapes are accepted in keys and values after decoding; decoded names must still match exactly. Invalid UTF-8 and unpaired UTF-16 surrogate escapes fail rather than becoming replacement characters. A valid surrogate pair produces its scalar value, which must then satisfy the field's type, fingerprint or base64 rules. Payload bytes themselves need not be UTF-8 or JSON.

Use bounded token parsing with explicit field sets and duplicate detection, not direct struct or map decoding. Reject unexpected nesting without building a generic object tree. A syntax/Unicode pass may precede the shape pass to implement section 7. Per-object state is fixed-size; count signatures without building an unbounded signature slice. [Go encoding/json](https://pkg.go.dev/encoding/json@go1.27.1#Unmarshal) accepts duplicate keys, matches struct fields without regard to case, ignores unknown fields by default and replaces invalid string encodings. `DisallowUnknownFields` alone cannot enforce this contract. Reject those permissive defaults because two consumers could choose different signed content.

| Input or limit | Rule and rejected alternative |
|---|---|
| Envelope | At most `MaxEnvelopeBytes`, inclusive, measured on received bytes before parsing. No unbounded decoder input. |
| Payload | At most `MaxPayloadBytes`, inclusive, decoded. Cap encoded text at 22,369,624 bytes before allocation; decode and check actual length too. No archive-sized allowance for a small control manifest. |
| Signatures | Exactly one, so the maximum is one. Reject both zero and multiple signatures, even if every signature is valid. No first-valid-signature shortcut. |
| Empty payload | Accept `""`, corresponding to zero bytes. Nil signing input has the same meaning. Requiring valid JSON or nonempty bytes would mix schema validation into signing. |
| Empty payloadType | Reject as `ErrPayloadType`. No default artifact kind. |
| Empty keyid | Reject as `ErrKeyID`. No omitted hint in this Ricevanta profile. |
| Empty sig | Decode as zero bytes, then reject as `ErrSignature`. No unsigned envelopes. |
| Base64 | Standard alphabet `A-Z a-z 0-9 + /`, exact `=` padding when needed, zero pad bits, no whitespace inside the decoded JSON string. Reject URL-safe characters, missing or excess padding and CR/LF. |

For each base64 field, use `base64.StdEncoding.Strict()` and require equality with `StdEncoding.EncodeToString(decoded)`. Discard partial output on error. [Go base64 documentation](https://pkg.go.dev/encoding/base64@go1.27.1#Encoding.Strict) states that strict decoding checks pad bits but still ignores CR/LF; the equality check closes that gap. JSON escapes for base64 characters remain valid because canonicality here applies to the decoded string, not its JSON spelling.

The limits are profile choices, not measured capacity claims. Sixteen MiB allows control manifests and intel documents without admitting bundle archives; 24 MiB leaves room for base64 expansion and metadata. Callers must impose smaller operation limits where needed, cap transport and decompression before allocating input, and bound concurrent verifications. Work and temporary storage are O(envelope bytes + payload bytes); the package does not promise a one-copy memory cap. Qualify consumer budgets before adoption. Configurable or unlimited primitive limits would make Go and Rust acceptance differ and are rejected.

## 5. Signing, hints and trust

Pre-authentication encoding (PAE) is the concatenation of ASCII `DSSEv1`, one space, the decimal byte length of the UTF-8 type, one space, the type bytes, one space, the decimal payload byte length, one space, and the exact payload. Decimal lengths have no leading zeros; zero is `0`. No trailing delimiter follows the payload. The [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md) authenticates type and payload; `keyid` is outside PAE.

`Sign` uses deterministic plain Ed25519 on the complete PAE. It does not sign the JSON envelope, prehash PAE, normalize payload bytes, or use Ed25519ph or Ed25519ctx. Validate a private key as exactly 64 bytes and require equality with `ed25519.NewKeyFromSeed(privateKey[:32])`, including its public-key suffix, before signing. Validate a verification key as exactly 32 bytes before calling Ed25519. A 64-byte but cryptographically invalid signature returns `ErrSignature`. [Go Ed25519](https://pkg.go.dev/crypto/ed25519@go1.27.1) documents the key sizes, seed representation and panics on wrong key lengths. These guards prevent caller mistakes from crashing a process.

The signer produces this exact ASCII layout, with no whitespace or final newline:

```text
{"payloadType":"TYPE","payload":"BASE64","signatures":[{"keyid":"HEX","sig":"BASE64"}]}
```

`TYPE` is the selected constant; both base64 values use section 4; `HEX` is 64 lowercase hexadecimal characters. Those alphabets need no JSON escaping, so a fixed encoder can produce identical bytes in Go and Rust without depending on map order. Equal type, payload, fingerprint and private key produce equal envelope bytes. Canonical output does not mean that all accepted input has that spelling.

The caller supplies `certificateSHA256 = sha256.Sum256(leafCertificateDER)`, where DER is the exact signing certificate, not PEM text, a public key or SubjectPublicKeyInfo. Every 32-byte value, including zero, has a valid hint representation; the primitive cannot prove a certificate exists or matches the signing key. Certificate construction and signing services must check that binding. Colons, uppercase hex, prefixes and base64 fingerprints are rejected to keep one hint representation.

`Verify` ignores `keyid` for key selection and signature verification. Its returned `KeyID` is unauthenticated metadata. A caller may use a hint to order an already authorized, bounded candidate set, but must not grant trust, fetch arbitrary certificates or skip chain checks because of the hint. A changed well-formed hint still verifies with the same key. Rejecting a fingerprint mismatch as proof of a bad signature would incorrectly authenticate metadata that PAE excludes.

Exactly one signature is verified against exactly one supplied key. Custodian thresholds, including the declared one-custodian setup, are outside this API: their types and authority rules are unspecified. A quorum consumer must never call this verifier repeatedly and count envelopes or hints as distinct custodians. It needs a separate reviewed contract that counts distinct trusted keys over identical payload bytes. Accept-any-of-many would silently weaken the two-of-three recovery rule and is rejected.

## 6. Exact envelope hashes and dispatch grants

Hash the exact received envelope bytes, including whitespace, field order, JSON escape spelling, hint and signature. Do not hash a parsed object or a re-encoded envelope. The signer emits canonical bytes for reproducibility; the verifier accepts section 4's alternate spellings. `Verified.EnvelopeSHA256` is `sha256.Sum256(envelope)` from the same call that verified its payload. No separate hash helper is needed: the signer uses `crypto/sha256.Sum256` on its output, and the verifier returns the checked input's digest.

The command issuer persists the bytes returned by `Sign`. `jobs` reloads and verifies those exact command bytes and their authorization, then puts their lowercase hexadecimal SHA-256 in `command_envelope_sha256` when signing the dispatch grant. Delivery must transport command bytes opaquely, not parse and marshal them. A future transport schema must preserve those bytes, for example as a base64 byte string; this slice does not choose the transport field.

The agent validates the policy certificate and grant, checks the expected grant type and payload schema, poll nonce, device, epoch and freshness, then verifies the received command with `TypeCommand`. It compares `Verified.EnvelopeSHA256` to the authenticated grant digest before accepting the command into its durable replay journal. Identity, sequence and approval bindings still follow [policy-envelope sections 6 and 7](policy-envelope.md#7-signatures). The application consumes only `Verified.Payload`.

| Hashing choice | Attack prevented and trade-off |
|---|---|
| Exact received bytes, selected | A delivery role cannot substitute a re-encoded command, altered hint or other signature representation under a grant for different bytes. Formatting changes cause a hash mismatch even when the signature remains valid. The delivery role can still drop data or cause denial of service. |
| Canonical signer output alone, rejected as the hash rule | Deterministic output prevents issuer retries from drifting in format. It does not stop a receiver from hashing a normalized reconstruction while executing a different received representation. It is useful output discipline but insufficient byte binding. |
| Reject every non-canonical envelope, rejected | Comparing received bytes with a canonical re-encoding prevents alternate JSON spellings from passing at all. It imposes an extra wire restriction with no added dispatch binding over exact-byte hashes. |

The command and grant are separate signed objects, so no object hashes itself. Changing `keyid` does not break the command signature but does break an existing grant's envelope hash. Hash equality alone never proves a signature, freshness, device binding or authorization. Consumers must not deduplicate commands by PAE or a normalized-envelope hash.

## 7. Error precedence

`Verify` completes checks in this order, regardless of field order. A failure stops before later stages. Within a stage all defects share its sentinel except where the sub-order is explicit:

1. Received size greater than the cap: `ErrEnvelopeTooLarge`.
2. JSON syntax, UTF-8 and surrogate validity, one-object framing, exact field sets, duplicates and value types, including every signature element's shape: `ErrEnvelope`.
3. Signature count unequal to one: `ErrSignatureCount`.
4. Unsupported caller expected type or received type, including empty: `ErrPayloadType`.
5. Supported but unequal types: `ErrTypeMismatch`.
6. Hint format: `ErrKeyID`.
7. Encoded payload length greater than 22,369,624: `ErrPayloadTooLarge`, even if base64 is invalid.
8. Payload base64 decoding and canonicality: `ErrBase64`; then decoded length above the cap: `ErrPayloadTooLarge`.
9. Signature base64 decoding and canonicality: `ErrBase64`; then decoded length unequal to 64: `ErrSignature`.
10. Public key length unequal to 32: `ErrPublicKey`.
11. Ed25519 verification failure: `ErrSignature`.

`Sign` checks supported type (`ErrPayloadType`), payload size (`ErrPayloadTooLarge`), then private-key length and seed/suffix consistency (`ErrPrivateKey`). No signature is computed before these pass. All valid signing inputs fit the envelope cap by construction. The fixed-size fingerprint cannot fail shape validation.

Examples: an unknown root field plus two signatures returns `ErrEnvelope`; zero signatures plus an empty type returns `ErrSignatureCount`; a type mismatch plus a bad signature returns `ErrTypeMismatch`; a bad hint plus malformed base64 returns `ErrKeyID`; a short signature plus a short public key returns `ErrSignature`; a length-valid bad signature plus a short public key returns `ErrPublicKey`. Test both root and signature member orders. Reporting the first JSON field encountered would make diagnostics depend on unauthenticated order and is rejected.

## 8. Responsibilities and attacker paths

| Check outside this package | Owner and acceptance boundary |
|---|---|
| Certificate chain, organization, signer subject, key usage and extended key usage | `pki` and agent trust code, [PKI section 4](../design/pki.md#4-policy-signing-certificate), before supplying an authorized policy key. A device certificate under the same root is insufficient. |
| CRL freshness, revocation and CRL counter | Same PKI boundary. [Offline release objects](policy-envelope.md#7-signatures) retain their explicit cached-CRL exception; this primitive has no time policy. |
| Epochs, counters, replay, approvals and sealed restore | Policy/command consumers, agent durable state and the backend independent authority journal under BE-12. No returned signature result advances authority. |
| JSON/YAML payload schema, archive hashes, device and scope bindings | Policy and extensions admission and agent artifact consumers. Verify exact bytes before parsing the payload once. |
| Publisher trust and prefix grants; project release trust | `extensions` trust list under EXT-02 and the updater's release-key contract. No key inferred from a hint becomes trusted. |
| Key storage, certificate/private-key binding, rotation and custody | Role signing services and PKI under [architecture section 4](../architecture.md#4-keys-and-what-they-sign) and [backend section 6](../design/backend.md). No keys are loaded or persisted here. |

Each attack starts outside the primitive and reaches a specific acceptance boundary:

| Attacker | Path, boundary and remaining power |
|---|---|
| Stolen enrollment token | Token reaches PKI enrollment and its approval/consumption checks. Even an issued device identity cannot satisfy the policy-signing profile. DSSE cannot turn that identity into a policy key; the token's enrollment powers remain a PKI concern. |
| Compromised agent host | Attacker controls local state and may bypass its own verifier or steal its device key. Other hosts still require an authorized policy key, expected type and their own bindings. This package cannot make a compromised host enforce policy. |
| Compromised console session | Session reaches RBAC and protected-action approval before a signing service. DSSE prevents post-signing alteration but faithfully signs work that authorization wrongly permits. It cannot supply a second approver. |
| Rogue extension publisher | Publisher can sign arbitrary bytes with its own key. `extensions` must validate trust, id prefix, grants, schema and content before compilation; PAE type binding prevents using a manifest as an index. Agents accept only organization-signed bundles and assignments. |
| Network position between agent and server | Attacker can replay, reformat, delay or drop stored envelopes. Signature checks reject changed type or payload; exact-byte grant hashes reject substituted representation. Poll freshness, device binding and durable replay checks reject stale commands; DSSE alone accepts a valid replay. |
| Database writer without signing keys | Attacker can replace rows, hints or blobs and replay valid signed bytes. Signature and archive checks reject invented content; grant binding rejects byte substitution. Current authorization and journal floors must reject revived grants, counters and revoked artifacts. |
| Server restored from backup | Restored valid signatures still verify cryptographically. BE-12 keeps serving and signing sealed until journal reconciliation and a valid custodian transition establish the epoch. This package neither authorizes that transition nor revives stale keys. |

The benefits are one parser, one error contract and shared byte fixtures for multiple consumers. The costs are strict Ricevanta interoperability rules, bounded buffering, and a separate future quorum API. Dependencies are the reviewed payload names, caller trust contracts and the standard library. No claim of complete policy, extension, recovery or platform support follows from these tests.

## 9. Machine-readable vectors and regeneration

[`schemas/dsse/v1/`](../../schemas/dsse/v1/) is shared protocol data, not Go `testdata`, so Rust can consume the same files without importing server code. `v1` versions the Ricevanta profile and fixture contract, not a new DSSE algorithm. `vectors.schema.json` validates the corpus format; `envelope.schema.json` validates decoded envelope structure. Neither schema detects duplicate raw keys, invalid raw UTF-8, nonzero pad bits, every decoded size bound or cryptographic failure. Raw-byte validation and the verification stages remain mandatory. Schema patterns use an absolute end assertion `(?![\s\S])`; `$` alone can match before a final newline in some validators.

`vectors.json` contains public RFC test keys, 20 positives, 65 verification negatives and four signing negatives. `seed_hex` is the published RFC seed, never a production secret. All `*_hex` byte strings use lowercase hex. Positive rows carry exact PAE, signature, canonical signer output, received envelope bytes and received-envelope digest. `key` references a key row; `payload_type` is also the expected verification type. `style` selects canonical, whitespace, reordered or escaped input; each row still provides its exact received bytes.

Negative rows name a stable sentinel and supply the caller's expected type and public key. `envelope_hex` holds malformed bytes without JSON-decoder repair. Large inputs use `envelope_recipe`: concatenate decoded `prefix_hex`, `repeat_hex` repeated `repeat_count` times, and decoded `suffix_hex`. Signing negatives use `payload_hex` or the identical `payload_recipe` rule, with the supplied full Go private-key bytes and the synthetic fingerprint below. No recipe reads a file or executes code.

Regenerate outside the repository:

1. Create `/tmp/dsse_generate.py` using Python `cryptography` 50. Take seeds and public keys from [RFC 8032 section 7.1, tests 1 and 2](https://www.rfc-editor.org/rfc/rfc8032.txt). Derive and compare both public keys before use. Build PAE by byte-length concatenation, sign with `Ed25519PrivateKey.sign`, and encode fields with Python standard padded base64 and compact JSON in section 5's order.
2. Rebuild each positive from its type, payload, key reference and hint. The default synthetic hint is bytes `00` through `1f`; `changed-hint-still-verifies` uses 32 `ff` bytes. These are shape fixtures, not certificate fingerprints or trusted certificate examples. Preserve the exact receive-style transformations and named negative mutations in the corpus; recompute all derived fields rather than copying signatures or PAE.
3. Write candidates only under `/tmp/dsse-candidate`. Before copying any positive into `schemas/`, run a separate `/tmp/dsse_check.go` with Go 1.27.1 `crypto/ed25519`: independently reconstruct PAE, derive public keys, sign and verify, construct canonical JSON, decode received variants and recompute SHA-256. Require equality of every byte field. This uses a different cryptographic implementation from Python.
4. Validate both schemas with `jsonschema.Draft202012Validator.check_schema`, validate the corpus, and validate every positive decoded envelope. Run a temporary raw-byte reference validator through every negative and require its named sentinel, including recipe expansion and signing-input checks. Payload fixtures are opaque bytes, not examples of complete domain schemas.
5. Run the generator into a fresh `/tmp/dsse-regenerated`, compare each artifact byte-for-byte, and run the independent Go checker again against the repository corpus. Only publish identical, fully checked results. Scripts stay in `/tmp`; the stable regeneration inputs, byte rules and expected outputs live in this spec and corpus.

## 10. Required tests and review focus

The implementation tests consume every machine vector without regeneration. Add table tests for every API constant and sentinel, zero results on error, output ownership, wrong-key lengths and inconsistent private-key suffixes. Prove that repeated signing is deterministic, changed hints still verify, and equal PAE with differently formatted envelopes yields different received hashes.

Construct boundary tests in memory: payload lengths 0, 1, 2, 3, cap minus one, cap and cap plus one; accepted whitespace-padded envelopes at envelope cap minus one and cap, rejected at cap plus one; signature counts 0, 1 and 2; decoded signature lengths 0, 63, 64 and 65. Cover all four base64 length residues, URL-safe-only characters, CR/LF, nonzero pad bits and extra padding. Generate pairwise combined defects across section 7's stages, and prove reordered fields do not change the sentinel. Test escaped duplicate keys, nested unexpected values, valid surrogate pairs and unpaired surrogates. A payload containing invalid UTF-8 remains valid opaque signed bytes. Reject signatures over payload alone, a PAE digest or leading-zero PAE lengths, non-canonical Ed25519 scalars, and a changed supported type even when the caller expects that changed type.

`FuzzVerify` supplies arbitrary envelope bytes, expected-type strings and public-key bytes. It asserts no panic and a zero result on error. On success it checks the received hash, closed expected type, independent Ed25519 verification of the returned payload and isolation from subsequent input mutation. Seed it from all small corpus inputs, including alternate JSON spellings. Keep resource-limit recipes in unit tests instead of inflating the fuzz corpus.

Review focus:

- A type mismatch fails before Ed25519, and the expected type comes from caller intent.
- Duplicate, unknown and case-aliased keys cannot exploit Go JSON defaults.
- Strict base64 plus re-encoding rejects ignored newlines and nonzero pad bits.
- No consumer confuses the hint or a returned signature result with certificate trust.
- Dispatch grants bind the same received bytes whose payload is returned, including altered hints.
- Signature count cannot implement or weaken custodian thresholds.
- Size checks precede large decoding allocations, and all combined defects follow section 7.
- Go and Python independently match the vector bytes; Rust compatibility remains a test obligation for its implementation.
