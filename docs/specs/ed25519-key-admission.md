# Ed25519 key admission

Ricevanta admits only canonical encodings of nonidentity points in the prime-order Ed25519 subgroup. One shared Go validator supplies that rule to every key admission boundary and to `dsse.Verify`. This is the key-validity detail of SH-05, not a trust or signature-format change. [The plan](../plans/ed25519-key-admission.md) requires independent approval before implementation.

## 1. Scope and implementation choice

Create `server/internal/signing/ed25519key` in module `github.com/ricevanta/ricevanta/server`. Use Go 1.27.1 and only its standard library. The package imports no Ricevanta package. `dsse` imports it; admission owners import it directly without importing a DSSE envelope parser.

Use `math/big` to decode a public point and check its subgroup. Reject mixed-order keys, which have a nonzero prime-order component and a nonzero torsion component. Ordinary generated keys meet the stricter rule. A validator that rejects only the eight small-order points leaves mixed-order acceptance to verifier-specific behavior. One accepted point encoding and one subgroup give later Go and Rust admission the same contract.

The package has no key generation, signing, signature verification, certificate parsing, storage, network, clock or authorization API. `crypto/ed25519` retains signature verification. [Its public API](https://pkg.go.dev/crypto/ed25519) has no Edwards point decoder or subgroup predicate; do not import Go's internal crypto packages or use `go:linkname`.

This design has no new module dependency or licensing row. The installed toolchains are Go 1.27.1, Rust 1.99.0 with cargo 1.99.0, Node 24.21.0 and pnpm 11.18.0. Only Go executes product code in this slice. The test corpus uses JSON Schema 2020-12. Validation uses Python `jsonschema` 4.25.1 and `cryptography` 50.0.0, with no product dependency on either.

## 2. Exact Go API and errors

```go
package ed25519key

func Validate(publicKey []byte) error

var (
    ErrLength       = errors.New("ed25519 public key length")
    ErrNonCanonical = errors.New("ed25519 public key encoding is not canonical")
    ErrPoint        = errors.New("ed25519 public key does not encode a point")
    ErrSmallOrder   = errors.New("ed25519 public key has small order")
    ErrMixedOrder   = errors.New("ed25519 public key has mixed order")
)
```

These are the only exports. A `crypto/ed25519.PublicKey` passes directly as `[]byte`. `Validate` returns nil on success; every error matches exactly one sentinel through `errors.Is`. Optional wrapping adds static context only, never input bytes. Error strings are not the caller contract. Do not join error classes.

The function never panics for any byte slice, never mutates or retains input, and has no shared mutable state. Nil equals an empty key. Callers must not mutate input during validation. After a length check, copy into a local `[32]byte` before clearing the sign bit. Do not expose a validated-key wrapper: a copied raw key still needs authority checks, and the verification boundary must remain safe when called directly.

## 3. Accepted points and error precedence

Let `p = 2^255 - 19`, `L = 2^252 + 27742317777372353535851937790883648493`, `d = -121665/121666 mod p`, and `O = (0,1)`. `[n]A` means point A added to itself n times. The sign bit is bit 255; the remaining 255 bits encode y in little-endian order. The group has order `8L`.

Validation stops at the first failing step:

| Step | Check | Result on failure |
|---|---|---|
| 1 | Byte length equals 32 | `ErrLength` |
| 2 | Extract sign and y without reducing y; require `y < p` | `ErrNonCanonical` |
| 3 | Recover x from `x^2 = (y^2-1)/(d*y^2+1) mod p`; require an inverse and a square root | `ErrPoint` |
| 4 | If x is zero, require sign zero; otherwise choose the root whose parity equals sign | `ErrNonCanonical` for signed zero |
| 5 | Require `[8]A != O` | `ErrSmallOrder` |
| 6 | Require `[L]A == O` | `ErrMixedOrder` |

[RFC 8032 section 5.1.3](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.3) defines canonical decoding, including y bounds and signed-zero rejection. Steps 5 and 6 are Ricevanta admission rules. [Section 5.1.7](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.7) describes signature verification and permits a cofactorless equation; successful verification alone is not this admission predicate.

For implementation, use `big.Int.ModInverse` and `big.Int.ModSqrt`, test nil before use, and verify the recovered square. Perform point multiplication with extended coordinates and the complete addition formula in [RFC 8032 section 5.1.4](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.4). Doubling may use the same addition routine with identical operands. Reduce each field result modulo p. Test projective identity as `Z != 0 && X == 0 && Y == Z` modulo p, not by comparing a single coordinate. Never reduce L modulo L before multiplication; `[0]A` would accept every mixed-order point.

Use three doublings for `[8]A` and fixed scalar multiplication by the 253-bit integer L. Only public values enter `math/big`; its variable-time behavior is acceptable here, never for secrets. Keep big integers local to each call or copy constants before any operation that can mutate a receiver. [The math/big contract](https://pkg.go.dev/math/big) documents receiver mutation, inverse and square-root failure. Check all exceptional arithmetic paths and fail closed with `ErrPoint`; valid decoded curve points cannot produce those failures under the complete formula.

All 32-byte strings have `y <= p+18`; reject the entire interval `p..p+18` with both sign bits. Never reduce, clear a signed-zero bit, multiply by the cofactor and accept the result, or otherwise repair input. The eight small-order points have orders 1, 2, 4 or 8. Every encoding of them fails: canonical encodings at step 5, y aliases at step 2, signed-zero encodings at step 4. Identity is explicitly rejected even though `[L]O == O`. A pure torsion point gets `ErrSmallOrder` before it can get `ErrMixedOrder`.

Combined defects have fixed results: a 33-byte noncanonical prefix gives `ErrLength`; noncanonical y that would reduce to an off-curve value gives `ErrNonCanonical`; signed-zero identity gives `ErrNonCanonical`; canonical identity gives `ErrSmallOrder`; a canonical mixed-order point gives `ErrMixedOrder`. These rules concern A, the public key. Do not apply this validator to a signature's R half or to X25519 keys.

## 4. DSSE integration

`dsse.Verify` must call `ed25519key.Validate` after envelope parsing, at the existing public-key stage, and before `crypto/ed25519.Verify`. Admission-only validation is rejected: database loads, backup restores and direct primitive callers can bypass an import endpoint. Revalidation prevents an invalid admitted key from making attacker-chosen bytes appear signed.

Keep the public `dsse.Verify` signature unchanged. All validator failures map to the existing `dsse.ErrPublicKey`, whose message becomes `dsse invalid public key`. Return `Verified{}` and exactly that DSSE sentinel. Do not wrap the validator cause into the DSSE error, preserving the DSSE contract of exactly one matching sentinel. Direct admission callers use the finer validator sentinels.

All earlier [DSSE error stages](dsse-envelope.md#7-error-precedence) keep their precedence. A malformed envelope, unsupported expected type, bad base64 or short signature wins over every bad public key. A correctly sized but invalid signature loses to any bad public key. A valid key with a bad signature gives `dsse.ErrSignature`. Check combined defects with both JSON member orders. No payload, hash or hint escapes on any failure.

`dsse.Sign` retains its seed/public-suffix consistency check; the standard key derivation yields a canonical subgroup key. This slice does not add private-key parsing or a signing dependency on the new validator. Generated public keys still undergo validation when admitted. Fingerprints remain hashes of exact admitted bytes under their owning contract; the validator neither computes nor authenticates a fingerprint.

The concrete forgery regression uses A encoded as `01` followed by 31 zero bytes and signature `R || S`, where R is that same encoding and S is 32 zero bytes. Since A and R are identity, the verification equation holds for every message. A temporary Go 1.27.1 probe confirms acceptance by `crypto/ed25519.Verify` for three distinct messages. DSSE tests must reject that signature with `ErrPublicKey` for two distinct well-formed envelopes, including different supported payload types.

## 5. Admission owners and integration gates

The current Go tree contains DSSE and a decoded extension manifest validator. It has no publisher trust-list service, certificate-profile implementation, custodian-manifest verifier or production DSSE consumer. Only DSSE changes in this implementation slice. `manifest.Validate` sees a fingerprint string, not a raw key, and must not invent or resolve a key to call this API.

Every future boundary validates the raw Ed25519 key before admitting authority and again when loading key material from untrusted persistence. Validate the exact owned copy subsequently stored or used; avoid checking one slice and using another. A valid key proves neither possession of its private key nor entitlement to any role.

| Owner | Required call and ordering |
|---|---|
| Publisher trust list in `extensions` | Call `Validate` on import, rotation, compiled default-key loading and every storage/cache reload, before fingerprint indexing, approval publication or persistence. Refuse the invalid entry, including an invalid first-party key. Keep prefix, revocation, protected-action and journal checks. |
| Extension loader being designed as `docs/specs/extension-loader.md` on the parallel branch | Its caller validates every supplied candidate key when building the bounded authorized candidate set. The loader calls `dsse.Verify` with the caller-selected type, then compares exact manifest bytes before YAML parsing. If the loader itself accepts raw candidates, it calls `Validate` at that input boundary too. Invalid candidates fail the operation, never become successful verification or fallback trust. This file is absent in this worktree; reconcile this interface at integration without editing that branch here. |
| PKI certificate profiles and trust consumers | For each Ed25519 subject key, call `Validate` after extracting raw SubjectPublicKeyInfo bytes and before accepting a CSR's proof of possession or issuing a certificate. Repeat for imported certificates and every Ed25519 issuer, trust anchor and leaf used by a chain or signing profile before relying on its signature. A parsed X.509 object is not proof of key admission. Non-Ed25519 profile algorithms use their own rules. |
| Custodian manifests and recovery | Validate every Ed25519 custodian and manifest-verifying key before accepting a pinned manifest, installing an update or counting any recovery signature. Reject the entire manifest if any key fails. Count distinct canonical raw keys, not hints, certificate wrappers or signatures; reject duplicate custodian keys. Root signature, installation binding, threshold and journal checks still apply. |
| Other signing key owners and Rust trust code | Validate role keys, journal/audit keys, device signing keys and compiled release/updater keys when loaded or pinned, and before direct non-DSSE verification. Rust must implement the same predicate and execute this corpus before its verifier ships. Do not assume a library's method named `strict` enforces it. |

Invalid persisted keys cannot receive a grandfather exception or automatic normalization. Refuse their use, report a stable key reference and reason without raw key bytes, and require the owner's authorized replacement flow. Restore validates its complete required key inventory before leaving sealed state. An invalid custodian key must not reduce the configured threshold or unlock a bypass. A valid key from an obsolete backup still needs live-journal reconciliation; this predicate supplies no freshness evidence.

Certificate profiles, custody formats, journal protocol, loader bounds and authorization remain gates in their own slices. This primitive is not a reason to implement a consumer whose other security contract is open. No supported OS loses its v1.0.0 obligations.

## 6. Shared corpus and independent computation

The machine contract is [key-admission-vectors.schema.json](../../schemas/dsse/v1/key-admission-vectors.schema.json); the fixture is [key-admission-vectors.json](../../schemas/dsse/v1/key-admission-vectors.json). Its format string is `ricevanta-ed25519-key-admission-v1`. Every record has a unique name, a recipe, exact lowercase public-key hex and an expected outcome. `accept` means nil; other outcomes name the validator sentinel. Schema validation checks structure, not curve arithmetic. Tests must execute every record and check recipe reconstruction, unique names and exact sentinel matching separately.

Recipes use the same p and L as section 3. Let B be the point with `y=4/5 mod p` and even x. Let `T=[L]decode(y=3, sign=0)`. T has order 8. Decimal scalar and y fields are strings to preserve integers beyond JSON's common 53-bit numeric range. Seeds are public test inputs, never production secrets.

| Recipe kind | Reconstruct raw bytes |
|---|---|
| `length` | `length` zero bytes |
| `y-sign` | 32-byte little-endian encoding of `y + sign*2^255`, without reduction |
| `torsion` | Canonical encoding of `[multiple]T` |
| `base` | Canonical encoding of `[scalar]B` |
| `mixed` | Canonical encoding of `[scalar]B + [multiple]T` |
| `seed` | Standard Ed25519 key generation from the 32-byte `seed_hex` |

The 80 records cover five wrong lengths (0, 1, 31, 33, 64); eight canonical torsion points; both signed-zero encodings at y=1 and y=p-1; all 38 noncanonical y/sign combinations; six off-curve encodings at y=2, 7 and 8; seven accepted keys (B, 2B, -B and four seeded keys); and fourteen mixed-order points (B and 2B plus every nonidentity multiple of T). This exhausts all fourteen byte encodings that permissive y reduction and signed-zero handling can map to the eight torsion points. Both sign values appear among valid keys.

Two temporary scripts independently reconstruct every record and outcome. The first uses affine addition, Fermat inversion, the p=5 mod 8 square-root formula and right-to-left multiplication. The second uses extended coordinates, Euclidean inversion, generic Tonelli-Shanks square roots and a left-to-right ladder. Neither imports the other's arithmetic. The second also checks all four seeded keys with `cryptography` 50.0.0, the two existing DSSE fixture keys, and all fourteen torsion encodings. Library key construction alone is not a point-validity oracle.

The authors' [Taming the many EdDSAs paper](https://eprint.iacr.org/2020/1244), [ed25519-speccheck condition table](https://github.com/novifinancial/ed25519-speccheck) and [cases.json](https://raw.githubusercontent.com/novifinancial/ed25519-speccheck/main/cases.json) are fetched references. Their cases distinguish small-order A, mixed-order A and noncanonical A from signature R/S defects. This corpus derives its bytes from the stated recipes; it does not vendor their code or signature corpus. Signature R/S interoperability is outside key admission. Verify: the later Rust verifier's complete signature acceptance must be qualified separately; shared key admission alone cannot establish it.

## 7. Security paths and limits

| Attacker | End-to-end path and effect of this slice | Remaining power |
|---|---|---|
| Rogue extension publisher | Submits an identity, alternate encoding or mixed-order key for trust import, then supplies chosen manifests. Import rejects the key before authority publication; loader revalidation and DSSE reject it even if import was bypassed. | Can sign arbitrary content with an admitted key they own. Prefix, grants, content checks and sandboxing still constrain that publisher. |
| Database writer without signing keys | Replaces a stored publisher, certificate or custodian key with a weak point, then supplies a forged artifact. Reload validation rejects the key; DSSE independently blocks identity forgery. | Can delete data, cause denial of service, replay valid artifacts or insert an ordinary key they control. Committed authority, chain validation and the independent journal must reject unauthorized valid-key substitution. |
| Server restored from backup | Restores weak keys or a cached validation flag and attempts verification or recovery. Reload ignores the flag, validates raw keys, and leaves restore sealed if a required key fails. | Can present valid but revoked or stale keys. Live-journal reconciliation, epochs and the existing custody ceremony remain required; admission does not prove current authority. |

Enrollment-token theft, a compromised host or console session, and a network position obtain no new powers or guarantees from this key predicate; their authorization and transport boundaries stay with [the DSSE responsibility table](dsse-envelope.md#8-responsibilities-and-attacker-paths). This slice does not repair compromise of an authorized signing key or a verifier process.

Work is bounded after rejecting non-32-byte input: one fixed-size decode, three doublings and a fixed 253-bit multiplication. `math/big` adds CPU and allocation costs to each verification. There is no performance target proven by this design. Admission owners must bound candidate counts and concurrent requests; do not add an unbounded global cache or skip validation based on a stored boolean. Measure cost with a benchmark before consumer integration.

Benefits are one auditable predicate, no dependency and explicit Go/Rust acceptance. Costs are public-point arithmetic to review and repeated subgroup checks. A blocklist plus length checks cannot reject off-curve or mixed-order keys. A canonical decoder plus only `[8]A != O` still accepts mixed order. Placing the check inside DSSE couples certificate and custody admission to an envelope package. All three alternatives are rejected.

`filippo.io/edwards25519` is the dependency alternative. Its [point API](https://pkg.go.dev/filippo.io/edwards25519#Point.SetBytes) would still need canonical-encoding and subgroup policy checks. Reject it for this slice to preserve the standard-library constraint. Adopting it requires an exact version, a `docs/licensing.md` row and independent review; the implementer must not make that substitution silently.

## 8. Required tests and review focus

In addition to every corpus row, test nil input, slices of length 30, 32 and 34, a long slice rejected before decoding, p-1/p/p+1/p+18 with both signs, and all local arithmetic exceptional branches that are reachable. Check input immutability on success and failure, serial determinism and concurrent calls with independent input copies. Accept keys generated from fixed test seeds; generated-key acceptance does not replace negative vectors.

`FuzzValidate` accepts arbitrary byte slices. Seed every corpus row. Assert no panic, unchanged input, deterministic outcome, nil only for length 32, and exactly one sentinel for errors. For success, an independent test-only affine oracle checks canonical re-encoding, nonidentity, `[8]A != O` and `[L]A == O`. Run that bounded oracle only after success. Do not call production point helpers from the oracle. Extend DSSE `FuzzVerify` with rejected-key seeds and assert that success implies `Validate(key)==nil`.

Review focus:

- Identity must fail even though it satisfies `[L]A == O`; test the message-independent forgery through DSSE.
- Exhaust all noncanonical y/sign combinations and both negative-zero cases without repairing bytes.
- Mixed-order rejection must multiply by integer L, never a scalar API that reduces L to zero.
- `big.Int` receiver aliasing and shared constants must not corrupt other calls or permit an arithmetic exception to pass.
- DSSE parsing errors keep precedence over key errors; every key error hides all verified output and maps to one DSSE sentinel.
- Persistent keys, compiled keys and restore paths cannot rely on an import-only check or a cached validation bit.
- The Rust predicate must run the exact corpus; a library's signature policy is not an admission contract.

## 9. Unresolved questions

These questions concern consumer qualification, not alternatives left to the implementer:

- Does review approve rejecting mixed-order keys as part of nonidentity prime-subgroup admission, instead of filtering only small-order keys? This design rejects both.
- Does the independent review accept standard-library public-point arithmetic and its measured cost, or require a separately reviewed dependency proposal? This design selects `math/big`; a blocklist is insufficient.
- Does the parallel extension-loader contract pass raw keys or an immutable authorized candidate set, and where does its input-boundary validation occur? This design requires direct validation of any raw candidates plus DSSE revalidation.
- Which Rust implementation meets the predicate and the separate signature contract on macOS ARM64, Windows x64 and Linux x64? Verify before that verifier ships; accepting mixed order to fit a library is not an option.
