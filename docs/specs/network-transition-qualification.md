# Network transition qualification

This specification defines the executable candidate contract for certificate renewal, RADIUS accounting, session control and RADIUS custody recovery. It refines the blockers in `../analysis.md` section 3 without claiming gateway support. A gateway variant remains `candidate` until every required row below passes on the exact model, firmware, client and architecture named in its qualification manifest.

The PKI and RADIUS designs remain authoritative for trust and policy. This file defines records, state transitions and evidence needed to implement and test those decisions.

## 1. Evidence status

Every profile fact has one status:

| Status | Meaning | Permitted use |
|---|---|---|
| `standard` | A cited standard defines the wire behavior | Parser and protocol invariant |
| `vendor_documented` | First-party vendor documentation defines the behavior for the named variant | Candidate configuration and test expectation |
| `observed` | A repeatable test passed on the manifest's exact unit | Capability input for that unit only |
| `assumed` | No qualifying source or test proves the behavior | Display and test planning only |

`standard` and `vendor_documented` do not prove that a gateway implements the behavior correctly. Only retained `observed` evidence enables a capability. Evidence records contain the unit manifest digest, configuration digest, test identifier, packet-capture digest, gateway-state capture digest, result and tool versions. A firmware, model, client, architecture or relevant configuration change invalidates the observation.

## 2. Certificate profiles and renewal overlap

Every issued leaf uses X.509 version 3 and a positive unpredictable serial of at most 20 octets that is unique for the issuing CA. Authority key identifier and subject key identifier are separate required extensions. Every leaf also has `basicConstraints CA=false`, critical `keyUsage`, an exact extended key usage allow list without `anyExtendedKeyUsage`, and subject and SAN values that `jobs` derives from protected profile, identity and registration rows. The issuer rejects unknown critical extensions, CA signing uses, empty SAN entries, wildcard identity names and a validity interval outside the stored profile. The CSR proves only the requested key. It never selects names, uses, lifetime or profile.

| Profile | Settled constraints | Constraints that block implementation |
|---|---|---|
| `network_access` | ECDSA P-256, 30 days, `digitalSignature`, `clientAuth`; CN, UPN `otherName` and DNS SAN derived from `netid` | Exact UPN ASN.1 encoding, subject encoding, clock skew, AIA and CRL distribution points, policy OID and compatibility fixtures for every client |
| `policy_signing` | Ed25519, 90 days, `digitalSignature`, private policy-signing extended key usage, fixed subject | Extension criticality, policy OID, clock skew and chain fixtures |
| `service` | 90 days; connector server name from registration; `jobs` has the reserved subject | Algorithm, key size, SAN form, clock skew, AIA and CRL distribution points; splitting `serverAuth` and `clientAuth` into separate profiles is a proposal |
| `agent_identity` | Current-key proof for renewal and a 30-day expired-certificate grace path | Algorithm set, lifetime, subject and SAN, uses, hardware-key compatibility, clock skew and revocation endpoints |
| `network_gateway` | `clientAuth`; subject derived from the gateway registration | Algorithm set, lifetime, SAN binding, key custody, clock skew and revocation endpoints |
| EAP and RadSec server | Server issuing CA and configured DNS name | Separate profile identifiers, algorithm set, lifetime, `serverAuth`, SAN encoding, clock skew and client compatibility |
| OCSP responder | No settled profile | A dedicated responder certificate with `id-kp-OCSPSigning` is a proposal; algorithm, lifetime, `id-pkix-ocsp-nocheck` policy, rollover and failure fixtures remain open |

Profile schemas must encode every row as a closed set. Issuance and relying-party validation use the same compiled profile fixture. RFC 5280 requires a CA to verify every SAN and restricts a key to the intersection of key usage and extended key usage. The table's unsettled values require a PKI design update before certificate consumers are implemented.

A renewal issues a new certificate generation for the same active `netid`. The old and new generations may both be eligible until install acknowledgement or the 24-hour overlap limit. An exact EAP-TLS observation binds the session to one generation. A certificate-derived name observation binds only the identity and stores no serial, fingerprint, issuer or generation. Revocation of any possibly used generation therefore selects every possibly active identity-only session for Disconnect. Inventory state never upgrades identity-only evidence to exact evidence.

## 3. Accounting records and session generations

Keep an immutable `AccountingReceipt` for each authenticated packet. An unlinked receipt keeps its own uid and is never semantically deduplicated. After the receipt has a proved accept and boot-generation link, derive an `AccountingEvent`. Canonicalization excludes packet Identifier, Request Authenticator, Message-Authenticator, source port, arrival time and `Acct-Delay-Time`. It sorts distinct numeric attribute keys but preserves wire order among repeated instances of the same standard or vendor attribute. The semantic key is the SHA-256 of the gateway uid, proved boot generation, accept uid and canonical attribute sequence. It includes status, session identifiers, `Class`, event timestamp, session time, termination cause and normalized counters when present. Preserve every receipt and its changing delay and arrival values.

RFC 2866 requires a new Identifier and Request Authenticator when `Acct-Delay-Time` changes. RFC 5080 defines transport retransmission behavior for Accounting-Request as well as other RADIUS packets, but it does not define accounting semantic identity. Two linked, indistinguishable semantic events may collapse only when applying either again produces the same session state and counters. Normalize each octet counter as `(gigawords << 32) | octets`. A normalized decrease, a missing gigaword when wrap is possible or conflicting values for one semantic key makes the event ambiguous and raises accounting health.

An internal session uid is minted for each committed accept. `Class` proves the accept link only when the variant has observed echo evidence. The session generation key is `(gateway_uid, qualified_boot_generation, Acct-Session-Id, accept_uid)`. `Acct-Multi-Session-Id` is supporting evidence, not a substitute. A missing accept link or boot generation stays unlinked or ambiguous. A reused NAS identifier never selects the newest row by arrival time.

The pure transition function is:

```text
applyAccounting(profile, prior, event) -> {next, effect, diagnostic}
```

It reads no clock or database. The event supplies authenticated input, a bounded event-time interval and either its proved boot generation or its candidate generation set. The function never substitutes the gateway's current generation. It is idempotent for a linked semantic key, never lowers counters or watermarks, and applies this table:

| Prior | Event with proved same generation | Result |
|---|---|---|
| `awaiting_start` | Start | `active`; record establishment interval |
| `awaiting_start` | Interim | `active`; mark missing Start |
| `awaiting_start` | Stop | `terminated`; retain Stop tombstone |
| `active` or `stale` | Start | No lifecycle change; merge non-regressing evidence |
| `active` or `stale` | Interim | `active`; advance counters and event watermark |
| `active` or `stale` | Stop | `terminated` only for the proved linked generation; never close a newer generation |
| `terminated` | Any delayed event | Stay `terminated`; retain evidence |
| Any | ambiguous generation or time | `possibly_active`; emit reconciliation work |

Accounting freshness is orthogonal to lifecycle. Three missed qualified interim intervals set `stale`; they do not terminate a session. A separate pure `applyBootEvidence(profile, priorBoundary, event)` function advances the boot generation only when qualified evidence proves a newer boundary. Delayed or duplicate boundary evidence cannot advance it again. Advancing the boundary marks sessions from an earlier generation for reconciliation. It does not terminate them. A separate observed gateway fact may prove that this boot boundary terminated those exact sessions. Original expiry is immutable and derives from the accepted `Session-Timeout` plus the upper establishment-time bound. No CoA extends it.

## 4. Desired state, CoA and Disconnect

Each session has one desired row `(recovery_epoch, desired_version, authority_versions, outcome, canonical_attributes)`. Versions increase without reuse. Each attempt stores the gateway uid, custody and secret generation, destination address and port, desired version, dispatcher fence, exact selectors, packet bytes, source address and port, Identifier, Request Authenticator, first and final send times, exclusion deadline, send state and result. A retry reuses the same packet identity, source port and original Event-Timestamp. A takeover never retries an attempt until it excludes the prior sender.

The first implementation primitive is a pure validator:

```text
planTransition(profile, applied, desired, unresolved) ->
  Noop | CoA(operations, proof_requirements) | Disconnect(reason)
```

For every changed attribute or inseparable group, the profile table must name canonical multiplicity, add, replace and explicit clear encodings, combined-operation atomicity, allowed values, exact session selectors, actual-state observation and a stale-packet barrier. Absence from a CoA packet is not clear. An empty value is not clear without observed evidence. Any removal, unknown applied value, unsupported combination or missing proof returns `Disconnect`.

An unresolved older CoA blocks every later CoA and every grant. Standard RADIUS carries no Ricevanta desired version. The candidate stale-packet barrier follows RFC 5176 section 6.3: the profile records a qualified clock-error bound, acceptance window and duplicate window; requires Event-Timestamp; proves that the gateway rejects a missing timestamp and silently discards one outside the window; and proves that its duplicate window equals its timestamp window. The original timestamp stays unchanged across retries. The exclusion deadline is the original timestamp plus the acceptance window and qualified clock-error bound. The default 300-second window in RFC 5176 is test guidance, not an assumed gateway value. No later CoA or grant is sent before that deadline and actual-state inspection.

If the variant cannot prove every barrier property, Ricevanta assumes no packet lifetime. It uses Disconnect and blocks new grants until exact termination is proved. Where selectors can collide with a new session, the entire selector-collision domain stays blocked until reconciliation proves the old packet cannot affect a new grant. A local database fence, ACK or elapsed retry timer does not exclude a packet already in flight.

Disconnect is the fallback for reject outcomes, identity-only generation revocation, unsafe attribute transitions and unresolved CoA. A Disconnect-ACK proves termination only when observed inspection shows the exact selected session ended. Error-Cause 503 means the selected session context was absent when the gateway processed the request under RFC 5176. Ricevanta treats 503 as absence proof only when the selectors uniquely identify one qualified session generation and the gateway observation confirms no broader or different match. Other ACK, NAK, timeout and sender-loss results remain `control_unknown`. Until termination or qualified original expiry, the session stays possibly active and later grants remain blocked for the gateway unit where selector ambiguity can affect them.

## 5. Compromise recovery order

Recovery uses this order per custody generation:

1. Disable affected gateway registrations and stop traffic to affected replicas.
2. Revoke database, deployment, secret-store, KMS and TLS access; terminate existing database and control-plane sessions and watches.
3. Commit the obsolete custody-generation fence. Old principals and queued updates cannot enter the replacement generation.
4. Reserve the replacement custody generation and prove with non-secret canaries that retained old sessions, watches, KMS grants and principals cannot read or write its namespace. Do not create or publish replacement material before this negative proof passes.
5. Create a new role wrapping root, sealing key and TLS keys from an unaffected control plane. Provision only rebuilt or verified replacement principals.
6. Repeat the old-access negative proof with non-secret probes against the provisioned generation and before publishing the new sealing key or gateway material. On failure, destroy and regenerate every replacement value that may have been exposed, then repeat from step 4.
7. Generate new shared secrets and binding tokens. Never re-seal or overlap compromised values. Change one gateway through a trusted administration path, prove both ends use the new generation, then enable only that registration.
8. Repeat the negative proof after enablement. A failure disables the registration and regenerates every potentially exposed replacement.

Failure at any step leaves the affected registration disabled. Recovery does not use ordinary rotation overlap. The qualification record binds each cutover proof to the old and new custody generations and the gateway configuration digest.

## 6. Qualification matrix

Each required variant runs every applicable row with packet capture and actual gateway-state inspection. Documentation alone records an expectation, not a pass.

| Area | Positive test | Required negative or fault test | Capability enabled by a pass |
|---|---|---|---|
| Renewal overlap | Authenticate old and new generations during overlap | Revoke each generation; identity-only sessions all enter Disconnect | Exact or identity-only evidence as observed |
| Accounting link | Start, Interim and Stop echo `Class` and selectors | Lost Start, changed retry delay, reordered Stop, id reuse | Accept linkage and semantic deduplication |
| Boot generation | Reboot produces bounded, monotonic boundary evidence | Delayed On or Off and identifier reuse after reboot | Advance boot generation only |
| Reboot termination | Inspect pre-boundary sessions after a proved reboot | Gateway preserves a session or evidence is unavailable | Exact pre-boundary termination only |
| Original expiry | Session ends or reauthenticates by the proved bound | Lost accounting and attempted CoA extension | Residual-access bound |
| Disconnect | Exact selector ends only the target | Duplicate, lost reply, wrong selector and 503 | Termination or exact absence proof |
| CoA replace | Add and replace each allowed attribute | NAK, lost ACK and duplicate | Named transition only |
| CoA clear | Clear each attribute and combined group | Omit, empty value, partial clear and atomicity failure | Named clear transition only |
| CoA order | New state survives delayed older packet | Crash, takeover, reordered packets and late replies | Named stale-packet barrier only |
| Custody recovery | New generation serves after cutover | Old credentials, connections, watches, ciphertext and queued updates | Re-enable one registration |

FortiGate SSL VPN, FortiGate IPsec certificate-derived, FortiGate IPsec EAP-TLS, ASA, ASAv, hostapd, one managed switch and one access point are separate units. No row passes by inheritance from another unit. FortiSwitch documentation informs only a named FortiSwitch unit. Cisco IOS XE CoA documentation supplies test ideas only and does not document ASA or ASAv behavior.

## 7. Sources

- Standards: [RFC 2866](https://www.rfc-editor.org/rfc/rfc2866.html), [RFC 2869](https://www.rfc-editor.org/rfc/rfc2869.html), [RFC 5080](https://www.rfc-editor.org/rfc/rfc5080.html), [RFC 5176](https://www.rfc-editor.org/rfc/rfc5176.html), [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html).
- Fortinet: [FortiGate RADIUS attributes](https://docs.fortinet.com/document/fortigate/7.0.8/administration-guide/952303/radius-avps-and-vsas); FortiSwitch-only behavior: [FortiSwitch CoA](https://docs.fortinet.com/document/fortiswitch/7.4.0/fortiswitchos-administration-guide/110309/radius-change-of-authorization-coa), [FortiSwitch supported CoA attributes](https://docs.fortinet.com/document/fortiswitch/7.6.5/fortiswitchos-administration-guide/137894/appendix-b-supported-attributes-for-radius-coa-and-rsso).
- Cisco: [ASA RADIUS authorization attributes](https://www.cisco.com/c/en/us/td/docs/security/asa/asa922/configuration/general/asa-922-general-config/aaa-radius.pdf); IOS XE-only behavior: [Cisco IOS XE RADIUS CoA](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_aaa/configuration/xe-16/sec-usr-aaa-xe-16-book/sec-rad-coa.html).
