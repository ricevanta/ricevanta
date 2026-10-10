# RADIUS gateway profiles

The contract between the Ricevanta RADIUS service and each gateway family: the request shapes Ricevanta accepts, the attributes it returns for a `NetworkAccessProfile`, accounting and dynamic authorization behaviour, the gateway-side configuration, and what vendor documentation confirms. The flows, identity binding, transport and failure rules are in `../design/radius.md`. Decisions: RAD-01 to RAD-06 in `../decisions.md`. Claims resting on vendor community pages or untested behaviour are marked "verify"; each profile is qualified against real gateways (`platform-qualification.md`), and an unconfirmed behaviour becomes a documented limit or a release blocker there, never an assumption.

## 1. Profile model

Every `RadiusGateway` (a gateway registration, `../design/radius.md` section 5) names one gateway profile. A profile is data in the `radius` module: accepted request shapes, identity form, exact-certificate evidence capability, attribute mappings, accounting time and boot evidence, session selectors, qualified Disconnect behavior, per-attribute CoA transitions and ordering proof, and the enforced session-timeout bound. Dynamic authorization is qualified per gateway model, firmware and VPN or 802.1X variant; a family-wide CoA flag grants no transition capability.

| Profile | Gateways | Architectures (RAD-01) | Status |
|---|---|---|---|
| `fortigate` | FortiGate SSL VPN and IPsec IKEv2 dialup | Certificate-derived; EAP-TLS on IKEv2 | Required qualification unit; candidate until evidence passes |
| `cisco-asa` | Cisco Secure Firewall ASA and ASAv remote-access VPN | Certificate-derived | Required qualification unit; candidate until evidence passes |
| `ieee8021x` | 802.1X wired switches and Wi-Fi access points following RFC 3580 | EAP-TLS | Required qualification units; candidate until authenticator evidence passes |
| `generic` | Any RFC 2865 network access server | Either | Community status, not qualified; shown as such in the console |

The FortiGate and ASA certificate-derived shapes below are name-only: they provide `identity_only` evidence and no serial, fingerprint, issuer or validity of the authenticated certificate. EAP-TLS provides exact evidence at Ricevanta. Another profile may advertise exact certificate binding only after qualification proves the wire fields bind the authenticated certificate to this authorization request and the authenticated gateway; arbitrary vendor attributes or inventory lookup do not establish that proof. Compilation and admission enforce the evidence rule in `cel-profile.md` section 5.

Accounting qualification must define event-time error bounds, idempotent event keys, session-id reuse and boot-generation evidence. A missing interim does not prove disconnection, and Accounting-On or Accounting-Off alone does not prove that user sessions ended (`../design/radius.md` section 7). A timeout capability must prove the original enforced upper expiry bound, including establishment delay and CoA behavior; otherwise the required unit stays candidate.

## 2. NetworkAccessProfile

A `NetworkAccessProfile` is the vendor-neutral outcome a `network` policy's `accept` action names (`../design/radius.md` section 6). It is a GitOps resource under `apiVersion: ricevanta.io/v1alpha1`.

```yaml
apiVersion: ricevanta.io/v1alpha1
kind: NetworkAccessProfile
metadata:
  name: vpn-finance
spec:
  groups: [vpn-finance]        # gateway group or group policy name
  vlan: "120"                  # 802.1X only; VLAN ID 1 to 4094
  filter: acl-finance          # Filter-Id, a filter defined on the gateway
  sessionTimeout: 8h           # upper bound on a session; also the revocation bound without CoA
  idleTimeout: 30m
  vendor:                      # profile-specific attributes from the profile's allow list
    cisco-asa: { banner: "Finance VPN" }
```

Validation runs per profile at publish. A field a profile cannot express is a validation error for every policy that sends that profile to such a gateway, never a silent drop. `vendor` keys come from each profile's allow list of dictionary attributes. Profiles never set `Message-Authenticator`, `EAP-Message`, `State`, `Proxy-State`, `Class`, `User-Name`, `MS-MPPE-Send-Key` or `MS-MPPE-Recv-Key`; Ricevanta writes those itself. `sessionTimeout` defaults to 8 hours for VPN profiles and 1 hour for 802.1X, where it also drives reauthentication.

## 3. Attribute mapping

| Field or purpose | `fortigate` | `cisco-asa` | `ieee8021x` |
|---|---|---|---|
| `groups` | One `Fortinet-Group-Name` (vendor 12356, attribute 1) per group, matched by `config user group` `config match` `set group-name` | `Group-Policy` (vendor 3076, attribute 25) with the group policy name; one group only, more is a validation error | Not applicable; validation error |
| `vlan` | Not applicable | Not applicable | `Tunnel-Type` = VLAN (13), `Tunnel-Medium-Type` = 802 (6), `Tunnel-Private-Group-ID` = VLAN ID, tag 0 (RFC 3580 section 3.31) |
| `filter` | Not mapped (verify `Filter-Id` handling) | `Filter-Id` (11), an ACL name defined on the ASA | `Filter-Id` (11) (RFC 3580 section 3.9) |
| `sessionTimeout` | `Session-Timeout` (27) (verify that SSL VPN and IPsec dialup honour it) | `Session-Timeout` (27) | `Session-Timeout` (27) with `Termination-Action` = RADIUS-Request (1), so the port reauthenticates rather than disconnects (RFC 3580 sections 3.17 and 3.19) |
| `idleTimeout` | Not mapped | `Idle-Timeout` (28) | `Idle-Timeout` (28) |
| Decision uid | `Class` (25) = `rv1:<decision uid>`, echoed in accounting (verify the echo) | `Class` (25) = `rv1:<decision uid>`; group policy is never carried in `Class` | `Class` (25) = `rv1:<decision uid>` |
| Keying material | `MS-MPPE-Recv-Key` and `MS-MPPE-Send-Key` (vendor 311, attributes 17 and 16, RFC 2548) on IKEv2 EAP-TLS accepts | None | `MS-MPPE-Recv-Key` and `MS-MPPE-Send-Key` |
| Integrity | `Message-Authenticator` (80) as the first attribute of every response | Same | Same |

### 3.1 CoA transition contract

CoA changes attributes rather than replacing a named profile. [RFC 5176 section 3.6](https://datatracker.ietf.org/doc/html/rfc5176#section-3.6), note 3, leaves omitted ordinary authorization attributes unchanged; note 5 replaces a supplied tunnel set, and note 7 separates a vendor attribute's identification and authorization purposes. A CoA-ACK therefore cannot prove removal of an omitted filter or vendor group.

Each qualified variant records a finite transition table for every allowed attribute or inseparable attribute group: wire type and tag, identification or authorization purpose, canonical multiplicity, add and replace operation, explicit clear operation or `disconnect_required`, supported source and target values, atomicity, session selector, packet-order barrier or expiry-and-replay proof, and evidence for the actual resulting gateway state. No entry means Disconnect is required. An empty string is not a clearing operation unless its exact encoding and gateway semantics are qualified. The table includes `Filter-Id`, vendor group and policy attributes, VLAN tunnel sets, timeout fields and every allowed vendor field.

The dispatcher compares the last proved applied attribute set with the complete desired set, including removals when the profile name stays the same. Use CoA only when every changed attribute and the combined transition have a qualified operation. An unqualified removal, unknown applied set, atomicity failure or missing stale-packet exclusion requires Disconnect and fresh authentication under the current policy. Local desired versions do not appear on the standard RADIUS wire and cannot prevent a delayed older packet from restoring an older state (`../design/radius.md` section 8).

Qualification removes an ACL and vendor group, changes between profiles with different attribute sets, and inspects actual gateway state after ACK, NAK, lost ACK, duplicate and reordered packets. The exact profile, transition-table and evidence schemas are implementation blockers (`../analysis.md` section 3); no generic clearing or ordering behavior is assumed.

## 4. FortiGate

### 4.1 Variants

| Variant | FortiOS | Client | Architecture | Evidence |
|---|---|---|---|---|
| SSL VPN tunnel mode with RADIUS-integrated certificate authentication | 7.4.1 up to 7.6.2; tunnel mode is removed from the GUI and CLI in 7.6.3 on all models | FortiClient | Certificate-derived | Fortinet 7.4.1 new-feature page and 7.6.3 release notes |
| IPsec IKEv2 dialup, certificate peer with `mfa-mode subject-identity` and the Ricevanta server as `mfa-server` | 7.6.3 and later, where it replaces SSL VPN tunnel mode | FortiClient | Certificate-derived | `subject-identity` is documented for SSL VPN and, with LDAP, for dialup IPsec in a Fortinet community article; RADIUS on IPsec dialup is unconfirmed (verify) |
| IPsec IKEv2 dialup with EAP pass-through to RADIUS | 7.4 and later | Windows native IKEv2 client; macOS native IKEv2 and strongSwan on Linux (verify) | EAP-TLS | Fortinet "Windows IKEv2 native VPN with user certificate" |

FortiClient does not initiate EAP-TLS: for IKEv2 it uses EAP-MSCHAPv2 or, from FortiClient 7.4.3, EAP-TTLS (Fortinet community, verify). FortiClient users are therefore served by the certificate-derived variants. A FortiOS release whose SSL VPN tunnel mode is gone is qualified on the IPsec variants only.

### 4.2 Accepted request shape

- Certificate-derived: `Access-Request` with `User-Name` holding the network identity in the form `account-key-cert-field` selects (`othername`, the SAN User Principal Name, is the default and the profile default; `dnsname` is allowed), with `account-key-processing same`. The intended shape carries `User-Password` (PAP) equal to the gateway's binding token, configured on the FortiGate as the peer's `mfa-password`; section 4.5 lists as unconfirmed that FortiOS sends `mfa-password` in `User-Password` and what it sends when the value is empty (verify). The token is 32 random bytes generated by Ricevanta and shown once; two tokens are valid during rotation. A request whose password does not match is rejected with reason `request_shape`, so a user who types a network identity into a password login on the same FortiGate cannot reach the certificate-derived path. Qualification includes two negative cases against one server object: a login with an empty `mfa-password`, and a login with a typed password, must both yield `request_shape` (`platform-qualification.md` section 4).
- EAP-TLS: `Access-Request` carrying `EAP-Message`; `User-Name` and the EAP identity are ignored for authorization (`../design/radius.md` section 4).
- Every request carries `Message-Authenticator` over UDP and TCP; FortiOS enables `require-message-authenticator` by default on its side and treats it as optional over TLS. Over RadSec Ricevanta accepts requests without it.

### 4.3 Gateway configuration

```
config user radius
    edit "ricevanta"
        set server "<radius service address>"
        set transport-protocol tls                # RadSec, TCP 2083; udp only where TLS is unavailable
        set ca-cert "<Ricevanta server issuing CA>"
        set client-cert "<certificate from the network-gateway profile>"
        set server-identity-check enable
        set account-key-cert-field othername
        set account-key-processing same
        set radius-coa enable                     # verify the path on each qualified FortiOS release
        set acct-interim-interval 600
    next
end
config user peer
    edit "ricevanta-network-access"
        set ca "<Ricevanta network-access issuing CA>"
        set mfa-mode subject-identity
        set mfa-server "ricevanta"
        set mfa-password <binding token>
    next
end
```

The FortiGate validates the client certificate against the network-access issuing CA and checks revocation through the OCSP responder or CRL the `pki` module serves (`../design/pki.md`). With `transport-protocol tls`, FortiOS uses port 2083 for authentication and accounting. RadSec is required when the FortiGate runs in FIPS-CC mode (`../analysis.md` C6).

Trust restriction: the VPN admits client certificates through the one `user peer` above, whose `ca` is the network-access issuing CA, and no other peer or CA group admits client certificates for the same VPN. Ricevanta cannot see the issuing CA of the certificate the gateway validated, so a certificate from any other CA the VPN trusts that carries a real network identity would pass authorization; this restriction is what excludes it (`../design/radius.md` section 1), and qualification presents a foreign certificate carrying an issued `netid`.

### 4.4 Accounting and dynamic authorization

The FortiGate sends accounting to the accounting server it is configured with, and over RadSec on the same connection. RADIUS CoA for SSL VPN sessions exists from FortiOS 7.0; a Disconnect-Request must carry `User-Name` and `Framed-IP-Address` to match a session (Fortinet community, verify). Disconnect and CoA for IPsec dialup sessions are unconfirmed (verify). Each operation and CoA transition needs variant-specific evidence under section 3.1. Without qualified dynamic authorization, only a proved enforced timeout bounds residual access; an unproved timeout blocks the required variant (`../design/radius.md` section 8).

### 4.5 What first-party documentation confirms

Confirmed: RADIUS-integrated certificate authentication from FortiOS 7.4.1 with `account-key-cert-field` (`othername`, `rfc822name`, `dnsname`) and `account-key-processing`; `mfa-password` as a per-peer setting (its transmission is in the verify list below); RadSec client with `transport-protocol tls`, `ca-cert`, `client-cert`, `server-identity-check` and port 2083; mandatory Message-Authenticator validation over UDP and TCP with `require-message-authenticator` enabled by default; removal of SSL VPN tunnel mode in 7.6.3; the Fortinet VSA dictionary. To verify: that `mfa-password` is sent as `User-Password` (PAP) and what is sent when it is empty, certificate-derived RADIUS on IPsec dialup, FortiClient EAP methods, CoA paths per variant, `Class` echo in accounting, `Session-Timeout` handling for VPN sessions, the fixed FortiOS releases for CVE-2024-3596 (a community article names 7.2.10, 7.4.5 and 7.6.1 as the releases that started enforcing Message-Authenticator).

## 5. Cisco ASA and ASAv

### 5.1 Variant and request shape

The ASA terminates Cisco Secure Client sessions (SSL/TLS and IKEv2) and validates the client certificate itself; Secure Client authenticates to an ASA with the proprietary EAP-AnyConnect, and EAP-TLS pass-through to RADIUS is not documented for it (verify), so the profile is certificate-derived only. The tunnel group uses `authentication certificate`, `username-from-certificate UPN` and an `authorization-server-group` pointing at Ricevanta with `authorization-required`, and the server group runs `authorize-only`. In that mode the ASA sends `Access-Request` with `Service-Type` = Authorize-Only (17) and `Message-Authenticator`, and no password (the ASA guide names neither the `Service-Type` value nor the absence of `User-Password` for `authorize-only`; verify). Ricevanta accepts exactly that shape on a `cisco-asa` gateway and rejects any request carrying `User-Password`, `CHAP-Password` or `EAP-Message` with reason `request_shape`. Where the ASA sends its tunnel group name in the Cisco VSA `Tunnel-Group-Name` (3076, 146) (verify), the gateway registration lists the allowed tunnel groups and others are rejected.

### 5.2 Gateway configuration

```
aaa-server RICEVANTA protocol radius
  authorize-only
  dynamic-authorization                  ! listener, default port 1700; documented for ISE
aaa-server RICEVANTA (outside) host <radius service address>
  key <shared secret>
tunnel-group RA-CERT general-attributes
  authorization-server-group RICEVANTA
  authorization-required
  username-from-certificate UPN
  accounting-server-group RICEVANTA
tunnel-group RA-CERT webvpn-attributes
  authentication certificate
crypto ca trustpoint RICEVANTA-NETWORK
  revocation-check ocsp crl
```

The ASA trustpoint holds the Ricevanta network-access issuing CA and checks revocation through the `pki` module's OCSP responder or CRL. Trust restriction: the tunnel group admits certificates only from that issuer, through `validation-usage` on the trustpoint limited to the VPN client uses with no other trustpoint validating them, or a certificate map that selects the tunnel group only for the Ricevanta issuer (verify the commands on each qualified release). Ricevanta cannot see which CA issued the certificate the ASA validated, so this restriction is what keeps a foreign certificate carrying a real `netid` out (`../design/radius.md` section 1); qualification presents one. `username-from-certificate` also accepts subject fields such as `CN` and `EA`; the profile uses `UPN`, which carries the same network identity as the FortiGate default. SAN DNS names are not offered by `username-from-certificate` on ASA 9.22 (Cisco community, verify).

### 5.3 Transport, accounting and dynamic authorization

No ASA release documents RADIUS over TLS (verify), so the ASA uses UDP with a per-gateway shared secret, source restriction and Message-Authenticator; the ASA fixed release for CVE-2024-3596 (bug CSCwk71992) and the request shape of an `authorize-only` server group (`Service-Type` 17 and no `User-Password`) are qualification inputs (verify). The ASA sends accounting for VPN sessions to its `accounting-server-group`. `dynamic-authorization` accepts CoA on port 1700 by default; Cisco documents it for use with ISE, and acceptance of Disconnect-Request from a non-ISE server, including the session identifier it requires, is unconfirmed (verify). Each CoA transition and selector needs section 3.1 evidence. Without qualified Disconnect, a proved original `Session-Timeout` is the bound; timeout support alone does not prove clearing or packet ordering.

### 5.4 ASAv

ASAv uses the same configuration; remote-access VPN on ASAv and ASA needs the Secure Client licence tier that covers certificate authentication and IKEv2 (verify the tier). The required-unit manifest names one ASA hardware model and one ASAv image.

## 6. 802.1X wired and Wi-Fi

The `ieee8021x` profile follows RFC 3580: EAP-TLS terminated by Ricevanta, `MS-MPPE` keys in the accept, VLAN through the tunnel attributes, `Filter-Id` for a named filter, and `Session-Timeout` with `Termination-Action` = RADIUS-Request so the authenticator reauthenticates the port within the bound without dropping a compliant client. `Called-Station-Id` carries the SSID on Wi-Fi where the authenticator sends it, exposed to policy as `access.ssid`. Disconnect-Request goes to the authenticator's dynamic authorization port (RFC 5176, UDP 3799) when the gateway registration enables it; CoA is sent only for the exact qualified transition and packet-exclusion proof of section 3.1; otherwise use qualified Disconnect or the proved original timeout bound. The reference authenticator for automated tests is hostapd (`driver=wired` and a Wi-Fi interface) with `wpa_supplicant` as the peer; its dynamic authorization server handles Disconnect-Request (verify CoA-Request support). The required-unit manifest names one managed switch and one access point model besides hostapd.

## 7. Sources

- FortiGate: [RADIUS integrated certificate authentication for SSL VPN 7.4.1](https://docs.fortinet.com/document/fortigate/7.4.0/new-features/471933/radius-integrated-certificate-authentication-for-ssl-vpn-7-4-1), [SSL VPN tunnel mode replaced with IPsec VPN (7.6.3 release notes)](https://docs.fortinet.com/document/fortigate/7.6.3/fortios-release-notes/173430/ssl-vpn-tunnel-mode-no-longer-supported), [Configuring a RADSEC client](https://docs.fortinet.com/document/fortigate/7.4.7/administration-guide/729374), [Configuring a RADIUS server (8.0)](https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/759080/configuring-a-radius-server), [RADIUS AVPs and VSAs](https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide/952303), [Windows IKEv2 native VPN with user certificate](https://docs.fortinet.com/document/fortigate/7.0.5/administration-guide/726232/windows-ikev2-native-vpn-with-user-certificate); vendor community: [certificate authentication for IKEv2 with RADIUS or LDAP](https://community.fortinet.com/fortigate-3/technical-tip-certificate-authentication-for-ikev2-vpn-with-radius-or-ldap-user-authentication-215788), [dialup with LDAP-integrated certificate authentication](https://community.fortinet.com/fortigate-3/technical-tip-how-to-configure-dialup-tunnel-with-ldap-integrated-certificate-authentication-202302), [RADIUS CoA behaviour](https://community.fortinet.com/fortigate-3/technical-tip-radius-coa-behavior-100060), [RADIUS failure after upgrade to 7.2.10, 7.4.5, 7.6.1](https://community.fortinet.com/fortigate-3/troubleshooting-tip-radius-authentication-failure-after-the-firmware-upgrade-to-v7-2-10-v7-4-5-v7-6-1-182769).
- Cisco: [ASA 9.19 RADIUS Servers for AAA](https://www.cisco.com/c/en/us/td/docs/security/asa/asa919/configuration/general/asa-919-general-config/aaa-radius.html), [ASA 9.2 RADIUS Servers for AAA](https://www.cisco.com/c/en/us/td/docs/security/asa/asa92/configuration/general/asa-general-cli/aaa-radius.html), [ASA command reference, u commands](https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/T-Z/asa-command-ref-T-Z/u-commands.html), [AnyConnect over IKEv2 to ASA](https://www.cisco.com/c/en/us/support/docs/security/anyconnect-secure-mobility-client/113692-technote-anyconnect-00.html), [Secure Client profile editor 5.1](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/Cisco-Secure-Client-5/admin/guide/b-cisco-secure-client-admin-guide-5-1/anyconnect-profile-editor.html), [cisco-sa-radius-spoofing-july-2024](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-radius-spoofing-july-2024-87cCDwZ3.html).
- Standards: [RFC 2548](https://www.rfc-editor.org/rfc/rfc2548.html), [RFC 2865](https://www.rfc-editor.org/rfc/rfc2865.html), [RFC 2868](https://www.rfc-editor.org/rfc/rfc2868.html), [RFC 3580](https://www.rfc-editor.org/rfc/rfc3580.html), [RFC 5176](https://www.rfc-editor.org/rfc/rfc5176.html).
