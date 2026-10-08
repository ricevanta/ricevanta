# Project facts

| Item | Value |
|---|---|
| Name | Ricevanta |
| Domain and namespace | `ricevanta.io`: `apiVersion: ricevanta.io/v1*` in policies and schemas, reverse-DNS `io.ricevanta.*` for bundle, extension and service identifiers, OCSF extension names, PKI subject and SAN patterns, default download, update and documentation URLs. No other domain is used in identifiers. |
| Repository | `github.com/ricevanta/ricevanta`, public, default branch `master` |
| Continuous integration | GitHub Actions with hosted macOS Apple silicon, Windows and Linux runners |
| License | Apache-2.0 (`LICENSE`) |
| Contributions | Developer Certificate of Origin 1.1, `git commit -s` (`CONTRIBUTING.md`, `DCO`). No contributor license agreement. |
| Console languages | English source strings, Vietnamese translation at v1.0.0, `vue-i18n` from the first component. Policies, rule packs and documentation are not translated. |

## Vendor programs and signing

Apple and Microsoft tie entitlements and driver signatures to one organization. The project holds them on behalf of all self-hosters; self-built sensors run without the features that need them, and the README says so.

| Phase | Accounts |
|---|---|
| Development and testing | Personal accounts and test machines: individual Apple Developer Program account for Developer ID signing; Endpoint Security on a test Mac with SIP disabled; test MDM push certificate from `mdmcert.download` (verify availability); Windows test-signing mode for the driver; self-hosted browser extension updates. |
| Before sensor distribution (v0.4.x) | A company is registered. Apple Developer Program organization account, Apple entitlement requests (Endpoint Security, Network Extension), Microsoft Partner Center account and EV code-signing certificate are filed under the company, because they bind to the team that files them. |
| Release | All production binaries signed under the company. Programs that cannot be used on personal accounts (Apple Business Manager, Microsoft Virus Initiative) are needed only for the capabilities deferred to v2.0.0 (`platform-support.md`). |
