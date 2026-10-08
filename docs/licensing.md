# Licensing

Ricevanta is Apache-2.0. This file records what third-party code and rule sources may be used and under which conditions. Every new dependency or rule pack gets a row before code depends on it.

## Rules

- GPL code is never linked into Ricevanta. A GPL program may run only as a separately distributed optional process after legal review.
- Reference projects are for learning; copying code requires a row in the table and attribution in `NOTICE`.
- Rule packs carry their own license record, author fields and signature from the first pack. Rule licenses are tracked separately from application code.
- Sigma rules under DRL 1.1 require the rule author to be shown wherever a match is displayed, including console alert views and exported events.
- An SBOM is produced for every release.

## Code and rule sources

| Source | License | Use |
|---|---|---|
| Sigma rules (SigmaHQ) | DRL 1.1 | Allowed with author attribution in match output and redistributed rules |
| Sigma tooling, pySigma | MIT (verify) | Reference only; Python |
| YARA-X | BSD-3-Clause | Rust library, linkable |
| Community YARA rules | Varies per repository; some non-commercial | Per-pack license record required |
| Magika | Apache-2.0 (verify model weight terms) | Linkable; ONNX runtime adds size |
| Presidio | MIT | Port recognizer patterns, not code; Python |
| Gitleaks | MIT | Patterns reusable with attribution; Go |
| detect-secrets | Apache-2.0 | Patterns reusable |
| Apache Tika | Apache-2.0 | Optional server-side only; Java |
| osquery | Apache-2.0 or GPL-2.0 dual | Reference; not bundled |
| Fleet | MIT, except `ee/` under a source-available license | Only non-`ee/` code; verify each file |
| NanoMDM, MicroMDM | MIT | Design and code reusable |
| Munki | Apache-2.0 | Reference |
| step-ca | Apache-2.0 | Go code reusable |
| `layeh/radius` | MPL-2.0 | Linkable; modified files stay MPL |
| FreeRADIUS | GPL-2.0 | Not used |
| Wazuh | GPL-2.0 with exceptions | Reference only |
| Santa | Apache-2.0 | Design reusable; Objective-C and Swift |
| HarfangLab `endpoint-sec` crate | Verify | Rust Endpoint Security bindings |
| Falco rules | Apache-2.0 | Reusable through logsource mapping |
| MITRE ATT&CK | MITRE terms, free with attribution notice | Include the notice |
| OCSF schema | Apache-2.0 | Used as the event format |
| CIS Benchmarks | Not freely redistributable | Not bundled; baselines are authored in-project |
