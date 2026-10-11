# Short-term work

Tasks leave this list when committed. Milestones stay in `docs/roadmap.md`; unresolved contracts and source checks are recorded in `docs/analysis.md`.

- [ ] Specify and prove a cross-store authority gate or recipient fence, then complete the typed audit records and replay model, authority-domain reducers and dependency closures, database DDL and grants, signed external-action evidence, executable model and crash fixtures required by `docs/specs/authority-journal-protocol.md` (BE-12).
- [ ] Qualify the endpoint candidates in `docs/specs/endpoint-mechanism-research.md`, and find supported macOS mechanisms for the macOS 15 exact-byte file gate, identity-bound termination and script descendant containment.
- [ ] Qualify Apple declarative-status freshness and the Windows escrow transaction in `docs/specs/mdm-evidence-recovery.md`; specify a jobs-only escrow-acknowledgement key, a Linux all-writer exclusion or atomic compare-delete primitive, and an Apple FileVault protocol guarantee or trust-boundary redesign before destructive actions.
- [ ] Decide whether to adopt the single-capsule console model in `docs/specs/isolation-qualification.md`; prove exact document binding and browser egress before enabling it, and prove native path, memory and cleanup bounds for the isolated inventory-query worker on every required platform.
- [ ] Publish the missing machine-readable contracts and positive and negative fixtures listed in `docs/analysis.md` section 3 before implementing their consumers.
- [ ] Complete the certificate-profile fields left open by `docs/specs/network-transition-qualification.md`, publish its typed records and fixtures, then qualify renewal, accounting, session control, CoA and custody recovery on every required gateway unit.
- [ ] Verify the remaining platform and dependency claims in `docs/analysis.md` section 4 and establish the required device and gateway test lab.
- [ ] Bound concurrent body decoding in the ingest handler: one key-dense 64 MiB batch costs about 18.5 million allocations and 250 MB of live heap in `server/internal/events/body`, so request concurrency and process memory need a measured limit before the handler ships (EV-09).
- [ ] Implement Tasks 2 to 5 of `docs/plans/extension-loader.md` (bounded archive reader, single verified YAML decode, `Load` and Gate B qualification), then specify stateful admission on top of the loader's verified evidence (EXT-08).
- [ ] Specify the console identity slice (OIDC, SAML and break-glass login, sessions, CSRF) and the change stream once the backend OpenAPI and identity endpoints exist (BE-08 to BE-10).
