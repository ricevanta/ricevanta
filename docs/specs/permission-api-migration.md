# Permission API binding migration

This is the single approved bounded exception to the immutable `uses` comparison in [CI hardening section 7](ci-hardening.md#7-reviewed-base-catalogue-compatibility-ci-02). The canonical catalogue contains revision 4 and has no active OpenAPI catalogue proposal. The private code-defined delta below owns the exact transition. Activation requires the complete atomic integration and independent implementation review in [contract validation](../plans/contract-validation.md#task-1-catalogue-migration-and-coverage), including identical embedded bytes and the final coverage source refresh.

## 1. Exact boundary

The delta introduces `identity.providers.create` and `identity.providers.delete`, each organization-scoped, role-grantable and always subject to fixed identity-authority approval. It appends 32 exact operation selectors to 24 existing permissions and retains every existing selector. It changes no existing owner, scope, protection, approval, rule, grant, status, introduced revision, source or note. No retired row changes. Root revision becomes 4; the two new rows have `introduced: 4`.

The canonical catalogue owns the resulting rows; the private migration constant specified in section 2 owns the exact transition delta. These groups explain why the additions do not enlarge existing authority:

| Binding group | Existing authority and retained limits |
|---|---|
| Ordinary approve/reject | The exact routes implement `api:approve-protected-action` and `api:reject-protected-action`; current eligible different operator, target visibility, recent interactive authentication and request-kind checks remain mandatory |
| Identity approve/reject | The direct `identity.authority.approve` boundary already owns identity decisions, including rejection through the ordinary rejection row's explicit note; authority approval requires bound unaffected authentication, and rejection requires recent authentication |
| Queue list/detail/targets | `authz.approvals.read` already covers the full queue; exact selectors expose metadata and sanitized frozen targets, never secrets, approval authority or enrollment-code claim rights |
| Break-glass list and lifecycle | `view:break-glass` and each distinct `api:` mutation acquire their corresponding operation IDs; fixed two-account approval remains, including enable and disable |
| Principal-link list/request list/create/delete | The metadata view includes pending verified requests; linking and unlinking implement the existing protected `api:change-principal-link`, without implicit roles or email matching |
| Revoke a user's sessions | Repeats the existing immediate session-revocation authority over the user's sessions; grants no API-token revocation, approval or fresh-authentication bypass for other actions |
| Thirteen `streamChanges` selectors | Each is a notification view of an already authorized resource, scoped by that exact read permission; it carries no row data and grants no source read or mutation beyond that permission |

Authorities for these limits: [API foundation section 8](api-foundation.md#8-authorization-binding-and-route-table), [identity login sections 5 and 6](identity-login.md#5-identity-providers-and-principal-links), [identity sessions sections 3 and 6](identity-sessions.md#3-lifetimes-activity-and-revocation), and [change stream section 2](change-stream.md#2-topics). The new provider names represent distinct mutations and are not aliases for `identity.providers.update`. Subject, protocol and public exemptions remain in the coverage manifest; no synthetic permission is added for enrollment-code claim.

## 2. Pinned compatibility exception

Strictly decode and validate the event-derived base and candidate Git blobs through the existing compatibility reader before considering this exception. Define a comparison digest as SHA-256 of `json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')`. This serialization is a local comparison rule for the catalogue's ASCII, integer-only data, not a signature format. Array order is retained.

| Object | Revision | Comparison digest |
|---|---|---|
| Complete base catalogue | 3 | `1966faf9ad11b86f5244747e8847fb56163187fc1c738c709bff466bbcb9615f` |
| Exact migration delta | base 3, result 4 | `09706e63ca1eaf7e1be223b5c456d8cf9cbbb588ba1f317db14658c9acf2b876` |
| Complete merged catalogue | 4 | `78a1b1ecaef5fade010e8bdaad85b6d57e968639cbfbc826f17c58e579727621` |

Pin these constants in the compatibility implementation, not in candidate-controlled configuration. The exception applies only when both complete catalogue digests match their row, the catalogue schema Git blob is unchanged, and the independently checked delta is exactly the two additions and 32 appended selectors. Retain every ordinary structural, revision, permanent-name, tombstone and immutable-field check; waive only the existing `uses`-set difference for this exact pair. A matching revision alone never suffices. No command-line flag, environment variable, workflow input, proposal path or editable allow-list can enable another exception.

Embed the exact reviewed delta as a private JSON string constant in `scripts/ci/catalogue_compat.py`. Strictly decode that constant, require its comparison digest above, and recompute the complete candidate from the validated event-base catalogue; require equality with the candidate Git blob and the pinned result digest. The constant is fixed implementation data, never a proposal loaded from either Git tree, the working tree, a command argument or the environment. The base need not contain any OpenAPI file. Both catalogue reads retain their regular-blob, missing-object and event-binding refusals, and the catalogue schema blobs must match. The candidate Git tree must contain no object at `schemas/openapi/v1/catalogue-proposal.json` for this exact transition; the OpenAPI validator separately rejects an already-applied active proposal. No candidate proposal can choose or widen the exception. Keep the exact exception available for validation of this transition; once the base is revision 4, all future `uses` changes fail the ordinary rule, even if the candidate is revision 5. No later catalogue format or authority migration is authorized.

## 3. Atomic lifecycle and tests

The integration change must include the compatibility exception and negative controls, revision 4 canonical bytes, an identical embedded Go copy, updated coverage bindings/exemptions, the completed source refresh, and removal of the active proposal. OpenAPI tests use synthetic proposals independent of the live catalogue. The data, guard, embedded copy and coverage refresh form one integration unit; no partial data or code change may land alone. Activation remains blocked until the complete change passes independent implementation review and CI. Local validation of one half is not integration proof.

The validator reads the canonical catalogue directly and validates it against its schema even when no proposal exists. Its proposal helper retains C01 through C07 failures: a stale/already-applied proposal, wrong base, duplicate/new-name collision, bad introduced revision, missing or inactive target, duplicate selector and invalid merged schema remain refusals. Test those paths with explicit local synthetic base/proposal objects independent of whether an active proposal exists; never skip a regression based on the current canonical revision. A future live proposal still requires its own independent semantic and compatibility review.

Required compatibility controls: exact migration passes with no OpenAPI tree in the event-derived base and no active proposal in the candidate; unchanged revision-3 and revision-4 catalogues pass. Missing/malformed or digest-mismatched embedded delta, a retained candidate active-proposal object of any Git kind, changed schema blob, wrong base/candidate digest, partial or extra selector additions, selector removal or reassignment, altered immutable field, new-name mutation, tombstone mutation, revision 5 replay, and candidate-as-base substitution fail. Candidate or working-tree proposal content cannot select another delta or make a different result pass. Verify the full result independently against the embedded delta and all three digest pins, and retain positive coverage for the actual base catalogue bytes. Formatting-only differences retain ordinary behavior. The normal revision-increase guard and unrelated immutable-uses tests stay enabled.

## 4. Authority trace and review

Path: repository design review authorizes the exact data delta; CI reads event-bound Git objects and verifies compatibility; Go embeds identical canonical bytes; future request handlers authenticate and resolve current authority under their own reviewed contracts. Catalogue acceptance creates no handler, role assignment, session, signature or journal record. Production API handlers remain blocked on reviewed implementation plans and BE-12.

| Attacker | Outcome |
|---|---|
| Stolen enrollment token | Cannot alter repository review or obtain a console permission through catalogue metadata |
| Compromised agent host | Can submit its protocol traffic only; cannot select a migration or gain administration authority |
| Compromised console session | Retains only current subject/permission rights; the exact new bindings do not remove scope, freshness, approval or one-use checks |
| Rogue extension publisher | Cannot change compiled catalogue bytes or use identity/approval routes through the extension bridge |
| Network position between agent and server | Cannot choose CI Git objects or manufacture a permission; runtime transport checks remain separate |
| Database writer without signing keys | Cannot replace embedded metadata; replay/current-generation refusal still requires BE-12, so this migration admits no production consumer |
| Server restored from backup | Remains sealed under the authority recovery contract; catalogue revision 4 is no recovery proof |

Benefit: approved operation IDs bind to their existing actions without duplicating permissions or broadening a general compatibility rule. Cost: one explicit transition and its regression fixtures must be maintained. Dependencies: independent design review, atomic canonical/embedded/coverage integration and event-bound compatibility. Limit: CI checks candidate repository code, not a sandbox against a malicious maintainer; independent review remains necessary. Rejected alternatives: permitting all additive uses, selecting exceptions by revision alone, loading candidate-supplied migration data, requiring an unrelated proposal file in the event base, bypassing compatibility, or inventing replacement names for unchanged actions.
