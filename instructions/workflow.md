# How work proceeds

## Design phase (current)

1. Read `docs/blueprint.md`, `docs/decisions.md` and the domain's design file if it exists.
2. Write or update the document where `instructions/documentation.md` says it lives.
3. If the work changes a decision, rewrite the entry in `docs/decisions.md` in the same change.
4. A new dependency gets a row in `docs/licensing.md`; a new vendor program or signing requirement goes into `docs/project.md`; both before anything relies on them.

No application code in this phase. Language and testing instructions (`instructions/rust.md`, `go.md`, `vue.md`, `testing.md`, `release.md`) are written when the first code directory is created, not before.

## Design rules

- Learn from the reference projects in the blueprint; copy code only after a row exists in `docs/licensing.md`. GPL code is never linked.
- Never promise enforcement on a channel until its row in the capability matrix has a passing acceptance test.
- Event-driven collection and bounded memory. Performance targets (blueprint section 7) are measured, not assumed.
- Sensitive content is classified on the endpoint. Raw content leaves the device only as the redacted snippet a policy allows.
- Every design states benefits, trade-offs, dependencies, limits and the alternatives considered.

## Reviews

- Design documents: one review by someone who did not write them.
- Security-relevant work (enrollment, keys, signing, update, enforcement): adversarial review before merge.
- A reviewer never implements what they review.

## Commits and pushing

- Commit only when asked. Each commit is one reviewable change with a subject that states the change and a body that states why. No tool attribution lines.
- Every commit is signed off: `git commit -s` (Developer Certificate of Origin, see `CONTRIBUTING.md`).
- Never push on your own. Commits stay local until the owner has reviewed `git log` and the diffs and said to push. Before that review, local history may be rewritten (squash, reorder, reword) so that the pushed sequence is clean to follow. After a push, history is not rewritten.
- Branch before committing to `master` once more than one person works on the repository.

## Reporting

End every task with what was verified and how: files cross-checked, commands run, test output. A failed check is reported as failed. Skipped work is reported as skipped, never as done.
