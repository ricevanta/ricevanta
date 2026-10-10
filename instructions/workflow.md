# How work proceeds

## Design and implementation (current)

1. Read `docs/blueprint.md`, `docs/decisions.md` and the domain's design file if it exists.
2. Write or update the document where `instructions/documentation.md` says it lives. If the work changes a decision, rewrite the entry in `docs/decisions.md` in the same change.
3. Define each code slice in a design and implementation plan that name its boundaries, contracts and required checks. Someone who did not write the design must approve both before implementation starts.
4. Do not implement production consumers that assume an unresolved native, platform or security guarantee. Explicitly isolated qualification harnesses and prototypes may proceed to resolve a gate, but they cannot claim the missing guarantee until the required evidence passes review.
5. Add a dependency to `docs/licensing.md` before code relies on it. Add a vendor program or signing requirement to `docs/project.md` before work relies on it.
6. Follow the language and testing instructions for the component. Go guidance begins with the first server packages. Rust and Vue guidance waits for their first reviewed code slices; do not create placeholder files.

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

- The primary agent may commit completed work locally without asking again. Each commit is one reviewable change with a subject that states the change and a body that states why. No tool attribution lines. Subagents leave Git operations to the primary agent.
- Every commit is signed off: `git commit -s` (Developer Certificate of Origin, see `CONTRIBUTING.md`).
- The primary agent may push without another permission request after the required checks and independent reviews pass. Before every push, remind the owner that unpushed commits must be reviewed and squashed into fewer coherent commits where appropriate. Inspect the full unpushed log and diff, combine fixups and work-in-progress commits, and preserve separate changes when that helps review. Rewrite only unpushed history; never rewrite published commits.
- Use CI to verify pushed changes. Keep CI scoped to affected files, cancel superseded runs, and cache dependencies when a cache saves work. Run cheap local checks before pushing and avoid repeated pushes solely to discover checks that can run locally.
- Branch before committing to `master` once more than one person works on the repository.

## Reporting

End every task with what was verified and how: files cross-checked, commands run, test output. A failed check is reported as failed. Skipped work is reported as skipped, never as done.
