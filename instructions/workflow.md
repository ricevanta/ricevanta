# How work proceeds

## Design and implementation (current)

1. Read `docs/blueprint.md`, the Shared, Platform and domain sections of `docs/decisions.md`, and the domain's design file if it exists. A design reviewer reads all of `docs/decisions.md`.
2. Write or update the document where `instructions/documentation.md` says it lives. Use `designer` under the [design routing rules](../AGENTS.md#agents-and-models). If the work changes a decision, rewrite the entry in `docs/decisions.md` in the same change.
3. Define each code slice in a design and implementation plan that name its boundaries, contracts and required checks. A `design_reviewer` meeting the [review eligibility rules](../AGENTS.md#agents-and-models) must approve both before implementation starts.
4. Do not implement production consumers that assume an unresolved native, platform or security guarantee. Explicitly isolated qualification harnesses and prototypes may proceed to resolve a gate, but they cannot claim the missing guarantee until the required evidence passes review.
5. Add a dependency to `docs/licensing.md` before code relies on it. Add a vendor program or signing requirement to `docs/project.md` before work relies on it.
6. Follow the language and testing instructions for the component. Go guidance begins with the first server packages. Rust guidance is in `instructions/rust.md` and Vue guidance is in `instructions/vue.md`.

## Design rules

- Learn from the reference projects in the blueprint; copy code only after a row exists in `docs/licensing.md`. GPL code is never linked.
- Never promise enforcement on a channel until its row in the capability matrix has a passing acceptance test.
- Event-driven collection and bounded memory. Performance targets (blueprint section 7) are measured, not assumed.
- Sensitive content is classified on the endpoint. Raw content leaves the device only as the redacted snippet a policy allows.
- Every design states benefits, trade-offs, dependencies, limits and the alternatives considered.

## Parallel slices and CI

- Each slice gets its own worktree and branch. The primary agent assigns decision IDs before work starts, so parallel slices never reuse one.
- The primary agent runs at most six Codex jobs at once across all of its slices, counting every design, review and implementation job it starts; nested agents count toward their parent job.
- Workers run only light local checks: formatting, vet or clippy, and focused tests for the packages they touch. Race tests, timed fuzzing, extended property tests, browser tests and the cross-OS matrix run on GitHub CI (`instructions/testing.md`); the primary agent reads those results before integration.
- For a failing or intermittent check, a crash, or wrong output whose cause is unknown, the primary agent dispatches the troubleshooter and supplies CI logs, artifacts and traces. When logs cannot settle the cause, it runs a temporary diagnosis workflow on push to its own `wip/` branch, supplies the results and deletes the workflow before landing. Use `push` because [`workflow_dispatch` requires the workflow file on the default branch](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch).
- Every brief tells the worker to settle, without stopping, any choice the reviewed design settles, report each choice, and stop and report only a real design conflict or missing evidence.
- When a worker stops with a question or a design conflict, the primary agent answers it from the reviewed design, or sends the conflict back to the design author and its independent reviewer, records any approved contract change in the design, and only then resumes the worker with a new task that states the answer.

## Landing a slice

1. Push the slice branch to `wip/<slice>` and open a pull request against `master`. Every workflow triggered by the change must run on the pull request head; an empty set of triggered workflows does not count as passing, so dispatch `Design checks` on the branch (`gh workflow run 'Design checks' --ref wip/<slice>`) when a change touches only paths no workflow watches.
2. Review findings, including GitHub Copilot findings when its review runs, are fixed on the same branch or answered with the reason they do not apply. When Copilot does not run, follow [Reviews](#reviews). After fixing or answering a Copilot finding, resolve its review thread (`gh api graphql` with the `resolveReviewThread` mutation), so the pull request shows which findings remain open. Fixups are squashed into coherent commits on the branch before landing.
3. When `master` has moved, rebase the branch onto it, have an independent reviewer check any conflict resolution that changes behaviour, and push with `git push --force-with-lease` to that `wip/` branch only. Push only after the rebase finished cleanly; a script that rebases and pushes chains the two with `&&`. CI then runs again on the new head.
4. Land only a head whose workflows all passed and whose final commit an eligible reviewer (Reviews, below) approved, including its fixes and every finding answered as not applying: fast-forward `master` to the pull request head (`git push origin <head>:master`). The `protect-master` ruleset requires an approving review that the sole owner cannot give, so this push uses the owner's admin bypass, which the owner has authorized. A teammate without that bypass hands the owner a pull request whose workflows passed, and the owner lands it. GitHub marks the pull request merged, and the commits keep the author's signature, which a squash or rebase merge on GitHub would replace.
5. Never force-push `master` or rewrite commits that `master` contains. When the repository deletes head branches automatically, the fast-forward that marks the pull request merged also deletes its branch, so later work on the slice starts a new `wip/` branch instead of reusing the old name.
6. After landing, and whenever work touches GitHub, review this repository's notification threads for pull requests, reviews and failed runs, including older read threads. Close each handled thread as done with `gh api -X DELETE notifications/threads/<id>` (HTTP 204); `PATCH` only marks a thread read. Close a failed-run thread only after its cause is fixed or explained.

## Reviews

Copilot is configured to review every pull request push automatically using [repository guidance](../.github/copilot-instructions.md), [path checklists](../.github/instructions/), the [code-review](../.github/skills/code-review/SKILL.md) and [security-review](../.github/skills/security-review/SKILL.md) skills, and the [review environment](../.github/workflows/copilot-code-review.yml). The guidance links to authoritative rule files instead of restating them. When Copilot does not run on a pull request head, for example because the account's quota is exhausted, landing relies on green CI and the independent review assigned by the [role table](../AGENTS.md#agents-and-models), both for that exact head. Request Copilot again once it becomes available.

- Use `design_reviewer` and `code_reviewer` under the [routing and independence rules](../AGENTS.md#agents-and-models), including fix confirmations.
- A `code_reviewer` brief carries the base commit, the diff, and the CI results with their run URLs, because the reviewer may run without Git or network access.
- Security-relevant work (enrollment, keys, signing, update, enforcement) requires an adversarial pass by `code_reviewer` before merge.

## Commits and pushing

- The primary agent may commit completed work locally without asking again. Each commit is one reviewable change with a subject that states the change and a body that states why. Subagents leave Git operations to the primary agent.
- Commit messages name no tool or assistant: no `Co-Authored-By` trailer for an assistant, no `Claude-Session` trailer and no "Generated with" line, whatever a tool proposes.
- Stage files by explicit path. Never `git add -A`, `git add .` or `git commit -a`, which can sweep another session's changes into the commit.
- Every commit is signed off: `git commit -s` (Developer Certificate of Origin, see `CONTRIBUTING.md`).
- The primary agent may push `wip/` branches at any time and lands slices on `master` only through the procedure in "Landing a slice". Before landing, inspect the full log and diff of the branch, combine fixups and work-in-progress commits, and keep separate changes separate when that helps review.
- Use CI to verify every slice before it reaches `master`. Keep CI scoped to affected files, cancel superseded runs, and cache only downloaded dependency sources whose integrity is rechecked. Authoritative jobs never restore compiled output; tag builds use no restored caches ([release builds](../docs/specs/release-builds.md)). GitHub Actions is free for this public repository, so heavy checks belong in CI rather than on local machines.
- Branch before committing to `master` once more than one person works on the repository.

## Reporting

End every task with what was verified and how: files cross-checked, commands run with their exit status, test output. A failed check is reported as failed. Skipped work is reported as skipped, never as done. A worker's report is evidence, not proof: the primary agent reruns its key checks before integrating the work.
