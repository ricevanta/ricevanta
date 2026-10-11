# Copilot code review

Apply this guidance only during code review. [AGENTS.md](../AGENTS.md) is the project guide; use the nearest component guide where present. CLAUDE.md, .claude/ and .codex/ assign roles and models to other agents and do not bind Copilot review.

Review in this order:

1. Security and conformance to the slice's [spec](../docs/specs/) and [plan](../docs/plans/): API, error sentinels, precedence, bounds and vectors.
2. Tests that cannot fail: vacuous assertions, missing negative controls, skipped cases and oracles that repeat the implementation. Follow [testing rules](../instructions/testing.md).
3. Current-state documentation under [documentation rules](../instructions/documentation.md), including completed TODO tasks, plan checkboxes and claims that delivered code is absent or pending.
4. CI and fixture wiring under [workflow rules](../instructions/workflow.md): every input triggers its consumer, every required check runs, and commands match the testing instructions without accidental duplicates.
5. Supply chain pins and [licensing rows](../docs/licensing.md), including transitive/build dependencies and evidence links that remain accessible outside ignored directories.

Use the [code-review skill](skills/code-review/SKILL.md) for every pull request and the [security-review skill](skills/security-review/SKILL.md) for its named triggers. Read GitHub MCP pull request context, review threads and failing check logs before commenting, as those skills specify. Apply the [Go](../instructions/go.md), [Rust](../instructions/rust.md) and [Vue](../instructions/vue.md) rules through the matching [path checklists](instructions/).

Do not comment on formatting enforced by gofmt, Prettier, ESLint or rustfmt, demand local execution of checks reserved for CI, or comment on the landing procedure. Check CI evidence for heavy checks; missing or failing required checks remain defects.

Write one comment per distinct defect: `file:line`, the violated rule's file and section, the triggering input or condition, its consequence, and a concrete fix. Report only supported findings introduced or exposed by the pull request; distinguish unavailable evidence from a defect. Use plain active voice and no em dashes.
