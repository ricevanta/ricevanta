---
applyTo: "docs/**,instructions/**,AGENTS.md,TODO.md,*.md"
excludeAgent: "cloud-agent"
---

Review against [documentation rules](../../instructions/documentation.md), [workflow rules](../../instructions/workflow.md) and the slice's spec and plan.

- Compare prose to the delivered head: remove completed [TODO.md](../../TODO.md) tasks; correct [analysis](../../docs/analysis.md) claims that code is absent or pending and spec sentences that say implemented code does not exist.
- Check plan state, unchecked boxes and completion claims against actual code, fixtures and test evidence. Preserve genuine unresolved qualification gates; a portable unit test does not prove native support.
- Rewrite every affected statement in place. Keep one home per fact, resolve relative links, use plain active voice and omit dates, change narratives and em dashes.
- Check the 400-line design/spec limit, decision IDs and links to authoritative contracts. Keep exact CI commands in [testing instructions](../../instructions/testing.md) aligned with workflows.
- Require [licensing](../../docs/licensing.md) rows and durable evidence for added dependencies. A link into an ignored directory is not reviewable license evidence from a clean checkout.
