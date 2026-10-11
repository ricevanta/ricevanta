# Ricevanta: guide for AI coding agents

Ricevanta is a free, open-source, self-hosted endpoint security and management platform: one Rust endpoint agent, one Go backend, one Vue 3 console, covering MDM, EDR, DLP, data lineage, PKI, RADIUS, unified policies and SIEM export. Apache-2.0.

This file applies to every agent (Codex, Claude Code and others) and to people. `CLAUDE.md` imports it and adds Claude Code specifics. A component directory may add its own `AGENTS.md`; `server/AGENTS.md` exists today. Every directory with an `AGENTS.md` also holds a `CLAUDE.md` containing `@AGENTS.md`, because Claude Code does not read a nested `AGENTS.md` when a `CLAUDE.md` exists above it.

## State

Implementation proceeds in reviewed slices. Each slice needs an independently reviewed design and implementation plan before code starts. Unresolved native, platform and security gates remain implementation blockers for the code that depends on them. The repository holds Go server libraries under `server/internal/`, Rust agent crates under `agent/crates/` and the static Vue console foundation under `console/`, but no releasable binary, server runtime or sensor. Brand assets and their build script remain in `branding/`.

## Map

| Question | File |
|---|---|
| What to build, technology stack | `docs/blueprint.md` (authoritative for scope) |
| Project facts: domain, hosting, license, vendor programs, languages | `docs/project.md` |
| What is hard, what depends on what, what is unspecified | `docs/analysis.md` |
| What is decided | `docs/decisions.md` (overrides the analysis where they differ) |
| What works on which OS | `docs/platform-support.md` |
| What code and rules may be used | `docs/licensing.md` |
| When | `docs/roadmap.md` |
| What is in hand right now | `TODO.md` (short-term tasks; a task leaves when committed) |
| System design | `docs/architecture.md`, then `docs/design/<domain>.md` and `docs/specs/<name>.md` |
| Implementation plans | `docs/plans/<name>.md` |
| Brand identity and assets | `branding/BRAND_SPEC.md`, `branding/README.md` |

| Doing | Read first |
|---|---|
| Any design work | `docs/blueprint.md`, the Shared (SH), Platform (PF) and domain sections of `docs/decisions.md`, `instructions/workflow.md`, then the domain's design file. The design reviewer reads all of `docs/decisions.md`. |
| Writing or changing a document | `instructions/documentation.md` |
| Reviewing, committing, reporting a task | `instructions/workflow.md` |
| Work in one domain (mdm, edr, dlp, lineage, pki, radius, policy, events, console, agent, backend, extensions) | This file, `docs/design/<domain>.md` and that domain's section of `docs/decisions.md` are the minimum domain context; component guides, language and testing instructions and the task's specs still apply. |

## Agents and models

Claude Code designs and researches; Codex implements and reviews. The owner chooses the primary session's model; this table sets the model of every subagent and worker. Among the process files (this file, `CLAUDE.md`, `instructions/` and the agent files), model ids appear only in this table and in the agent files' headers, so a model change edits those places alone.

| Role | Work | Model | Definition | Access |
|---|---|---|---|---|
| `designer` | Designs, specifications, schemas, first-party research | Claude Code `fable`, high; Codex `gpt-6-astra`, high when Fable is unavailable | `.claude/agents/designer.md`, `.codex/agents/designer.toml` | Writes `docs/`, `schemas/`, `instructions/` |
| `design_reviewer` | Independent review of designs, specifications and schemas | `gpt-6.1-sol` or `gpt-6-astra`, xhigh, never the author's model | `.codex/agents/design-reviewer.toml` | Read-only |
| `implementer` | Planning and one bounded code task with its tests | `gpt-6.1-sol`, medium | `.codex/agents/implementer.toml` | Writes the paths its brief owns |
| `code_reviewer` | Final code review, with the adversarial pass for security-relevant code | `gpt-6.1-sol` or `gpt-6-astra`, xhigh, never the author's model | `.codex/agents/code-reviewer.toml` | Read-only on sources; builds in a disposable copy |
| `explorer` | Searches, summaries, mechanical checks | `gpt-6-luna`, low | `.codex/agents/explorer.toml` | Read-only |

- No subagent or worker runs on Sonnet or Opus. When a skill names a Sonnet or Opus delegation, use the model this table gives the skill's role, and keep the skill's ownership.
- Set the model and effort explicitly on every dispatch.
- A review runs only on Sol or Astra at `xhigh`, never on Luna and never on the model that wrote the work. When no qualified reviewer is available, the work waits; it is never approved on a smaller model.
- Agents may use subagents and general-purpose agents; there is no separate researcher role. Give each worker owned paths and a separate worktree for concurrent edits. A reviewer never implements what it reviews.
- The primary agent handles Git operations under `instructions/workflow.md`; subagents never commit or push. The primary agent writes the Codex role files, because the Codex sandbox cannot write `.codex/`.
- New plans and specifications name roles, not model ids.
- Track every role file: `*.md` under `.claude/agents/` and `*.toml` under `.codex/agents/`. Every other file there, and all other local tool settings, stay ignored.

## Three rules for every task

1. Scope: every blueprint feature ships with full support at v1.0.0 on macOS ARM64, Windows x64 and Linux x64 (`docs/platform-support.md` lists the two capabilities scheduled for v2.0.0). Never propose alert-only or deferred substitutes as the end state; never drop an OS limit silently.
2. Documents describe the current state. No dates, no history, no stale statements; rewrite in place.
3. End every task by stating what was verified and how. Report failed checks as failed.
