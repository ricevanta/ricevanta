# Ricevanta: guide for AI coding agents

Ricevanta is a free, open-source, self-hosted endpoint security and management platform: one Rust endpoint agent, one Go backend, one Vue 3 console, covering MDM, EDR, DLP, data lineage, PKI, RADIUS, unified policies and SIEM export. Apache-2.0.

This file applies to every agent (Codex, Claude Code and others) and to people. `CLAUDE.md` imports it and adds Claude Code specifics. Component directories get their own `AGENTS.md` when they exist.

## State

Implementation proceeds in reviewed slices. Each slice needs an independently reviewed design and implementation plan before code starts. Unresolved native, platform and security gates remain implementation blockers for the code that depends on them. The repository contains initial Go server libraries, but no releasable binary, Rust agent or Vue console. Brand assets and their build script remain in `branding/`.

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
| Any design work | `docs/blueprint.md`, `docs/decisions.md`, `instructions/workflow.md`, then the domain's design file |
| Writing or changing a document | `instructions/documentation.md` |
| Reviewing, committing, reporting a task | `instructions/workflow.md` |
| Work in one domain (mdm, edr, dlp, lineage, pki, radius, policy, events, console, agent, backend, extensions) | This file, `docs/design/<domain>.md`, that domain's section of `docs/decisions.md`. Nothing else is required. |

## AI agent definitions

| Tool | Where | Agents |
|---|---|---|
| Claude Code | `.claude/agents/` | `designer` (Fable) |
| Codex | `.codex/agents/` | `design_reviewer` (Sol xhigh, read-only), `implementer` (Sol medium), `code_reviewer` (Sol xhigh, read-only, including adversarial review) |

Claude Code handles design and research only, on Fable. When Fable reaches its usage limit, Astra writes and improves designs in a separate general-purpose worker. Sol xhigh reviews designs, with an independent reviewer for every fix. Sol xhigh reviews code, including the adversarial pass, and Sol medium implements code. Agents may use subagents and general-purpose agents; there is no separate researcher role. Set the model and effort explicitly on every dispatch: `gpt-6-astra` at `high` for design when Fable is unavailable, `gpt-6.1-sol` at `medium` for planning and implementation, `gpt-6.1-sol` at `xhigh` for every review and fix confirmation, and `gpt-6-luna` at `low` for exploration and mechanical work. No work runs on Sonnet or Opus; map a skill's Sonnet or Opus delegation to Sol medium while preserving ownership. Give each worker owned paths and use separate worktrees for concurrent edits. A reviewer never implements what they review. The primary agent handles Git operations under `instructions/workflow.md`; subagents never commit or push.

Track the agent definitions listed above under `.claude/agents/` and `.codex/agents/`. Keep other local tool settings ignored.

## Three rules for every task

1. Scope: every blueprint feature ships with full support at v1.0.0 on macOS ARM64, Windows x64 and Linux x64 (`docs/platform-support.md` lists the two capabilities scheduled for v2.0.0). Never propose alert-only or deferred substitutes as the end state; never drop an OS limit silently.
2. Documents describe the current state. No dates, no history, no stale statements; rewrite in place.
3. End every task by stating what was verified and how. Report failed checks as failed.
