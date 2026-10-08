# Ricevanta: guide for AI coding agents

Ricevanta is a free, open-source, self-hosted endpoint security and management platform: one Rust endpoint agent, one Go backend, one Vue 3 console, covering MDM, EDR, DLP, data lineage, PKI, RADIUS, unified policies and SIEM export. Apache-2.0.

This file applies to every agent (Codex, Claude Code and others) and to people. `CLAUDE.md` imports it and adds Claude Code specifics. Component directories get their own `AGENTS.md` when they exist.

## State

Design phase. No application code. Work happens in `docs/`. Code directories are created when their design document exists.

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
| System design | `docs/architecture.md`, then `docs/design/<domain>.md` and `docs/specs/<name>.md` |

| Doing | Read first |
|---|---|
| Any design work | `docs/blueprint.md`, `docs/decisions.md`, `instructions/workflow.md`, then the domain's design file |
| Writing or changing a document | `instructions/documentation.md` |
| Reviewing, committing, reporting a task | `instructions/workflow.md` |
| Work in one domain (mdm, edr, dlp, lineage, pki, radius, policy, events, console, agent, backend) | This file, `docs/design/<domain>.md`, that domain's section of `docs/decisions.md`. Nothing else is required. |

## Three rules for every task

1. Scope: every blueprint feature ships with full support at v1.0.0 on macOS ARM64, Windows x64 and Linux x64 (`docs/platform-support.md` lists the two capabilities moved to v2.0.0). Never propose alert-only or deferred substitutes as the end state; never drop an OS limit silently.
2. Documents describe the current state. No dates, no history, no stale statements; rewrite in place.
3. End every task by stating what was verified and how. Report failed checks as failed.
