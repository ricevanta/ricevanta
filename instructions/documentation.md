# Writing documents

Applies to `docs/`, `instructions/` and the root guide files.

## Where things go

| Content | Location |
|---|---|
| Product requirements | `docs/blueprint.md` |
| Project facts (domain, hosting, license, vendor programs, languages) | `docs/project.md` |
| Conflicts, dependencies, open specifications | `docs/analysis.md` |
| Decisions | `docs/decisions.md` |
| Targets, version floor, capability matrix | `docs/platform-support.md` |
| Third-party licenses | `docs/licensing.md` |
| Milestones | `docs/roadmap.md` |
| Short-term tasks in hand | `TODO.md` at the repository root; one line per task, removed when committed |
| System design | `docs/architecture.md` |
| Per-domain design and domain-specific rules | `docs/design/<domain>.md` |
| Schemas and protocols | `docs/specs/<name>.md`; machine-readable files in `schemas/` |
| Implementation plans | `docs/plans/<name>.md` |
| How to work | `instructions/<topic>.md` |

Create a directory with its first real file. No placeholders.

## Rules

- Current state only. No dates, no "decided on", no changelog, no "previously". Git history records change.
- When something changes, rewrite every statement it affects, in every file that repeats it. Prefer one home per fact and links from elsewhere.
- Lead with the point. Short paragraphs. Tables for comparisons across the same criteria; bullets for parallel items; prose for reasoning. No em dashes.
- One file per question. A design document links to the blueprint instead of restating it.
- Mark claims from vendor or forum sources rather than first-party documentation with "verify".
- Keep files short enough to read in full: a design document or specification has at most 400 lines. Split by domain when a file serves more than one domain. When a file would pass the limit, split it into two files along its sections and link them; never cut wording that carries information to stay under the limit.

## Decision entries

`docs/decisions.md` is a register of decisions in force, grouped by domain. Each entry:

```
### PREFIX-nn. Title
Decision: one to three sentences.
Why: one sentence, with the analysis finding (Cnn) where one exists.
Rejected: the alternative and why, one sentence.
Detail: link to the design document, when one exists.
```

Prefixes: SH (shared), PF (platform), AG (agent), BE (backend and console), MDM, EDR, DLP, LIN (lineage), PKI, RAD (RADIUS), POL (policy), EV (events), EXT (extensions). IDs are stable and never reused. A changed decision is rewritten in place. A withdrawn decision is removed and its ID is not reused. Design detail belongs in the design document, not in the entry.
