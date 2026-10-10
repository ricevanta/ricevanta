@AGENTS.md

## Claude Code specifics

- Claude does design and research only. `.claude/agents/designer.md` uses Fable for architecture and security-critical design, with Opus for other design, specs and research. Agents may delegate bounded tasks to subagents or general-purpose agents. There is no separate researcher role. Set the model and effort explicitly on every dispatch. Sonnet is not used in this project.
- No review and no implementation runs on a Claude model. Sol medium improves designs and Sol xhigh reviews them, with separate writers and reviewers. Implementation runs on Sol medium; code review runs on Sol xhigh, including the adversarial pass for security-relevant code. The definitions are in `.codex/agents/`; design improvements use a general-purpose worker. From a Claude Code session, run Codex tasks through the plugin's companion script `task` command with `--model` (`gpt-5.6-sol`) and `--effort` set explicitly and without `--write` for a review; the plugin's `review` command only covers git diffs. A reviewer never implements what they review.
- Before writing a design document, read `docs/decisions.md` and `instructions/documentation.md`.
- Keep the scratchpad directory for temporary files; nothing temporary goes under `docs/`. Review output is saved there, and its findings become tasks in `TODO.md`.
