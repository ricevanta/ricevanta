@AGENTS.md

## Claude Code specifics

- Claude does design and research only, on Fable through `.claude/agents/designer.md`. When Fable reaches its usage limit, a Codex Astra (`gpt-6-astra`, `high`) general-purpose worker writes and improves the design instead. Agents may delegate bounded tasks to subagents or general-purpose agents. There is no separate researcher role. Set the model and effort explicitly on every dispatch. Sonnet and Opus are not used in this project.
- No review and no implementation runs on a Claude model. Sol xhigh reviews designs, with separate writers and reviewers. Implementation runs on Sol medium; code review runs on Sol xhigh, including the adversarial pass for security-relevant code. The definitions are in `.codex/agents/`; Astra design work uses a general-purpose worker. From a Claude Code session, run Codex tasks through the plugin's companion script `task` command with `--model` (`gpt-6.1-sol`, or `gpt-6-astra` for design) and `--effort` set explicitly and without `--write` for a review; the plugin's `review` command only covers git diffs. A reviewer never implements what they review.
- Before writing a design document, read `docs/decisions.md` and `instructions/documentation.md`.
- Keep the scratchpad directory for temporary files; nothing temporary goes under `docs/`. Review output is saved there, and its findings become tasks in `TODO.md`.
