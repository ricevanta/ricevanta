@AGENTS.md

## Claude Code specifics

- Claude does design and research only, through `.claude/agents/designer.md`. No review and no implementation runs on a Claude model: dispatch those roles to Codex with the model and effort the table in `AGENTS.md` ("Agents and models") gives them. Subagents and workers never run on Sonnet or Opus; the owner chooses the primary session's model.
- Before writing a design document, read `instructions/documentation.md` and the Shared, Platform and domain sections of `docs/decisions.md`.
- Keep the scratchpad directory for temporary files; nothing temporary goes under `docs/`. Review output is saved there, and its findings become tasks in `TODO.md`.

## Running Codex from Claude Code

- Start a Codex job with the Codex plugin's companion script, from the worktree that owns the job: `node "$(ls -d ~/.claude/plugins/cache/openai-codex/codex/*/ | sort -V | tail -1)scripts/codex-companion.mjs" task --background [--write] --fresh --model <model> --effort <effort> --prompt-file <file>`. `status <job-id>` and `result <job-id>` only find jobs started from the same directory. The plugin's `review` command covers Git diffs only. The concurrency cap and the landing procedure are in `instructions/workflow.md`.
- In companion 1.0.6, `task --resume-last` selects the eligible task job in the workspace with the latest update time, filtering to the current Claude session when known; without a session, it considers all workspace jobs and falls back to the latest matching task thread if none is eligible. Selection ignores model and sandbox and can resume a reviewer launched through `task`, so start the author with `--fresh` and the full brief.
- Follow the [shared brief and conflict rules](instructions/workflow.md#parallel-slices-and-ci).
- A Codex job started from Claude Code does not load `.codex/agents/<role>.toml`; Codex loads role files only for subagents it spawns itself. Start the prompt file with the role's `developer_instructions`, or pass them to `codex exec` with `-c developer_instructions=<TOML string>`. A Codex role's pinned model overrides the model a spawn names, so a fallback model runs as a general worker carrying the role's instructions.
- Codex's content filter can stop a job whose prompt reads like attack instructions. Phrase a security check as a property to verify, in neutral wording.
- The read-only sandbox cannot build Go or Rust. Run a code review with `--write` in a disposable copy of the worktree without `.git`, placed outside every Git working tree (the companion resolves its workspace with `git rev-parse --show-toplevel`), plus a `CHANGES.txt` holding the base commit, the tracked diff, the untracked files and the CI results. Design reviews stay read-only.
- The sandbox has no network. Prefetch pinned crates (`cargo fetch` in a scratch project) and run `pnpm install` yourself before an implementer needs them, then tell it to work offline. For Codex role-file changes, follow the [write restriction in AGENTS.md](AGENTS.md#agents-and-models): the worker writes the complete draft to a file under `/tmp` and the primary agent installs it.
- Each finished job leaves its companion broker running, and idle brokers fill memory. Stopping one is optional and allowed only for a worktree this session created and is removing, after its last job finished; the companion's `status` lists only this session's jobs, so it cannot prove a broker idle anywhere else. Never stop a broker in any other directory.
- After reading each job's result, delete its disposable review copy and per-job Go build cache to keep local memory and disk use low.

## Shell gotchas

- `pkill -f <pattern>` also matches the shell running the command when its command line contains the pattern, because `-f` matches the [full command line](https://gitlab.com/procps-ng/procps/-/blob/master/man/pgrep.1). Stop processes by PID.
