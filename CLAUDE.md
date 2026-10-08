@AGENTS.md

## Claude Code specifics

- Design and review work use Opus; implementation uses Sonnet; searches and summaries use Haiku. Set the model explicitly on every subagent.
- Before writing a design document, read `docs/decisions.md` and `instructions/documentation.md`.
- Keep the scratchpad directory for temporary files; nothing temporary goes under `docs/`.
