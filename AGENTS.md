# Repository instructions

Follow [CONTRIBUTING.md](./CONTRIBUTING.md) for issues, pull requests,
and local gates. Use [README.md](./README.md) for the
package overview, and [REPOSITORY.md](./REPOSITORY.md) before changing
workflows or settings.
See [SECURITY.md](./SECURITY.md) for vulnerability reporting.

When an agent works here, a separate worktree per task keeps your own
checkout clean: hooks and agents change files where they run. For
example, `git worktree add ../<name> origin/main -b <branch>`, and
`git worktree remove ../<name>` when done.

Choose the least capable model that can reliably complete the task: use
a fast model for straightforward execution, a reasoning-focused model
for multi-step work, and the most capable available model for difficult
or ambiguous problems. Increase capability if progress stalls.

## Code Review Rules

Review against [REVIEWING.md](./REVIEWING.md). Its *The verdict* says
which review opens with a verdict line and what every other review
posts.

The heading is the one Codex's GitHub review asks for
([Customize what Codex reviews](https://learn.chatgpt.com/docs/third-party/github#customize-what-codex-reviews)).
