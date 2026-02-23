---
name: resolve-jira-kan-issue
description: Resolve a Jira issue end-to-end from ISSUEID input. Use when the user asks to implement and complete a Jira issue, including clarification dialogue, code changes, commit, and pull request. Always operate on KAN project issues only, follow jira-kan for Jira operations, follow git-commit for commit execution, and follow CONTRIBUTING.md for branch and PR rules.
---

# Resolve Jira Issue (KAN)

Resolve one Jira issue from input `ISSUEID` through implementation, commit, and PR.

## Input

Required input:

- `ISSUEID` (e.g., `KAN-123`)

If missing, ask for it before any action.

## Scope and Safety

- Target project is only `KAN`.
- Reject non-`KAN-*` issue keys.
- Use `jira-kan` skill rules for all Jira reads/writes.
- For searches, always include `project = KAN`.

## Docker Execution Rule

All work (implementation, tests, format, lint, static analysis, coverage, and Git operations) **must** run inside a Docker container.

- Build the image once if not already built: `docker build -t gpg-bridge-dev .` (from the worktree root).
- Run every command via: `docker run --rm -v "$PWD:/workspace" -w /workspace gpg-bridge-dev <command>`.
- For Git operations that need user identity, add: `-v "$HOME/.gitconfig:/root/.gitconfig:ro"`.
- Never install or run Rust/Flutter/cargo tools directly on the host.
- **Exception:** Worktree management (`git worktree add/remove`) and `git push` run on the host since they manage the host filesystem and require host credentials.

## End-to-End Workflow

1. Validate `ISSUEID` and fetch issue details.
2. Confirm problem statement, acceptance criteria, and constraints.
3. If missing/ambiguous, ask the user and resolve via dialogue before coding.
4. Create a **git worktree** inside the repository's `work/` directory to isolate work from the existing environment:
   - If `work/` directory does not exist, create it and add `work/.gitignore` containing `*` to prevent tracking worktree contents.
   - Run `git worktree add work/<issueid> -b <branch> main` to create a separate working directory (e.g., `work/kan-123`).
   - All subsequent implementation and checks must run inside this worktree, not the original repository.
   - Branch naming follows `CONTRIBUTING.md` and always includes `ISSUEID`:
     - `feature/<issueid>-<topic>` for feature work (e.g., `feature/kan-123-add-auth`)
     - `fix/<issueid>-<topic>` for bug fix (e.g., `fix/kan-123-token-expiry`)
     - `chore/<issueid>-<topic>` for maintenance (e.g., `chore/kan-123-update-docs`)
5. Build the Docker image if needed: `docker build -t gpg-bridge-dev .` (run from the worktree root).
6. Transition the Jira issue status to `進行中`.
7. **Implement** required changes using a subagent (the "implementation agent").
   - The implementation agent must aim for **global optimization**, not minimal or narrowly scoped changes. Consider the overall codebase health, consistency, and design when making changes.
   - All commands (edit verification, build, etc.) run inside Docker.
8. **Quality gate** (run by the implementation agent inside Docker before requesting review):
   - Always run format/lint, static analysis, tests, and coverage commands for the changed area.
   - For Rust changes: `docker run --rm -v "$PWD:/workspace" -w /workspace gpg-bridge-dev sh -c "cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo llvm-cov --workspace --summary-only"`.
   - For Flutter changes: `docker run --rm -v "$PWD:/workspace" -w /workspace gpg-bridge-dev sh -c "cd mobile && dart format --output=none --set-exit-if-changed lib test && flutter analyze && flutter test --coverage"`.
   - If coverage is low for the changed area, add/adjust tests and re-run until coverage improves.
   - All checks must pass before proceeding to review.
9. **Review** using a **different** subagent (the "review agent").
   - The review agent must **never modify code**. It only inspects and reports findings.
   - If issues are found, the review agent returns a detailed list of required fixes and **rejects** (sends back) the work to the implementation agent.
   - **Post review findings to Jira**: After the review agent completes its review, post a summary of all findings (severity, category, description) as a Jira comment on the issue. This applies to both rejection and approval cases, so that the review history is traceable in Jira.
10. **Rework loop**: If the review agent rejects:
    - The implementation agent fixes all reported issues.
    - Re-run the quality gate (step 8).
    - Re-submit to the review agent (step 9).
    - Repeat until the review agent approves with no remaining issues.
11. Commit changes using `git-commit` skill workflow (Git commands run inside Docker).
12. Push the branch to the remote: `git push -u origin <branch>` (runs on the host — requires host credentials).
13. Create pull request following `CONTRIBUTING.md` PR template requirements.
14. Report summary and PR URL.
15. Clean up: remove the git worktree (`git worktree remove work/<issueid>`) and return to `main` branch.

## Clarification Dialogue Rules

When issue details are insufficient, ask targeted questions such as:

- expected behavior and non-goals
- edge cases and failure behavior
- compatibility or migration constraints
- deadline/priority trade-offs

Do not proceed with implementation until required unknowns are resolved.

## Jira Handling Rules

- Read issue content, comments, and status before implementation.
- When work begins, transition the issue to `進行中`.
- If scope needs refinement, add concise Jira comment in `KAN`.
- When work is ready for review, update Jira with PR link and summary.
- After each review round, post review findings (severity, file, description) as a Jira comment for traceability.
- When posting Jira comments via `mcp_com_atlassian_addCommentToJiraIssue`, always pass `commentBody` with **actual newline characters** (not escaped `\n` literals). Escaped sequences render as literal text and break formatting.
- Never update issues outside `KAN`.

## Quality Standards

- **Review findings**: Address ALL findings up to and including INFO level. No finding may be left unresolved.
- **Commit granularity**: Split commits appropriately. Each commit should be roughly tens of lines to 200 lines of diff. Do not bundle unrelated changes.
- **File and function size**: Keep functions/methods around 20–30 lines. Keep files around 200 lines (excluding test code). Split when exceeding these guidelines.
- **Test coverage**: Maintain at least 80 % line coverage for the changed area. Add or adjust tests until this threshold is met.

## Commit Rules

Use `git-commit` skill and `CONTRIBUTING.md` Conventional Commits format:

`<type>(<scope>): <subject>`

Allowed types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`.

Prefer one logical change per commit; avoid mixed-purpose commits. Each commit should be roughly tens of lines to 200 lines of diff.

## Pull Request Rules

Follow `CONTRIBUTING.md` exactly.

GitHub operations (PR create/update/comment/search, issue comments, merge checks) must use GitHub MCP tools (`mcp_io_github_*`) only. Do not use `gh` CLI for GitHub interactions.

PR body must include:

- Why (motivation)
- What (summary of changes)
- How to test
- Impact scope
- Related issue (e.g., `Closes KAN-123`)

Ensure branch is not `main` and direct push to `main` is never used.

## Output Format

At completion, provide:

1. Resolved issue key
2. Implemented change summary
3. Commit hash and message
4. PR URL
5. Remaining risks or follow-ups
