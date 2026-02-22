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

## End-to-End Workflow

1. Validate `ISSUEID` and fetch issue details.
2. Confirm problem statement, acceptance criteria, and constraints.
3. If missing/ambiguous, ask the user and resolve via dialogue before coding.
4. Create working branch from `main` according to `CONTRIBUTING.md`:
   - `feature/<topic>` for feature work
   - `fix/<topic>` for bug fix
   - `chore/<topic>` for maintenance
5. Start implementation and immediately transition the Jira issue status to `進行中`.
6. Implement minimal required changes in repository.
7. Run relevant tests/build checks for changed area.
8. Commit changes using `git-commit` skill workflow.
9. Create pull request following `CONTRIBUTING.md` PR template requirements.
10. Report summary and PR URL.

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
- Never update issues outside `KAN`.

## Commit Rules

Use `git-commit` skill and `CONTRIBUTING.md` Conventional Commits format:

`<type>(<scope>): <subject>`

Allowed types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`.

Prefer one logical change per commit; avoid mixed-purpose commits.

## Pull Request Rules

Follow `CONTRIBUTING.md` exactly.

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
