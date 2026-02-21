---
name: review-jira-kan
description: Review deliverables and create/update Jira tasks in KAN safely. Use when the user asks to review a scoped target and register findings as Jira tasks. Require review scope as input, check whether each finding already exists, create new tasks for new findings, and update existing tasks when needed. Always execute Jira operations according to the jira-kan skill constraints.
---

# Review to Jira (KAN)

Perform structured review and register actionable findings in Jira project `KAN` only.

## Mandatory Input

Require review scope before starting.

Scope must include at least one of:

- target files/directories
- feature/module name
- requirement/spec section
- review objective (quality, security, performance, etc.)

If scope is missing or vague, ask for clarification first.

## Safety and Project Constraint

Follow `jira-kan` skill rules for all Jira operations.

- operate only on `KAN`
- include `project = KAN` in all searches
- set `project: KAN` for all creations
- do not write to other projects

If user requests cross-project write, refuse and explain KAN-only policy.

## Review Workflow

1. Confirm review scope and success criteria.
2. Review from zero-base perspective.
3. Extract findings as independent actionable items.
4. Check each finding against existing Jira issues in `KAN`.
5. Decide action per finding:
   - new finding -> create new issue
   - existing finding -> update existing issue when needed
6. Report created/updated/skipped items with issue keys.

## Zero-Base Review Principle

Do not anchor on existing findings.

- point out problems even if prior decisions differ
- prioritize correctness over historical consistency
- explicitly flag areas that should be reconsidered from scratch

## Finding Normalization

For each finding, define:

- title (short and specific)
- problem statement
- impact/risk
- evidence (file, section, behavior)
- suggested action
- severity/priority hint

Only register findings that are actionable.

## Existing Finding Check

For each finding, search in `KAN` with project-qualified query, combining:

- key terms from title/problem
- component/module tags if available
- status constraints as needed

Treat as potential duplicate when issue intent matches substantially, even if wording differs.

If potential duplicate exists:

1. inspect the issue details
2. compare scope/impact/current status
3. decide one:
   - update existing issue (details, acceptance criteria, priority, comments)
   - keep as separate issue (only when materially different)

## Jira Action Policy

### Create New Issue

Create when no substantial duplicate exists.

Recommended defaults:

- issue type: `Task` (or `Bug` when defect is explicit)
- project: `KAN` (mandatory)
- summary: concise finding title
- description: problem, impact, evidence, proposed action

### Update Existing Issue

Update when finding matches existing issue intent.

Possible updates:

- enrich description with new evidence
- add comment with latest review context
- adjust priority/status when justified

Do not duplicate by creating parallel issues for the same problem.

## Output Format

Return concise review result with:

1. review scope used
2. findings summary (new / existing / skipped)
3. created issues: keys + summaries
4. updated issues: keys + update summary
5. reconsider-from-scratch points

## Good Requests

- "`api/auth` のレビューをして、指摘をKANに起票して"
- "要件書3章をレビューし、既存指摘と重複確認してKANを更新して"

## Bad Requests

- "全部見て適当に起票して" (scope missing)
- "他プロジェクトにも同時に起票して" (policy violation)
