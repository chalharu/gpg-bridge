---
name: jira-kan
description: Operate Jira safely for a single project only. Use when the user asks to search, create, update, comment, transition, or inspect Jira issues in project KAN at https://chalharu.atlassian.net/jira/software/projects/KAN/. Always scope all operations to KAN and refuse writes to other projects.
---

# Jira KAN Project Operator

Operate Jira with strict project isolation.

## Scope Lock (Mandatory)

Target project is only:

- Project key: `KAN`
- URL: `https://chalharu.atlassian.net/jira/software/projects/KAN/`

Never perform write operations outside `KAN`.

## Safety Rules

1. Include `project = KAN` in every issue search.
2. Specify `project: KAN` for every issue creation.
3. Before update/comment/transition, verify the issue belongs to `KAN`.
4. If the user request is ambiguous about project, ask and default to `KAN` only.
5. Reject any request to write to non-`KAN` projects.

## Standard Workflow

1. Confirm operation intent (search/create/update/comment/transition).
2. Confirm target is `KAN`.
3. Execute with project constraint.
4. Return concise result and affected issue keys.

## Operation Patterns

### Search

Always use project-qualified filters.

Good:

- `project = KAN AND type = Bug`
- `project = KAN AND statusCategory != Done`
- `project = KAN AND assignee = currentUser()`

Bad (forbidden):

- `type = Bug`
- `statusCategory != Done`
- `assignee = currentUser()`

## Create

Always set project explicitly:

- `project: KAN`

Allowed example:

- "Create a new story in KAN"

Forbidden example:

- "Create a new issue" (no project)

## Update / Comment / Transition

Before writing:

1. Fetch issue details.
2. Verify the issue key starts with `KAN-` or issue project is `KAN`.
3. Only then proceed.

If the issue is not in `KAN`, stop and explain that cross-project writes are not allowed.

### Atlassian MCP commentBody Formatting

When using `mcp_com_atlassian_addCommentToJiraIssue`, the `commentBody` parameter must contain **actual newline characters**, not escaped `\n` literals. Escaped `\n` sequences are rendered as literal text in Jira, breaking the comment formatting.

- Good: Pass a multi-line Markdown string directly (the tool parameter value naturally contains real newlines).
- Bad: Concatenate strings with `\n` — these become literal backslash-n in the comment.

## Response Style

When operation succeeds, report:

1. action performed
2. issue keys affected
3. exact project scope used (`KAN`)

When rejected by policy, clearly state:

- operation blocked by project isolation rule
- only `KAN` is allowed
- ask user to restate request within `KAN`
