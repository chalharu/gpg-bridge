# Contributing

This document is the source of truth for contribution rules.

## 1. CLA (Copyright Assignment)

This project requires all contributors to agree to a Contributor License Agreement (CLA) before their pull requests can be merged. By submitting a pull request, you will be prompted (via CLA Assistant) to review and sign the CLA. **Pull requests cannot be merged until the CLA is signed.**
See the full CLA text in [CLA.md](CLA.md).

## 2. Development Flow

1. Create or pick an issue.
2. Create a branch from `main`.
3. Implement changes and add/update tests.
4. Commit using Conventional Commits.
5. Open a pull request.
6. Address review feedback and merge.

## 3. Branch Rules

- `main`: always releasable.
- Working branches: `feature/<topic>`, `fix/<topic>`, `chore/<topic>`.
- Direct push to `main` is not allowed.

## 4. Commit Message Rules (Conventional Commits)

Format:

`<type>(<scope>): <subject>`

Examples:

- `feat(api): add user profile endpoint`
- `fix(parser): handle empty input`
- `docs(readme): clarify setup steps`
- `chore(ci): update workflow cache key`

Types:
- `feat`: new feature
- `fix`: bug fix
- `docs`: documentation only
- `refactor`: code change without behavior change
- `test`: tests
- `chore`: maintenance/configuration

## 5. Pull Request Process

Each PR should include:

- Why (motivation)
- What (summary of changes)
- How to test
- Impact scope
- Related issue (e.g., `Closes #123`)

Checklist:

- [ ] CLA accepted
- [ ] Tests pass
- [ ] Breaking changes are clearly described
- [ ] Required documentation is updated
