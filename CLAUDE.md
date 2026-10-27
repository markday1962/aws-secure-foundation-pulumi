# CLAUDE.md

Guidance for Claude Code (and anyone else) working in this repository. The
README explains what the infrastructure is; this file is how to work on it.

## Layout

Two independent Pulumi (Python) projects, each its own uv project with
`__main__.py`, components in `src/` and pytest tests in `tests/`:

- `account-baseline/`: once per account (CloudTrail, Config, GuardDuty,
  Security Hub, alerting, hardening). Deployed before `network`, and outlives it.
- `network/`: the VPC and everything in it, the ALB and the WAF.

## Checks

```sh
make install   # uv sync in each project
make test      # pytest; Pulumi mocks, no AWS access needed
make lint      # ruff format --check, ruff check, pyright
```

All three must pass before a change is done. CI (`.github/workflows/ci.yml`)
runs the same checks per project, and both checks are required to merge.
Validate workflow edits with `actionlint` and `zizmor`. A commented-out job
isn't linted, so lint an uncommented copy.

## Workflow

- `main` is protected by a ruleset: changes only through a pull request with
  the `account-baseline` and `network` checks green and the branch up to date.
  No force pushes; no approvals are needed (a solo repo).
- Branch from an up-to-date `main` (`feat/…`, `chore/…`), one commit per
  logical step, then open a PR, wait for CI, merge with a **merge commit**
  (not squash), confirm CI passes on `main`, and delete the branch.
- `/ship` (`.claude/skills/ship/SKILL.md`) runs that whole sequence for the
  current branch; `/ship review` stops once CI passes, before merging.
- Commit, push, open PRs and merge only when asked.
- The repository is **public**: never commit real account IDs, secrets,
  passphrases or state. The `111111111111` account and `example.com` domain
  in the stack config are placeholders.

## AWS and Pulumi

- Nothing is deployed from here without being asked. Treat `pulumi up`,
  `destroy`, `refresh`, `import`, `cancel`, `state …` and `stack rm/import`
  as needing explicit confirmation every time. `pulumi preview` is read-only.
- State is `pulumi login --local` for now. The CI `preview` job is written
  but commented out until an AWS account, an OIDC role and an S3 state
  backend exist (see the comment above it).
- The network VPC is created with `protect=True`. Removing it needs
  `pulumi state unprotect --all` first; never do that unprompted.

## Code conventions

- **Feature flags** (`network/src/features.py`): every part of the network is
  off by default and switched on in `network/Pulumi.dev.yaml`. A new part gets
  a flag in `Features`, its dependencies in `__post_init__`'s requirements, a
  `network/__main__.py` config read, an entry in `Pulumi.dev.yaml` and the
  README's "Controlled deployment" table, and tests for it on, off and with
  a dependency missing.
- Components are `pulumi.ComponentResource` subclasses taking a frozen
  `…Args` dataclass. Validate arguments in the constructor with a clear
  `ValueError` before creating resources.
- IAM, KMS, bucket and endpoint policies go through `policy_document` /
  `Statement` (`src/policy.py`), scoped with `aws:SourceAccount`,
  `aws:SourceArn` or `aws:PrincipalAccount` where the service supports it.
- Physical names start with the component name (`learning-<stack>-…`), so
  stacks can share an account; stack names are 1-10 characters.
- Tests use the mocks in `tests/conftest.py` and the `registered()`,
  `find()` and `all_of()` helpers to assert on resource inputs. Give each
  test build its own name prefix rather than depending on another test's
  resources.
- Comments explain *why*; match the existing density. Keep the README, the
  stack config comments and the code in step with each other, including test
  counts and costs.
