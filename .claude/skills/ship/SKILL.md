---
name: ship
description: Ship the current feature branch through this repo's PR workflow - checks, rebase on main, push, open a PR, wait for CI, merge with a merge commit, confirm CI on main, delete the branch. Pass "review" to stop before merging.
argument-hint: "[review]"
disable-model-invocation: true
---

# /ship

Takes the current feature branch from local commits to merged on `main`,
following CLAUDE.md's workflow. Stop at the first failure and report it: never
retry blindly, force-push over someone else's work, bypass the ruleset or
disable a check. Never run `pulumi` commands.

If `$ARGUMENTS` is `review`, stop after step 6 and give the PR link instead of
merging.

The repository is `markday1962/aws-secure-foundation-pulumi`. Write PR bodies
to a file in the scratchpad and pass `--body-file`; macOS bash 3.2 mis-parses
apostrophes in a heredoc inside `$(…)`.

## 1. Preconditions

- The current branch must not be `main`. If it is, stop and ask for a branch
  name; don't commit to `main` (the ruleset would refuse the push anyway).
- If there are uncommitted changes, show `git status --short` and ask whether
  to commit them (and with what message) before going on. Don't commit
  unrelated files.
- There must be at least one commit ahead of `origin/main`; otherwise there's
  nothing to ship.

## 2. Local checks

Run `make test` and `make lint` from the repo root. Both must pass. Report the
test counts per project.

## 3. Bring the branch up to date

`git fetch origin`, then `git rebase origin/main` if the branch is behind.
On a conflict, stop and show it; don't resolve it unasked. If the rebase
changed anything, rerun step 2.

## 4. Push

`git push -u origin <branch>`. If the branch was already pushed and the
rebase rewrote it, use `git push --force-with-lease`, and only for this
feature branch.

## 5. Open the pull request

If the branch already has an open PR, reuse it. Otherwise
`gh pr create --base main --head <branch>` with:

- a title from the commits (one commit: its subject line)
- a body that says what changed and why, then a `## Testing` section with the
  local results from step 2 and anything not verified (e.g. "Not yet
  deployed"), ending with the attribution line from the session's
  instructions

## 6. Wait for CI

`gh pr checks <pr> --watch`, then list the results. The required checks are
`account-baseline` and `network`. Confirm from the run's log that pytest
actually ran (the `N passed` lines), and check
`gh pr view <pr> --json mergeStateStatus` is `CLEAN`. If anything failed,
stop and show the failing job's log; don't merge.

In `review` mode, stop here: report the PR link and the check results.

## 7. Merge

`gh pr merge <pr> --merge` (a merge commit, never squash or rebase). Note the
merge commit SHA.

## 8. Confirm CI on main

Find the CI run for that exact merge commit (`gh run list --branch main
--commit <sha>`; it can take a moment to appear) and `gh run watch` it. If it
fails, report it straight away: `main` is broken.

## 9. Tidy up

- Switch to `main` and `git pull --ff-only`.
- Confirm the branch has no commits missing from `origin/main` (locally and on
  GitHub), then delete it on GitHub and locally with `git branch -d`, never
  `-D`. Prune remote-tracking branches.

## 10. Report

Give a short summary: the PR link, the checks and test counts, the merge
commit, the result on `main`, and that the branch was deleted.
