---
name: pr-green-loop
description: Commit and push prepared repository changes, monitor the resulting pull-request checks, diagnose failures from their logs, fix them, and repeat until the latest commit is green. Use when the user explicitly requests this delivery loop for a branch or pull request.
---

# PR Green Loop

Drive the current change through its pull-request pipeline until every required check passes for the latest head commit.

## Authorization and scope

Run mutating steps only when the user explicitly asks to commit and push or explicitly invokes `$pr-green-loop` with
that intent. Loading this skill automatically does not itself authorize staging, committing, pushing, creating a pull
request, or changing external state.

Use the current repository, branch, remote, and open pull request unless the user names different targets. Read and
follow the repository's contributor instructions. Preserve the requested behavior and do not weaken tests, coverage
thresholds, security checks, or branch protections merely to make the pipeline pass.

## Loop

1. Inspect the worktree, current branch, remote tracking state, diff, and relevant pull request. Check for accidental
   generated files, secrets, unrelated edits, and stale names or paths introduced by renames.
2. Run the repository's required pre-commit verification after the final edit. If local instructions define a complete
   sequence, run that exact sequence. Any subsequent tracked edit invalidates it.
3. Stage only the intended files, review the staged diff, create a focused commit, and push the current branch. Do not
   force-push or rewrite history unless the user explicitly requests it.
4. Record the pushed commit SHA. Discover workflow runs and external checks for that exact SHA; ignore results from
   superseded commits. Keep the user informed while checks run.
5. Wait for all required jobs and asynchronous external services such as Codecov to finish. A workflow completing does
   not prove that delayed check suites have reported their final result.
6. If a check fails, inspect its job log, annotations, and detailed check output. Identify the concrete cause before
   editing. Reproduce it locally when practical, including the relevant operating system, runtime version, display,
   filesystem, network, or coverage conditions.
7. Make the smallest complete fix. Add or adjust meaningful tests when behavior changed; do not edit assertions solely
   to conceal a defect or platform incompatibility. Rerun focused checks while iterating, then repeat the repository's
   full required pre-commit sequence.
8. Commit and push the fix, then return to step 4 for the new SHA.

## Completion and stopping

Finish only when every required workflow and external status passes for the latest pushed SHA, the branch is synced
with its remote, and the intended worktree is clean. Update an existing pull-request description when its validation
counts, commands, paths, or final behavior became stale.

Stop and report a blocker when progress requires unavailable credentials, an unauthorized destructive action, a user
product decision, or an external service change. After three materially identical failures with no new evidence or
safe corrective action, stop retrying and explain the repeated blocker.

Report the pull request, final commit SHA, fixes made, verification performed, and final check results.
