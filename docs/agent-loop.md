# Agent loop operator guide

The agent loop moves work from GitHub issue to review-ready pull request. A repository administrator only creates (or
receives) issues, approves or revises each issue's analysis, and reviews the final pull request. The design and rollout
plan are in [agent-loop-plan.md](agent-loop-plan.md).

## Current status

Implemented:

- **Phase 1 (foundations):** configuration with precedence and implementation/review model-separation rules; GitHub
  App authentication, with every GitHub call made through the GitHub CLI; administrator-only trigger authorization and
  analysis-approval binding; the label state machine; the subscription quota ledger and failure classifier; the GitHub
  notifier, label bootstrap, `doctor`, `status`, `pause`, and `resume`.
- **Phase 2 (analysis and approval):** the read-only issue analysis stage, the `issue-analysis` skill, `/approve` and
  conversational revisions (any administrator comment, `/revise`, or a mention of the bot), reporter follow-up for `agent:needs-info`, quota pauses with a status comment, and
  administrator notification.
- **Phase 3 (implementation):** after `/approve`, the implementation stage builds the change on an `agent/issue-<n>-*`
  branch, the dispatcher verifies it, applies the diff policy, pushes it, and opens a draft pull request; each tick then
  watches CI, repairs failures, and marks the pull request ready for AI review once the required checks pass.
- **Phase 4 (review and feedback):** a model distinct from the authors reviews each green pull request against the
  approved analysis; blocking findings go back to the author model, which fixes, declines, or escalates each one and
  replies in the review threads. Once a review has no blocking findings, you are asked to review the pull request.
  Your own "Request changes" review goes through the same feedback loop.

Unattended operation (the systemd timer) arrives in Phase 5; until then, run `tick` yourself or in a shell loop.

## Administrator workflow

| Where | Action | Effect |
| --- | --- | --- |
| Issue | Create an issue (or let others create one) | The loop analyzes it and labels it `agent:awaiting-approval` |
| Issue | Comment `/approve` as the first line | Implementation starts from the approved analysis |
| Issue | Comment anything else (a question, a change request, an answer to the analysis's open questions) | The bot reacts with 👀, waits until you have been quiet for `revision_debounce_minutes` (default 5), then posts one revised analysis covering all your comments |
| Issue | Mention the bot (`@imap-tools-agent can you reconsider…`) or start with `/revise <notes>` | The same revision, started on the next tick without waiting |
| Issue | Start a comment with `/note` | The comment is kept as context but never triggers a revision, for example when talking to a collaborator |
| Issue | Close the issue | The loop stops |
| Issue | Reply `/approve` | The issue becomes `agent:implementing`; a draft PR with `Closes #<n>` appears when the change is verified |
| Pull request | Wait | CI runs on each push; failures are repaired automatically (up to `max_ci_fix_attempts`); the PR is marked ready and labeled `agent:ai-review` when the required checks pass |
| Pull request | Wait | A different model reviews it; blocking findings are addressed and re-reviewed (up to `max_ai_review_rounds`), then the PR is labeled `agent:ready-for-admin` and you are requested as reviewer |
| Pull request | Approve and merge, or close | Done. The bot authored the PR, so your approval satisfies the branch rules without `--admin` |
| Pull request | Submit a "Request changes" review (summary and/or inline comments) | The loop addresses each comment, replies to it, and returns the PR through CI and AI review to you |
| Issue or PR | Apply `agent:paused` | The loop leaves the item alone until you remove the label |
| Existing issue or PR | Apply `agent:adopt` | Opts in an item created before `enabled_since` (or a PR the loop did not create) |

Only users with the repository **Admin** role count. Commands and `agent:*` label changes from anyone else are
ignored or reverted, and the bot replies once to say so. Comments from other people are never a trigger, even when
they mention the bot, but the model still reads them as context. `/approve` is always explicit: it must be the first
line of a comment, it wins over plain comments written around it, and only a later `/revise` overrides it. A
malformed command such as `/approve now` is ignored, never read as feedback. Comments must not have been edited by
anyone other than an administrator, and apply only to the analysis they follow, including comments written while the
analysis was still running. If the issue or the analysis changes afterwards, the loop re-analyzes and a new `/approve`
is required. After `max_revisions_per_issue` (default 5) revisions, the issue is labeled `agent:blocked` and you are
notified so a long thread cannot spend subscription quota indefinitely.

## Setup

### This repository's setup

Completed on 2026-10-14 for `JCallico/imap-migration-tools`:

| Item | Value |
| --- | --- |
| GitHub App | `imap-tools-agent`, owned by JCallico, acting as `imap-tools-agent[bot]` |
| Installation | JCallico account, **only** `imap-migration-tools` |
| App permissions | Contents, Issues, Pull requests: read and write; Actions, Checks, Metadata: read-only |
| Private key | `~/.ssh/imap-agent-app.pem`, mode 600, on the machine that runs the loop |
| Loop settings | `~/.config/agent-loop/env` (mode 600): App ID, installation ID, key path |
| Shell loading | `~/.bashrc` loads that file above Omarchy's interactive-shell guard, so every bash shell has it |
| Labels | All eleven `agent:*` labels, created by the App |
| Branch rules | Ruleset `main_branch_ruleset` updated as described under [Branch protection](#branch-protection) |

The App ID, installation ID, and key path are not secrets; the key itself is, and never leaves that machine.

### Dependencies

```bash
.venv/bin/python -m pip install -r tools/agent_loop/requirements.txt
```

The loop also needs the GitHub CLI (`gh`), and the Codex and Claude Code CLIs signed in with their subscriptions
(`codex login`, `claude auth login`). Never configure API keys for them: stage processes run with API-key variables
removed, and `doctor` fails if either CLI is signed in with an API key.

### GitHub App setup

The loop acts on GitHub as its own App so that administrators receive notifications (GitHub does not notify you about
your own comments) and so that bot activity is clearly separated from yours.

1. Open **GitHub → Settings → Developer settings → GitHub Apps → New GitHub App**.
2. Name it (for example `imap-tools-agent`), set the homepage to the repository URL, and **uncheck** Webhook → Active.
3. Repository permissions:
   - **Contents**: Read and write
   - **Issues**: Read and write
   - **Pull requests**: Read and write
   - **Checks**: Read-only
   - **Actions**: Read-only
   - **Metadata**: Read-only (mandatory)

   Leave everything else, especially **Workflows** and **Administration**, at **No access**.
4. Under "Where can this GitHub App be installed?", choose **Only on this account**, then create the App.
5. Note the **App ID** (the Client ID is not needed). Under **Private keys**, generate a key and move it to a private
   location outside the repository and outside synced folders such as OneDrive. This repository's machine uses
   `~/.ssh`:

   ```bash
   mv ~/Downloads/<app-name>.*.private-key.pem ~/.ssh/imap-agent-app.pem
   chmod 600 ~/.ssh/imap-agent-app.pem
   ```

   Any private path works (for example `~/.config/agent-loop/app.pem`); the dispatcher refuses keys readable by other
   users. A lost or exposed key is replaced by generating a new one in the App settings and deleting the old one.

6. Choose **Install App**, install it on **Only select repositories → imap-migration-tools**, and note the installation
   ID from the URL (`.../settings/installations/<installation-id>`).
7. Put the settings in `~/.config/agent-loop/env` (mode 600). A systemd unit can later load the same file with
   `EnvironmentFile=`:

   ```bash
   install -d -m 700 ~/.config/agent-loop
   cat > ~/.config/agent-loop/env <<'EOF'
   AGENT_LOOP_APP_ID=<app-id>
   AGENT_LOOP_APP_INSTALLATION_ID=<installation-id>
   AGENT_LOOP_APP_PRIVATE_KEY_PATH=/home/<you>/.ssh/imap-agent-app.pem
   EOF
   chmod 600 ~/.config/agent-loop/env
   ```

8. Load it in every shell by adding this to `~/.bashrc`. On Omarchy, place it **above** the
   `[[ $- != *i* ]] && return` guard so non-interactive shells get it too:

   ```bash
   # Agent loop GitHub App settings (above the interactive guard so every bash shell gets them)
   if [ -f ~/.config/agent-loop/env ]; then set -a; . ~/.config/agent-loop/env; set +a; fi
   ```

9. Verify in a new terminal:

   ```bash
   set -a; . ~/.config/agent-loop/env; set +a
   PYTHONPATH=tools .venv/bin/python -m agent_loop doctor
   ```

   `doctor` reports the App's bot login (for example `imap-tools-agent[bot]`) and confirms the installation can reach
   the repository.

The private key never leaves the local machine. The dispatcher signs a nine-minute JWT with PyJWT and exchanges it for
a one-hour installation token through `gh api`; tokens are kept in memory only. Because `gh` receives the JWT as a
request header argument, it is briefly visible in the local process list, so run the loop on a single-user machine.

### Labels

```bash
PYTHONPATH=tools .venv/bin/python -m agent_loop labels           # describe
PYTHONPATH=tools .venv/bin/python -m agent_loop labels --apply   # create or update (as the App)
```

### Branch protection

`main` is protected so that even a malfunctioning loop cannot merge. The repository ruleset `main_branch_ruleset`
(**Settings → Rules → Rulesets**) enforces:

- pull requests for every change, squash merges only, and resolved review conversations;
- one approving review, dismissed when new commits are pushed;
- these status checks: `Lint`, `Test (Python 3.10)` through `Test (Python 3.13)`, `Security Scan`, `Build Check`,
  `PyPI README`, `Native GUI (ubuntu-24.04)`, `Native GUI (macos-latest)`, `Native GUI (windows-latest)`, and the
  Android `build`;
- no force-pushes and no deletion of `main`;
- a bypass for the repository **Admin** role in pull-request mode only: administrators can merge their own pull
  requests (GitHub does not allow self-approval) with "bypass rules" or `gh pr merge --squash --admin`, but nobody can
  push to `main` directly.

Pull requests opened by the bot therefore need an administrator's approval and green checks. The ruleset as it was
before the agent loop is saved locally at `~/.local/state/agent-loop/main_branch_ruleset.backup.json`.

## Configuration

`.github/agent-loop.toml` holds stage models, policy, quota, and notification settings. Precedence, highest first:

1. `--stage-model <stage>=<engine>:<model>[:<effort>]` (repeatable);
2. environment variables: `AGENT_LOOP_<STAGE>_ENGINE`, `AGENT_LOOP_<STAGE>_MODEL`, `AGENT_LOOP_<STAGE>_EFFORT`,
   `AGENT_LOOP_CONFIG`, `AGENT_LOOP_REPO`, `AGENT_LOOP_BOT_LOGIN`, `AGENT_LOOP_PAUSED`, `AGENT_LOOP_STATE_DIR`, and
   the `AGENT_LOOP_APP_*` credentials;
3. the configuration file;
4. built-in defaults (the same stage models and policy as the committed file; repository, `enabled_since`, and
   `notify.mention` have no defaults).

Verification, diff-policy, and CI-repair settings live in `[verify]` and `[policy]` (`max_verify_rounds`,
`max_ci_fix_attempts`, `protected_paths`, `max_diff_lines`).

Stages are `analysis`, `implementation`, `feedback`, `ci_fix`, `review`, and `summarize`. Engines are `codex` and
`claude`. The dispatcher refuses to start when the review model equals any code-authoring model or, unless
`require_distinct_review_vendor = false`, shares its vendor. The repository `.env` file is deliberately not loaded; it
contains IMAP credentials that stage processes must never inherit.

## Commands

```bash
PYTHONPATH=tools .venv/bin/python -m agent_loop doctor          # verify setup
PYTHONPATH=tools .venv/bin/python -m agent_loop status          # stages, quota, managed items
PYTHONPATH=tools .venv/bin/python -m agent_loop tick --dry-run  # show planned actions
PYTHONPATH=tools .venv/bin/python -m agent_loop tick            # act (requires the App)
PYTHONPATH=tools .venv/bin/python -m agent_loop pause           # pause on this machine
PYTHONPATH=tools .venv/bin/python -m agent_loop resume
PYTHONPATH=tools .venv/bin/python -m agent_loop -v tick         # also report each step on stderr
```

`-v` (before the command) logs progress to stderr with timestamps: the items fetched and actions planned, each action
and its result and duration, model runs (worktree, time limit, duration, outcome, actual model, session id, quota
used), each verification command and its result, the diff policy verdict, commits, pushes, pull request creation,
and CI states. `-vv` also logs every GitHub CLI call with its exit status and duration. The log never contains
prompts, model output, comment bodies, field values, or credentials, and standard output is unchanged.

Local state (quota ledger, tick log, pause marker, and locks) lives in `~/.local/state/agent-loop/<owner>-<repo>/`.
Stage checkouts are disposable git worktrees under `~/.cache/agent-loop/<owner>-<repo>/worktrees/` (override with
`[loop] worktree_dir` or `AGENT_LOOP_WORKTREE_DIR`). They deliberately live outside the state directory: stages are
forbidden to read `~/.local/state`, `~/.config`, `~/.ssh`, and other credential locations, so a checkout inside one of
them would be unreadable to the very stage that needs it. The dispatcher refuses to run a stage whose checkout lies
inside a denied location.

## Implementation stage

After `/approve` (and at most `max_concurrent_implementations` at a time), each tick runs this pipeline. The model
only edits files; the dispatcher does everything that touches git history or GitHub, as the GitHub App.

1. **Approval is re-verified** at the moment work starts: the approval must still follow the current analysis, and
   the issue text must be unchanged. Otherwise the issue becomes `agent:blocked`.
2. **A persistent worktree** `impl-<n>` is created under the worktree directory on branch `agent/issue-<n>-<slug>`
   from the latest `origin/<base_branch>`. A local branch with unpushed commits is reused, never reset.
3. **The implementation model** (Codex by default) runs in its `workspace-write` sandbox: it can edit the worktree
   but cannot write elsewhere, use the network, or run git commits. It receives the `implement-approved-issue` skill,
   the approved analysis, and your comments; the original issue text is deliberately withheld. It writes progress
   notes to `.agent-loop/progress.md`, which is never committed.
4. **Verification runs outside the sandbox.** The dispatcher runs the `[verify]` commands (the AGENTS.md sequence:
   full pytest suite, Ruff check and format check, `git diff --check`), because the sandbox blocks the loopback
   sockets that most tests need. Failures are returned to the same model session for up to `max_verify_rounds`
   repair rounds; then the issue becomes `agent:blocked`.
5. **The diff policy gate** runs on the commit: no changes to `policy.protected_paths` (default
   `.github/workflows/**`), no symbolic links, submodules, or binary files, no credential-like content, and at most
   `max_diff_lines` changed lines outside tests. Violations name the rule and path, never the content.
6. **The dispatcher commits and pushes** to the `agent/*` branch (never force, never any other branch) using a
   one-shot credential helper, so the App token never appears in a command line or in the model's environment. The
   commit is attributed to the bot account.
7. **A draft pull request** is opened with `Closes #<n>`, the model's summary and notes (mentions neutralized and
   scanned for credentials), the verification results, and a comment recording which model implemented it, which the
   review stage later uses to pick a different model.

### CI loop

Each tick, a pull request labeled `agent:implementing` is checked against the status checks required by the base
branch's rules (falling back to every reported check):

- **Pending or not yet reported:** wait.
- **Failed:** the `ci_fix` model receives the failing job logs (credentials redacted) and repairs the branch. The fix
  goes through the same verification, policy gate, and push; at most `max_ci_fix_attempts` times, then
  `agent:blocked`.
- **Green:** the pull request is marked ready for review, labeled `agent:ai-review`, and its worktree is removed.

### Interruptions

A subscription limit, transient error, or restart never loses work. The worktree and the model's session id are kept
(`~/.local/state/agent-loop/<owner>-<repo>/stages/issue-<n>.json`); the next tick resumes the session (falling back
to a fresh session that rediscovers the work from the worktree) and the status comment says when work continues.
Every stage step is idempotent: an existing pull request for the branch is reused, and a finished model run is not
repeated when only verification or pushing remained.

## Review stage

A pull request labeled `agent:ai-review` (after its required checks pass) is reviewed by the `review` model:

1. **Reviewer selection:** the reviewer must differ from every model recorded as an author of the pull request
   (implementation, CI repair, and feedback runs) and, by default, from their vendors. If no configured reviewer
   qualifies, the review waits; the model the engine actually used is checked again before anything is posted.
2. **Read-only checkout:** the pull request head (`refs/pull/<n>/head`) is checked out detached under the worktree
   directory, with `origin/<base_branch>` for the diff. The reviewer gets the `cross-model-pr-review` skill, the
   approved analysis, the diff, and earlier review rounds with the author's responses, so settled items are not
   raised again. It cannot edit files or use the network.
3. **The review is posted by the App** as a comment review bound to the head commit: inline comments on changed lines,
   other findings in the review body. The bot never approves or merges. If GitHub rejects an inline position, every
   finding is posted in the body instead.
4. **Routing:** any blocking finding labels the pull request `agent:changes-requested`; otherwise it becomes
   `agent:ready-for-admin`, you are mentioned, and you are requested as reviewer. After `max_ai_review_rounds`
   reviews without reaching you, the pull request is blocked and you decide. Each "Request changes" review of yours
   starts a new budget.

## Feedback stage

A pull request labeled `agent:changes-requested` is handled by the `feedback` model in the issue's worktree:

1. **Only trusted items are collected:** unresolved review threads started by an administrator or by the AI review,
   your latest "Request changes" review summary, and the AI review's findings outside changed lines. Threads, reviews,
   and comments from anyone else are ignored before any model runs. A thread counts again once you reply to it.
2. **The model decides each item:** fix it, decline it with evidence, or mark it as needing your decision, following
   the `address-review-feedback` skill. Every item must get exactly one response.
3. **Changes go through the same verification, diff policy, and push** as the implementation stage; when every item
   was declined, nothing is committed and verification is skipped.
4. **Replies:** each thread gets a reply with the decision, and threads the AI reviewer opened are resolved when they
   were fixed. Your threads are left for you to resolve. A summary comment lists every item.
5. **Next:** the pull request returns to `agent:implementing`, so CI runs and the next AI review round follows. If any
   item needs your decision, the pull request is blocked and you are notified; reply in the thread (or review again)
   and remove `agent:blocked`.

### Isolation limits

Codex's sandbox restricts writes and the network, **not reads**: an implementation or repair run can read any file your
account can read, including the App private key. That is why the model never receives credentials, why you approve
the specification before it runs, and why every change passes the diff policy gate and your review before merging.
Treat the implementation model as running with your account's read access and review its output accordingly. If you
configure a Claude model as the implementer, its tool allow- and deny-lists apply instead (no network tools, no git
commits, credential locations denied), but there is no operating-system sandbox.

## Analysis stage

On a live `tick`, each new issue (and each issue with a pending revision request or a reporter reply to
`agent:needs-info`)
is analyzed by the configured `analysis` model, at most `max_stage_runs_per_tick` per tick:

1. The issue is labeled `agent:analyzing`, and a disposable worktree of `origin/<base_branch>` is created under the
   worktree directory (see above).
2. The model receives the `issue-analysis` skill from the dispatcher's own checkout and the issue as a quoted JSON
   document marked untrusted. The administrator's comments that requested a revision are passed separately as trusted
   input.
3. The run is read-only. For Claude, only `Read`, `Grep`, `Glob`, and read-only `git` commands are allowed; editing,
   web access, and subagents are denied, as is reading credential locations (`~/.ssh`, `~/.config`, `~/.codex`,
   `~/.claude`, `~/.local/state`, `~/.gnupg`, `~/.aws`, keyrings, and `.env` files). Codex runs in its read-only
   sandbox, which has no network access but can read any local file.
4. The result must be a JSON object (`analysis` or `needs_info`). Before posting, the dispatcher rejects output that
   looks like a credential and neutralizes @mentions in model text, so only the dispatcher notifies people.
5. An analysis is posted with a hidden hash marker, the issue moves to `agent:awaiting-approval`, and the
   administrator is mentioned and assigned. A request for information mentions the reporter and moves the issue to
   `agent:needs-info`.

A subscription limit labels the issue `agent:waiting-quota` and keeps one status comment up to date until the work
resumes. Invalid output, a possible credential, an authentication problem, or a failed run labels the issue
`agent:blocked` and notifies the administrator; remove the label to retry.

## Subscription limits

Usage limits pause work; they never fail it. The dispatcher records the CLIs' own rate-limit telemetry (Codex session
`token_count` events and Claude `rate_limit_event` messages) in the quota ledger. An engine above
`low_threshold_percent` starts no new analysis or implementation. An exhausted engine waits until its reported reset
time; when no reset time is known, it backs off exponentially up to `unknown_backoff_max_hours`. `status` shows each
engine's state and resume time.
