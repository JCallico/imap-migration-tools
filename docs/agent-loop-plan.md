# Agent loop implementation plan

Status: Phases 1 (foundations), 2 (analysis and approval), 3 (implementation), and 4 (review and feedback)
implemented; the GitHub App, labels, and branch rules are set up. Phase 5 (unattended operation) is pending. See
[agent-loop.md](agent-loop.md) for operation.

## Goal

Automate the project lifecycle from GitHub issue to review-ready pull request. The project administrator is involved
only to:

1. create issues (or let external contributors create them);
2. review an issue's analysis and either approve it with `/approve`, request revisions by simply commenting (or with
   `/revise <notes>` or by mentioning the bot), or close
   the issue; and
3. review the final pull request and merge it, close it, or request further changes.

Everything between those touchpoints (analysis, implementation, CI repair, cross-model review, and responding to review
feedback) runs autonomously on this machine using the administrator's existing Codex and Claude subscriptions.

## Prior art and what this plan adopts

| System | What it does | Adopted here |
| --- | --- | --- |
| [GitHub Copilot coding agent][copilot] | Assign an issue, the agent pushes a draft PR, requests review, and acts on review comments | Overall issue → draft PR → review → feedback shape |
| [GitHub Spec Kit][speckit] | Specify → plan → tasks → implement, with human review of the plan | The analysis is a structured spec; implementation follows the approved spec, not raw issue text |
| [GitHub Agentic Workflows (gh-aw)][ghaw] | Agents run read-only; declared "safe outputs" are executed by a separate, minimally privileged job | Deterministic code performs every state change; models only reason and propose |
| [claude-code-action][claude-action], [openai/codex-action][codex-action] | Hosted CI agents for triage, review, and fixes | Not used now (API billing); stage adapters keep a future Actions host possible |
| [CSA prompt-injection note][csa], [GitInject][gitinject] | Malicious issue text has hijacked CI agents and led to supply-chain compromise | This repository is public, so issue and comment text is treated as hostile input |

## Decisions

| Topic | Decision |
| --- | --- |
| Execution host | Local machine, systemd user timer, headless `codex exec` and `claude -p` on existing subscriptions |
| Orchestration | Deterministic Python dispatcher in `tools/agent_loop/`; models run only inside stage invocations |
| GitHub access | GitHub CLI (`gh`) for every GitHub interaction, from the dispatcher and from skills |
| State | GitHub labels plus hidden HTML markers in comments; local state only for locks, quota, and sessions |
| Bot identity | GitHub App installed only on this repository (`<app-name>[bot]`) |
| Approval signal | `/approve` comment from a repository administrator, bound to the analysis hash |
| Revision signal | Any other administrator comment on an issue awaiting approval; debounced, immediate on `/revise` or a bot mention, suppressed by `/note` |
| Trigger authority | Only repository administrators can trigger write-capable actions; see [Trigger authorization](#trigger-authorization) |
| Notifications | GitHub-native only (mentions, assignment, review requests); pluggable notifier interface for later |
| Models | Configurable per stage; implementation and review must never use the same model |
| Subscription limits | Treated as pauses with resumable work, never as failures or a reason to use paid API billing |
| OpenClaw | Not part of the solution |

## Lifecycle and state machine

State lives in `agent:*` labels so the administrator can see and override it directly in GitHub, and the loop survives
restarts.

| Label | Applies to | Advanced by | Next state |
| --- | --- | --- | --- |
| *(no `agent:*` label, open issue)* | Issue | Dispatcher | `agent:analyzing` |
| `agent:analyzing` | Issue | `issue-analysis` | `agent:awaiting-approval` or `agent:needs-info` |
| `agent:needs-info` | Issue | Reporter or administrator reply, then dispatcher (read-only re-analysis, capped) | `agent:analyzing` |
| `agent:awaiting-approval` | Issue | **Administrator**: `/approve`, any other comment (revise), or close | `agent:implementing` or `agent:analyzing` |
| `agent:implementing` | Issue + PR | `implement-approved-issue`, then the dispatcher's CI loop | PR gets `agent:ai-review` |
| `agent:ai-review` | PR | `cross-model-pr-review` | `agent:changes-requested` or `agent:ready-for-admin` |
| `agent:changes-requested` | PR | `address-review-feedback` + `pr-green-loop` | `agent:ai-review` (max 3 AI rounds, then escalate) |
| `agent:ready-for-admin` | PR | **Administrator**: merge, close, or "Request changes" review | Done, or `agent:changes-requested` |
| `agent:waiting-quota` | Issue or PR | Dispatcher (in addition to the stage label) | Removed when the stage resumes |
| `agent:blocked` | Issue or PR | Any stage on an unrecoverable problem; administrator notified | Administrator decides |
| `agent:paused` | Issue or PR | Administrator (kill switch) | Removed by administrator |
| `agent:adopt` | Issue or PR | Administrator opts in an item created before `enabled_since`, or a PR the loop did not create | Normal processing |

A local pause marker (`agent_loop pause`), `AGENT_LOOP_PAUSED`, or `[loop] paused` also pauses the whole loop.
Issues created before `[github] enabled_since`, and pull requests the loop did not create (for example #71), are
adopted only when an administrator applies `agent:adopt`.

## Architecture

```text
systemd user timer (every 10–15 min)
        │
        ▼
tools/agent_loop dispatcher  ── gh (GH_TOKEN = App token) ──►  GitHub (labels, comments, PRs, reviews)
  • reads state, verifies approvals, applies policy, prioritises work
  • quota ledger, locks, session store  (~/.local/state/agent-loop/)
        │  one stage at a time per engine
        ▼
stage runner ──► codex exec / claude -p  (skill + scoped prompt, API keys scrubbed)
        │
        ▼
structured stage result (JSON) ──► dispatcher validates and performs GitHub writes
```

Principle: **code orchestrates, models reason.** Stages return structured results; the dispatcher validates them
against policy before writing anything visible on GitHub. Analysis runs with no write credentials at all.

## Model configuration

Configuration lives in `.github/agent-loop.toml`. Precedence, highest first, mirrors the project's existing `.env`
rules: command-line `--stage-model <stage>=<engine>:<model>[:<effort>]`, then environment variables
(`AGENT_LOOP_<STAGE>_ENGINE`, `AGENT_LOOP_<STAGE>_MODEL`, `AGENT_LOOP_<STAGE>_EFFORT`), then the config file, then
built-in defaults.

```toml
[stages.analysis]          # spec writing, library-versus-scratch research
engine = "claude"
model = "claude-opus-5-5"
effort = "medium"
on_exhausted = "wait"

[stages.implementation]    # long agentic coding plus pr-green-loop
engine = "codex"
model = "gpt-6.1-sol"
effort = "medium"
on_exhausted = "wait"

[stages.feedback]          # address review items, rerun pr-green-loop
engine = "codex"
model = "gpt-6.1-sol"
effort = "medium"
on_exhausted = "wait"

[stages.ci_fix]            # CI log diagnosis inside pr-green-loop
engine = "codex"
model = "gpt-6.1-sol"
effort = "medium"
on_exhausted = "wait"

[stages.review]            # independent cross-vendor PR review
engine = "claude"
model = "claude-sonnet-5-5"
effort = "medium"
on_exhausted = "wait"

[stages.summarize]         # notification summaries, needs-info detection
engine = "claude"
model = "claude-haiku-4-5-20251001"
effort = "low"
on_exhausted = "fallback"
fallbacks = ["codex:gpt-6-luna:low"]

[policy]
require_distinct_review_model = true    # hard rule; cannot be disabled
require_distinct_review_vendor = true   # default; false allows same vendor with a different model
max_ai_review_rounds = 3
max_concurrent_implementations = 1

[quota]
low_threshold_percent = 80
reserve_for_inflight = true
unknown_backoff_max_hours = 6
max_stage_minutes = 90
max_turns = 200

[notify]
backends = ["github"]
admin_delay_alert_hours = 12
```

### Default model rationale

Frontier models (`gpt-6-astra`, `claude-fable-5-1`) are deliberately not used by default; every model stage runs at
medium effort or lower to conserve subscription quota.

- **Implementation, feedback, CI repair — `gpt-6.1-sol`, medium:** Codex's current coding workhorse; the existing
  `pr-green-loop` and `release-green-loop` skills already run on Codex.
- **Analysis — `claude-opus-5-5`, medium:** strong reasoning for specs and library-versus-scratch research.
- **Review — `claude-sonnet-5-5`, medium:** a different vendor and model from the implementer, satisfying the
  distinct-model and distinct-vendor rules, and a different model from the analysis author, so the reviewer does not
  check code against a spec its own model wrote.
- **Summaries — Haiku 4.5, low:** small, cheap tasks.

Model names come from the local Codex model list and the current Claude lineup; each is a one-line change.

### Distinct-model enforcement

1. **Startup validation:** the resolved primary review model must not share an `(engine, model)` pair with the primary
   implementation or feedback model and, by default, not a vendor either. Violations stop the dispatcher. Fallback
   candidates are checked per pull request at run time (item 3).
2. **Actual-model verification:** CLIs can fall back silently, so the dispatcher reads the model actually used from
   `codex exec --json` and `claude -p --output-format json`/`stream-json` output and records it in hidden markers in
   the PR's status comments and reviews.
3. **Per-PR author set:** the dispatcher tracks every model that authored commits on a PR. The reviewer is the first
   candidate (primary, then fallbacks) not in that set and, by default, not of the same vendor. If none qualifies,
   the review waits; if the PR's authors and reviewer already collide, the PR moves to `agent:blocked`.
4. **`doctor`:** verifies every configured model is available before stages run.

## Subscription limits

### Principles

1. Reaching a subscription limit is a **pause**, never a failure. It does not count toward the "three materially
   identical failures" budget, does not set `agent:blocked`, and never discards work.
2. **No silent switch to paid API billing.** Stage processes run with `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and
   similar variables removed. `doctor` verifies both CLIs are authenticated with subscriptions and refuses to run
   otherwise.
3. **Quota is tracked per subscription (engine)**, not per model, because limits are largely account-wide.
   Same-vendor fallback rarely helps; real fallback is cross-vendor and must respect the distinct-model rule.

### Detection

A quota ledger in `~/.local/state/agent-loop/quota.json` records, per engine: `available`, `low`, `exhausted`, or
`unknown`; `reset_at` and window type (rolling or weekly) when known; last observed usage percentage; and update time.

- **Proactive:** parse rate-limit and usage telemetry from the CLIs' JSON event streams. Above
  `low_threshold_percent`, mark the engine `low`.
- **Reactive:** classify every non-zero exit as `quota_exhausted`, `transient`, `auth`, or `task_failure`, and extract
  the reset time when present.
- **Unknown reset time:** exponential backoff (30 min, 1 h, 2 h, … up to `unknown_backoff_max_hours`), then one tiny
  probe call with the cheapest model before resuming real work.

The CLIs' exact limit messages and event formats are **not assumed**. Phase 1 captures real output as test fixtures,
and limit messages are added as they are observed. Unrecognised errors classify as `unknown` and pause; they never
cause retry storms. A CLI upgrade that changes formats surfaces as `unknown`.

### Resumable work

- Each stage's session ID is stored per issue or PR. After a reset on the same engine, the dispatcher resumes the
  session (`codex exec resume <id>` or `claude --resume <id>`).
- Skills write an ignored checkpoint file, `.agent-loop/progress.md`, in the worktree after each step: completed
  steps, next step, and the last verification result. A fresh session or a fallback engine resumes from that file
  plus the worktree.
- An interrupted edit stays uncommitted. Every stage begins by inspecting `git status` and the checkpoint.
  `pr-green-loop`'s verify-before-commit rule prevents pushing a partial edit.
- The item gets `agent:waiting-quota` beside its stage label, and one status comment is edited in place (for example,
  "Paused: Codex quota, resumes about 14:30").

### Fallback policy

Per stage, `on_exhausted = "wait"` or `"fallback"` with an ordered `fallbacks` list. Before an implementation or
feedback fallback is used, the dispatcher verifies a valid reviewer will still exist. Example: if Codex is exhausted
mid-PR and a configured Claude fallback takes over the implementation, the Claude reviewer can no longer review (same
vendor); unless a reviewer from another vendor is configured, the stage waits instead. A fallback always works from
the same approved spec and checkpoint, so the administrator's approval stays valid.

Defaults: analysis, implementation, feedback, CI repair, and review **wait** (quality and authorship clarity over
speed); only summaries **fall back** across vendors. Because limits are largely account-wide, the default review
stage has no useful fallback: Codex authored the implementation, and another Claude model shares the exhausted
subscription.

## Notifications

Default backend: GitHub-native.

- Analysis ready: @mention the administrator in the analysis comment and assign the issue.
- PR ready: request the administrator as reviewer.
- Blocked or quota alert: @mention in the item's status comment.
- Delivery relies on GitHub Mobile push and email settings.
- Each notification is deduplicated by analysis hash or head SHA.

The `notifier` interface allows additional backends (for example email or ntfy) to be added later through
configuration without changing stages.

## Skills

Canonical skills live in `.claude/skills/<name>/SKILL.md` with thin `.codex/skills/<name>/` adapters, following the
existing `setup-development-environment` pattern, so either engine can run any stage.

1. **`issue-analysis`** — Reads the issue as untrusted data and investigates the code. Applies AGENTS.md's
   library-first rule (dependency versus from-scratch, with maintenance, security, and portability tradeoffs). Produces
   a spec: problem, acceptance criteria, approach and options with a recommendation, affected files, test plan
   (including the `.env` end-to-end requirements), risks, size, and open questions. Posted with
   `<!-- agent-loop:analysis rev=N hash=… model=… -->`. Runs read-only with no write token.
2. **`implement-approved-issue`** — Guides the sandboxed author model (implementation and CI repair). The dispatcher,
   not the skill, verifies approval provenance and hash, creates the worktree on `agent/issue-<n>-<slug>` from
   `origin/main`, runs the full AGENTS.md verification sequence outside the sandbox, commits and pushes as the App,
   opens a draft PR with `Closes #n`, and runs the green loop: it watches CI each tick, repairs failures, and marks the
   PR ready. (Design change from the first draft: the plan had the model run `pr-green-loop` itself, which would have
   required giving it GitHub credentials and a network-enabled sandbox.)
3. **`address-review-feedback`** — Guides the sandboxed feedback model. The dispatcher collects unresolved review
   threads through `gh api graphql`, keeping only items whose author is a repository administrator or the loop's AI
   reviewer (see [Trigger authorization](#trigger-authorization)); all other comments are ignored. The model classifies
   each item as valid (fix), invalid (rebut with evidence), or needs administrator decision (escalate) and edits
   files. The dispatcher verifies, pushes, replies to every item with the fixing commit SHA or rationale, and resolves
   only AI-reviewer threads that were fixed; administrator-opened threads are left for the administrator.
4. **`cross-model-pr-review`** — Reviews the diff against the approved spec and repository conventions. Receives the
   PR's author-model set from the dispatcher. The dispatcher posts its result as a comment-only GitHub review with
   inline comments and a verdict marker bound to the head SHA. Never approves for merge or merges.
5. **`agent-loop`** — Operator skill: run one tick or `--dry-run`, show status and quota, run `doctor`, pause or resume.
6. **`pr-green-loop` and `release-green-loop`** — Unchanged and still available for manual delivery work. The agent
   loop does not run them: their commit, push, and CI-monitoring steps are implemented in the dispatcher (scoped to
   `agent/*` branches, never forcing, never touching `main`), with checkpoint-and-resume and quota interruptions
   excluded from the CI repair budget.

## Security and guardrails

- **Hostile input:** issue and comment text is passed to models as quoted data, never as instructions. Implementation
  follows the approved spec.
- **Trigger authority:** only repository administrators can trigger write-capable actions. See
  [Trigger authorization](#trigger-authorization).
- **Approval binding:** approval is bound to the analysis hash. Editing the issue or analysis afterwards requires
  re-approval.
- **GitHub App:** `imap-tools-agent`, installed on this repository only. Permissions: Contents, Pull requests, and
  Issues read/write; Metadata, Checks, and Actions read. No Workflows or Administration permission. Private key stored
  outside the repository at `~/.ssh/imap-agent-app.pem` with mode 600; installation tokens are short-lived and held in
  memory only.
- **Analysis stage isolation:** read-only runs in a disposable worktree under `~/.cache/agent-loop/` (never under a
  location stages are denied, which an early version got wrong, leaving the model unable to read its own checkout); Claude is denied editing, web access,
  subagents, and reads of credential locations; Codex uses its read-only sandbox without network access. Output that
  looks like a credential is never posted, and @mentions in model text are neutralized.
- **Diff policy gate** before `agent:ready-for-admin`: reject changes to `.github/workflows/**`, secret-like content,
  oversized diffs, and files outside the spec's declared scope unless justified in the PR.
- **Branch protection on `main`** (applied 2026-10-14 by updating the existing `main_branch_ruleset`): pull requests
  only, squash merges only, one approval dismissed on new pushes, resolved conversations, twelve required CI checks, no
  force-push or deletion. The Admin role may bypass only through pull requests, because GitHub forbids approving your
  own pull request; bot pull requests always need the administrator's approval.
- **Budgets:** one concurrent implementation, three AI review rounds, three materially identical CI failures, and
  per-stage time and turn caps; exceeding a budget sets `agent:blocked` and notifies.
- **Opt-in only** for pre-existing issues and pull requests; `agent:paused` and a global flag act as kill switches.

## Trigger authorization

Every GitHub event that can cause the loop to write code, push, or change workflow state must come from a
**repository administrator**. "Administrator" means the GitHub collaborator permission `admin` (repository owner or a
user granted the Admin role); `maintain`, `write`, `triage`, and `read` do not qualify. The dispatcher enforces this
in code before any model runs; skills never decide authorization.

| Trigger | Required actor | Ignored when |
| --- | --- | --- |
| `/approve`, `/revise <notes>`, and plain comments on an issue awaiting approval (implicit revisions) | Administrator | Author is not an administrator, or the comment was edited by anyone other than its administrator author. `/note` comments and malformed commands never trigger |
| Admin "Request changes" PR review and its threads | Administrator | Review author is not an administrator |
| PR review threads acted on by `address-review-feedback` | Administrator, or the AI reviewer identified by the dispatcher's own run marker | Any other author, including the bot's other comments and outside reviewers |
| `agent:*` labels that change state (`agent:paused`, adopting an existing issue or PR, clearing `agent:blocked`) | Administrator who applied the label, from the issue timeline | Applied by anyone else; the dispatcher reverts it and records why |
| Reporter reply on `agent:needs-info` | Anyone (re-analysis only) | Never grants write access; capped at two re-analyses per issue without administrator action |

Verification rules:

- **Permission source:** `gh api repos/{owner}/{repo}/collaborators/{login}/permission`, checking that `permission`
  is `admin`. `author_association` (`OWNER`, `MEMBER`, `COLLABORATOR`) is not used because it does not distinguish
  roles. An optional `allowed_admins` list in the config can narrow, but never widen, the set.
- **Check at execution time:** permission is re-verified when the action is executed, not only when the comment is
  first seen, so revoked access takes effect immediately.
- **Edits:** collaborators with write access can edit other users' comments. A command comment counts only if
  it has never been edited, or every edit in its GraphQL `userContentEdits` history was made by an administrator.
- **Exact syntax:** `/approve`, `/revise <notes>`, and `/note` must be the first line of the comment and match
  exactly. Quoted text and code blocks never count, and a first line that looks like a command but is malformed is
  ignored rather than treated as feedback.
- **Implicit revisions:** every other administrator comment after the latest analysis is feedback. The bot reacts
  with 👀, then revises once after `revision_debounce_minutes` of quiet, immediately when the comment mentions the
  bot or uses `/revise`. The latest explicit command wins, so `/approve` is never overridden by plain comments, and
  `/approve` is never implicit. `max_revisions_per_issue` escalates long threads to `agent:blocked`.
- **No lost comments:** each analysis records the newest comment it was shown (`seen=`), so comments posted while
  the model was running still count afterwards.
- **Binding:** `/approve` applies only to the analysis revision current when it was posted (by hash); a later analysis
  revision or issue edit requires a new `/approve`.
- **Bot exclusion:** comments authored by the App itself never count as commands, even though the App writes the
  analysis and status comments.
- **Ignored commands:** an unauthorized command is ignored without running a model. The dispatcher records the event
  in its local log and may reply once, without echoing the comment text, that only administrators can issue it.
- **Tests:** unit tests cover each rule with recorded `gh` JSON, including non-admin collaborators, edited comments,
  revoked permission, quoted commands, and bot-authored comments.

## AGENTS.md changes

AGENTS.md currently forbids staging, committing, or pushing without an explicit request. Add a scoped exception: the
administrator's `/approve` of an issue analysis authorizes the agent loop, acting as the GitHub App, to commit and
push only to that issue's `agent/*` branch. Add an "Agent loop" section describing roles, labels, commands, and
configuration.

## Dependencies

Per AGENTS.md, maintained libraries are preferred for security-sensitive concerns.

| Need | Choice | Alternatives considered |
| --- | --- | --- |
| All GitHub interactions (issues, labels, comments, PRs, reviews, checks, review-thread GraphQL, git push credentials) | **GitHub CLI** (`gh issue`, `gh pr`, `gh api`, `gh api graphql`, `gh auth setup-git`) | PyGithub, githubkit (rejected: single interface wanted) |
| GitHub App JWT signing (minting short-lived installation tokens, which are then exchanged with `gh api`) | **PyJWT** with `cryptography` | Hand-rolled RS256 signing (rejected: security-sensitive); third-party `gh` token extensions (less established) |
| Configuration parsing | **`tomllib`** (3.11+) with **`tomli`** backport on 3.10 | YAML (adds a dependency, weaker typing) |
| Cross-process locking | **filelock** | raw `fcntl` (Linux-only, manual stale-lock handling) |
| Persistent backoff | Small in-house ledger | tenacity (in-process only; does not survive across timer ticks) |

These go in `tools/agent_loop/requirements.txt` and the development `requirements.txt` so CI can run the tests. They
are **not** added to the published package's runtime dependencies.

## Repository layout

```text
.github/agent-loop.toml               # stage, policy, quota, notifier configuration
tools/agent_loop/
  __main__.py                         # CLI: tick [--dry-run], status, doctor, labels, pause, resume
  config.py                           # loading, precedence, distinct-model validation
  gh.py                               # gh subprocess wrapper: JSON output, errors, GH_TOKEN injection
  app_auth.py                         # App JWT signing and in-memory installation tokens
  snapshot.py                         # GraphQL snapshots of issues and PRs (comments, edits, label events, reviews)
  authz.py                            # administrator checks, command parsing, analysis-approval binding
  state.py                            # label state machine, run markers, priorities
  selection.py                        # quota-aware model selection and reviewer separation
  engines.py                          # codex/claude commands, env scrubbing, result parsing
  quota.py                            # ledger, classifier, backoff, probes
  notify.py                           # notifier interface and GitHub backend
  labels.py                           # agent:* label definitions and bootstrap
  dispatcher.py                       # tick, status, doctor
  policy.py                           # diff policy gate
  review.py, feedback.py              # review and feedback stages (Phase 4)
  requirements.txt
packaging/systemd/agent-loop.{service,timer}   # Phase 5
.claude/skills/{issue-analysis,implement-approved-issue,address-review-feedback,cross-model-pr-review,agent-loop}/
.codex/skills/<same names>/            # thin adapters
docs/agent-loop.md                     # operator guide, including GitHub App setup
test/tools/agent_loop/                 # unit tests with recorded CLI fixtures and a scripted gh runner
```

## Rollout

Phases were originally planned as separate branches and pull requests; at the administrator's request, Phases 1 and 2
are delivered together on `feat/agent-loop-foundations` (PR #76).

1. **Foundations** *(implemented)* — AGENTS.md amendment; GitHub App setup guide; label bootstrap script (run only on request);
   dispatcher skeleton with configuration and precedence, distinct-model validation, App authentication, quota ledger
   and classifier, API-key scrubbing, `doctor`, `status`, `--dry-run`, and the GitHub notifier; captured CLI output
   fixtures; unit tests.
2. **Analysis and approval** *(implemented)* — `issue-analysis` skill, read-only analysis runner with disposable
   worktrees, output contract and safety checks, `/approve`, conversational revisions (implicit, debounced, mention,
   `/revise`, `/note`) and `agent:needs-info` handling, quota pauses
   with a status comment, and a per-tick limit on model-backed stage runs. Next: exercise live on issue #77.
3. **Implementation** *(implemented)* — `implement-approved-issue` skill; a sandboxed author model with
   dispatcher-run verification (the sandbox blocks the loopback sockets the tests need), the diff policy gate, commits and
   pushes by the dispatcher as the App, draft pull requests, and a tick-driven CI loop (wait, repair failures, mark
   ready) that replaces a model-driven `pr-green-loop`, so the model never holds GitHub credentials. Checkpoints in
   `.agent-loop/progress.md`, persisted session ids with resume and fresh-session fallback, and quota pauses that keep
   the worktree. Next: exercise on a small throwaway issue.
4. **Review and feedback** *(implemented)* — `cross-model-pr-review` and `address-review-feedback` skills; a read-only
   reviewer on a detached checkout of the pull request head, re-checked against the actual model used; comment-only
   reviews bound to the head commit with inline findings; a feedback stage that answers every trusted review item
   (fixed, declined, or needs the administrator), replies in threads, resolves only the AI reviewer's fixed threads,
   and returns the pull request through CI and review; AI review rounds counted per administrator request. The
   diff policy gate shipped in Phase 3. Deviation: the feedback model edits files only, so the dispatcher, not
   `pr-green-loop`, verifies, pushes, and posts the replies.
5. **Operation** — enable the systemd timer, run logs in `~/.local/state/agent-loop/`, operator guide finalized.

## Testing

- Unit tests for configuration precedence, distinct-model and reviewer selection (including fallback collisions),
  approval provenance and hash binding, state transitions, the limit classifier, ledger and backoff, scheduling
  priority, the diff policy gate, and notification deduplication.
- A `fake` engine replays captured CLI output so tests never call real models or GitHub.
- End-to-end validation on a throwaway issue per phase, including a simulated quota exhaustion and resume.
- Standard repository verification before every commit: full pytest suite, Ruff check, Ruff format check, and
  `git diff --check`.

## Administrator prerequisites

1. ~~Create the GitHub App, install it on this repository only, and store its private key privately.~~ Done
   2026-10-14 (`imap-tools-agent`; see [agent-loop.md](agent-loop.md#this-repositorys-setup)).
2. ~~Apply branch protection for `main`.~~ Done 2026-10-14.
3. ~~Create the `agent:*` labels.~~ Done 2026-10-14.
4. Enable GitHub Mobile or email notifications for mentions and review requests.

## Open items for review

- Phase 1 must verify the `gh` App-token flow end to end: mint the installation token with `gh api` using the App
  JWT, run `gh` and `git push` with `GH_TOKEN` set to that token, and confirm actions are attributed to
  `<app-name>[bot]`.
- Confirm the default models and fallback lists per stage.
- Confirm the library choices above.
- Confirm the systemd timer interval (proposed: 15 minutes).
- Confirm the diff-size limit for the policy gate (proposed: 1,500 changed lines, excluding tests).

[copilot]: https://github.blog/news-insights/product-news/github-copilot-meet-the-new-coding-agent/
[speckit]: https://github.blog/ai-and-ml/generative-ai/spec-driven-development-with-ai-get-started-with-a-new-open-source-toolkit/
[ghaw]: https://github.github.com/gh-aw/
[claude-action]: https://www.codewithseb.com/blog/claude-code-github-actions-pr-automation-guide
[codex-action]: https://developers.openai.com/codex/github-action
[csa]: https://labs.cloudsecurityalliance.org/research/csa-research-note-claude-code-github-action-prompt-injection/
[gitinject]: https://arxiv.org/html/2606.09935v1
