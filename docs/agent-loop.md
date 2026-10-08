# Agent loop operator guide

The agent loop moves work from GitHub issue to review-ready pull request. A repository administrator only creates (or
receives) issues, approves or revises each issue's analysis, and reviews the final pull request. The design and rollout
plan are in [agent-loop-plan.md](agent-loop-plan.md).

## Current status

Phase 1 (foundations) is implemented:

- configuration with precedence and implementation/review model-separation rules;
- GitHub App authentication, with every GitHub call made through the GitHub CLI;
- administrator-only trigger authorization and analysis-approval binding;
- the label state machine, with `tick --dry-run` showing the planned actions;
- the subscription quota ledger and failure classifier;
- the GitHub notifier, label bootstrap, `doctor`, `status`, `pause`, and `resume`.

Stage runners (analysis, implementation, review, and feedback) arrive in later phases. Until then, a live `tick`
performs only dispatcher-owned actions: reverting unauthorized label changes, answering unauthorized commands, and
escalating pull requests that exceed the AI review round limit. Planned stage runs are reported as pending.

## Administrator workflow

| Where | Action | Effect |
| --- | --- | --- |
| Issue | Create an issue (or let others create one) | The loop analyzes it and labels it `agent:awaiting-approval` |
| Issue | Comment `/approve` as the first line | Implementation starts from the approved analysis |
| Issue | Comment `/revise <notes>` | The analysis is revised using your notes |
| Issue | Close the issue | The loop stops |
| Pull request | Merge or close | Done |
| Pull request | Submit a "Request changes" review | The loop addresses your comments and returns the PR for review |
| Issue or PR | Apply `agent:paused` | The loop leaves the item alone until you remove the label |
| Existing issue or PR | Apply `agent:adopt` | Opts in an item created before `enabled_since` (or a PR the loop did not create) |

Only users with the repository **Admin** role count. Commands and `agent:*` label changes from anyone else are
ignored or reverted, and the bot replies once to say so. A command must be the first line of a comment, must not be
edited by anyone other than an administrator, and applies only to the analysis revision it follows. If the issue or
the analysis changes afterwards, the loop re-analyzes and a new `/approve` is required.

## Setup

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
5. Note the **App ID**. Under **Private keys**, generate a key and move it outside the repository:

   ```bash
   install -d -m 700 ~/.config/agent-loop
   mv ~/Downloads/<app-name>.*.private-key.pem ~/.config/agent-loop/app.pem
   chmod 600 ~/.config/agent-loop/app.pem
   ```

6. Choose **Install App**, install it on **Only select repositories → imap-migration-tools**, and note the installation
   ID from the URL (`.../settings/installations/<installation-id>`).
7. Provide the credentials to the machine that runs the loop, for example in `~/.config/agent-loop/env`
   (mode 600), which a systemd unit can later load with `EnvironmentFile=`:

   ```bash
   AGENT_LOOP_APP_ID=123456
   AGENT_LOOP_APP_INSTALLATION_ID=78901234
   AGENT_LOOP_APP_PRIVATE_KEY_PATH=/home/<you>/.config/agent-loop/app.pem
   ```

8. Verify:

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

Protect `main` so that even a malfunctioning loop cannot merge: require pull requests, the CI checks, and one approving
review from an administrator. Apply this through **Settings → Rules → Rulesets** after reviewing the plan.

## Configuration

`.github/agent-loop.toml` holds stage models, policy, quota, and notification settings. Precedence, highest first:

1. `--stage-model <stage>=<engine>:<model>[:<effort>]` (repeatable);
2. environment variables: `AGENT_LOOP_<STAGE>_ENGINE`, `AGENT_LOOP_<STAGE>_MODEL`, `AGENT_LOOP_<STAGE>_EFFORT`,
   `AGENT_LOOP_CONFIG`, `AGENT_LOOP_REPO`, `AGENT_LOOP_BOT_LOGIN`, `AGENT_LOOP_PAUSED`, `AGENT_LOOP_STATE_DIR`, and
   the `AGENT_LOOP_APP_*` credentials;
3. the configuration file;
4. built-in defaults (identical to the committed file).

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
```

Local state (quota ledger, tick log, pause marker, and locks) lives in `~/.local/state/agent-loop/<owner>-<repo>/`.

## Subscription limits

Usage limits pause work; they never fail it. The dispatcher records the CLIs' own rate-limit telemetry (Codex session
`token_count` events and Claude `rate_limit_event` messages) in the quota ledger. An engine above
`low_threshold_percent` starts no new analysis or implementation. An exhausted engine waits until its reported reset
time; when no reset time is known, it backs off exponentially up to `unknown_backoff_max_hours`. `status` shows each
engine's state and resume time.
