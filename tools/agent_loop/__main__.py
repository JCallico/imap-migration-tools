"""Command-line interface: ``PYTHONPATH=tools python -m agent_loop <command>``.

The repository ``.env`` file is intentionally not loaded: it holds IMAP credentials that stage processes must never
inherit. Configure the loop with ``.github/agent-loop.toml`` and ``AGENT_LOOP_*`` environment variables.
"""

from __future__ import annotations

import argparse
import sys

from .config import ConfigError, load_config
from .dispatcher import DispatcherError, build_runtime, doctor, set_paused, status, tick
from .gh import GhError
from .labels import bootstrap_labels


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent_loop", description="Issue-to-pull-request agent loop dispatcher.")
    parser.add_argument("--config", help="configuration file (default: .github/agent-loop.toml)")
    parser.add_argument(
        "--stage-model",
        action="append",
        default=[],
        metavar="STAGE=ENGINE:MODEL[:EFFORT]",
        help="override a stage's model for this invocation (repeatable)",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    tick_parser = commands.add_parser("tick", help="run one dispatcher pass")
    tick_parser.add_argument("--dry-run", action="store_true", help="show planned actions without changing GitHub")
    commands.add_parser("status", help="show configuration, quota, and managed items")
    commands.add_parser("doctor", help="verify GitHub access, App identity, subscriptions, and models")
    labels_parser = commands.add_parser("labels", help="create or update the agent:* labels")
    labels_parser.add_argument("--apply", action="store_true", help="apply changes (default: describe only)")
    commands.add_parser("pause", help="pause the loop on this machine")
    commands.add_parser("resume", help="resume the loop on this machine")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.config, stage_overrides=args.stage_model)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    try:
        if args.command == "doctor":
            checks = doctor(config)
            for check in checks:
                print(check.render())
            return 0 if all(check.ok or check.warning for check in checks) else 1
        require_app = (args.command == "tick" and not args.dry_run) or (args.command == "labels" and args.apply)
        runtime = build_runtime(config, require_app=require_app)
        if args.command == "tick":
            lines = tick(runtime, dry_run=args.dry_run)
        elif args.command == "status":
            lines = status(runtime)
        elif args.command == "labels":
            lines = bootstrap_labels(runtime.gh, apply=args.apply)
        elif args.command == "pause":
            set_paused(runtime, True)
            lines = ["agent loop paused on this machine"]
        else:
            set_paused(runtime, False)
            lines = [
                "agent loop resumed on this machine" + (" (still paused by configuration)" if config.paused else "")
            ]
    except (DispatcherError, GhError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
