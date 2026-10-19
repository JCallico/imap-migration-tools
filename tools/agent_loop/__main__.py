"""Command-line interface: ``PYTHONPATH=tools python -m agent_loop <command>``.

The repository ``.env`` file is intentionally not loaded: it holds IMAP credentials that stage processes must never
inherit. Configure the loop with ``.github/agent-loop.toml`` and ``AGENT_LOOP_*`` environment variables.
"""

from __future__ import annotations

import argparse
import logging
import sys

from .config import ConfigError, load_config
from .dispatcher import DispatcherError, build_runtime, doctor, run_ticks, set_paused, status, tick
from .gh import GhError
from .labels import bootstrap_labels


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        value = 0
    if value < 1:
        raise argparse.ArgumentTypeError(f"expected a positive integer, got {text!r}")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent_loop", description="Issue-to-pull-request agent loop dispatcher.")
    parser.add_argument("--config", help="configuration file (default: .github/agent-loop.toml)")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="report progress on stderr: -v for each step, -vv to also show every GitHub CLI call",
    )
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
    tick_parser.add_argument(
        "--repeat",
        type=_positive_int,
        default=1,
        metavar="N",
        help="run up to N ticks, stopping early once only administrator actions remain (default: 1)",
    )
    tick_parser.add_argument(
        "--interval",
        type=_positive_int,
        default=120,
        metavar="SECONDS",
        help="pause between repeated ticks (default: 120)",
    )
    commands.add_parser("status", help="show configuration, quota, and managed items")
    commands.add_parser("doctor", help="verify GitHub access, App identity, subscriptions, and models")
    labels_parser = commands.add_parser("labels", help="create or update the agent:* labels")
    labels_parser.add_argument("--apply", action="store_true", help="apply changes (default: describe only)")
    commands.add_parser("pause", help="pause the loop on this machine")
    commands.add_parser("resume", help="resume the loop on this machine")
    return parser


def configure_logging(verbosity: int, stream=None) -> None:
    """Send the dispatcher's progress log to ``stream`` (stderr by default); quiet unless ``verbosity`` is set."""
    logger = logging.getLogger("agent_loop")
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    if verbosity <= 0:
        logger.setLevel(logging.WARNING)
        logger.addHandler(logging.NullHandler())
        return
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s", datefmt="%H:%M:%S"))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbosity > 1 else logging.INFO)


def _print_tick(number: int, lines: list[str]) -> None:
    print(f"== tick {number}")
    for line in lines:
        print(line)
    sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "tick" and args.dry_run and args.repeat > 1:
        parser.error("--repeat cannot be combined with --dry-run: a dry run changes nothing, so it would repeat itself")
    configure_logging(args.verbose)
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
        if args.command == "tick" and args.repeat > 1:
            ran = run_ticks(runtime, args.repeat, args.interval, _print_tick)
            lines = [
                f"stopped after {ran} tick(s): " + ("nothing left to do" if not runtime.actionable else "limit reached")
            ]
        elif args.command == "tick":
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
