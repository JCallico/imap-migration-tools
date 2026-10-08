"""Agent loop configuration: loading, precedence, and model-separation validation.

Precedence, highest first: command-line stage overrides, ``AGENT_LOOP_*`` environment variables, the TOML file, then
built-in defaults.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on Python 3.10 only
    import tomli as tomllib

DEFAULT_CONFIG_PATH = Path(".github") / "agent-loop.toml"

ENGINE_VENDORS = {"codex": "openai", "claude": "anthropic"}
ENGINE_EFFORTS = {
    "codex": ("minimal", "low", "medium", "high", "xhigh"),
    "claude": ("low", "medium", "high", "xhigh", "max"),
}
STAGES = ("analysis", "implementation", "feedback", "ci_fix", "review", "summarize")
# Stages whose model commits code to a pull request; the reviewer must differ from all of them.
AUTHOR_STAGES = ("implementation", "feedback", "ci_fix")
# Stages that should not start on an engine whose quota is already low.
LONG_STAGES = ("analysis", "implementation")
ON_EXHAUSTED = ("wait", "fallback")


class ConfigError(ValueError):
    """Raised when the agent loop configuration is invalid."""


@dataclass(frozen=True)
class ModelRef:
    """An engine, model, and reasoning effort used for one model invocation."""

    engine: str
    model: str
    effort: str

    @property
    def vendor(self) -> str:
        return ENGINE_VENDORS[self.engine]

    @property
    def key(self) -> tuple[str, str]:
        """Identity used for the distinct-model rule; effort does not make a model distinct."""
        return (self.engine, self.model)

    def __str__(self) -> str:
        return f"{self.engine}:{self.model}:{self.effort}"


@dataclass(frozen=True)
class StageConfig:
    name: str
    primary: ModelRef
    on_exhausted: str = "wait"
    fallbacks: tuple[ModelRef, ...] = ()

    @property
    def candidates(self) -> tuple[ModelRef, ...]:
        """Models this stage may use, in order of preference."""
        if self.on_exhausted == "fallback":
            return (self.primary, *self.fallbacks)
        return (self.primary,)


@dataclass(frozen=True)
class PolicyConfig:
    require_distinct_review_model: bool = True
    require_distinct_review_vendor: bool = True
    max_ai_review_rounds: int = 3
    max_concurrent_implementations: int = 1
    max_reanalyses_without_admin: int = 2
    max_diff_lines: int = 1500


@dataclass(frozen=True)
class QuotaConfig:
    low_threshold_percent: float = 80.0
    reserve_for_inflight: bool = True
    unknown_backoff_max_hours: float = 6.0
    max_stage_minutes: int = 90
    max_turns: int = 200


@dataclass(frozen=True)
class NotifyConfig:
    backends: tuple[str, ...] = ("github",)
    mention: tuple[str, ...] = ()
    admin_delay_alert_hours: float = 12.0


@dataclass(frozen=True)
class GitHubConfig:
    repo: str | None = None
    bot_login: str | None = None
    allowed_admins: tuple[str, ...] = ()
    enabled_since: datetime | None = None
    app_id: str | None = None
    installation_id: str | None = None
    private_key_path: Path | None = None


@dataclass(frozen=True)
class LoopConfig:
    stages: Mapping[str, StageConfig]
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    quota: QuotaConfig = field(default_factory=QuotaConfig)
    notify: NotifyConfig = field(default_factory=NotifyConfig)
    github: GitHubConfig = field(default_factory=GitHubConfig)
    paused: bool = False
    state_dir: Path | None = None
    env_passthrough: tuple[str, ...] = ()
    source: Path | None = None

    def stage(self, name: str) -> StageConfig:
        return self.stages[name]

    def resolved_state_dir(self) -> Path:
        """Return the local state directory, partitioned per repository."""
        if self.state_dir is not None:
            return self.state_dir
        base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
        repo = (self.github.repo or "default").replace("/", "-")
        return base / "agent-loop" / repo


DEFAULT_STAGES: dict[str, StageConfig] = {
    "analysis": StageConfig("analysis", ModelRef("claude", "claude-opus-5-5", "medium")),
    "implementation": StageConfig("implementation", ModelRef("codex", "gpt-6.1-sol", "medium")),
    "feedback": StageConfig("feedback", ModelRef("codex", "gpt-6.1-sol", "medium")),
    "ci_fix": StageConfig("ci_fix", ModelRef("codex", "gpt-6.1-sol", "medium")),
    "review": StageConfig("review", ModelRef("claude", "claude-sonnet-5-5", "medium")),
    "summarize": StageConfig(
        "summarize",
        ModelRef("claude", "claude-haiku-4-5-20251001", "low"),
        on_exhausted="fallback",
        fallbacks=(ModelRef("codex", "gpt-6-luna", "low"),),
    ),
}


def parse_model_ref(text: str, default_effort: str | None = None) -> ModelRef:
    """Parse ``engine:model[:effort]`` into a validated :class:`ModelRef`."""
    parts = text.strip().split(":")
    if len(parts) not in (2, 3) or not all(parts):
        raise ConfigError(f"invalid model reference {text!r}; expected engine:model[:effort]")
    engine, model = parts[0], parts[1]
    effort = parts[2] if len(parts) == 3 else default_effort
    if engine not in ENGINE_VENDORS:
        raise ConfigError(f"unknown engine {engine!r} in {text!r}; expected one of {sorted(ENGINE_VENDORS)}")
    if effort is None or effort not in ENGINE_EFFORTS[engine]:
        effort = _default_effort(engine, effort, text)
    return ModelRef(engine, model, effort)


def _default_effort(engine: str, effort: str | None, text: str) -> str:
    if effort is None:
        return "medium"
    raise ConfigError(f"invalid effort {effort!r} for {engine} in {text!r}; expected one of {ENGINE_EFFORTS[engine]}")


def _parse_bool(value: str, name: str) -> bool:
    lowered = value.strip().lower()
    if lowered in ("1", "true", "yes", "on"):
        return True
    if lowered in ("0", "false", "no", "off", ""):
        return False
    raise ConfigError(f"{name} must be a boolean, got {value!r}")


def _parse_datetime(value: Any, name: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise ConfigError(f"{name} must be an ISO 8601 timestamp, got {value!r}") from exc
    else:
        raise ConfigError(f"{name} must be an ISO 8601 timestamp, got {value!r}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _check_keys(section: Mapping[str, Any], allowed: Iterable[str], where: str) -> None:
    unknown = sorted(set(section) - set(allowed))
    if unknown:
        raise ConfigError(f"unknown key(s) in {where}: {', '.join(unknown)}")


def _stage_from_table(name: str, table: Mapping[str, Any], base: StageConfig) -> StageConfig:
    _check_keys(table, ("engine", "model", "effort", "on_exhausted", "fallbacks"), f"[stages.{name}]")
    engine = str(table.get("engine", base.primary.engine))
    model = str(table.get("model", base.primary.model))
    effort = table.get("effort")
    if effort is None:
        effort = base.primary.effort if engine == base.primary.engine else None
    primary = parse_model_ref(f"{engine}:{model}", default_effort=effort)
    on_exhausted = str(table.get("on_exhausted", base.on_exhausted))
    if on_exhausted not in ON_EXHAUSTED:
        raise ConfigError(f"[stages.{name}] on_exhausted must be one of {ON_EXHAUSTED}, got {on_exhausted!r}")
    if "fallbacks" in table:
        raw = table["fallbacks"]
        if not isinstance(raw, list):
            raise ConfigError(f"[stages.{name}] fallbacks must be a list of engine:model[:effort] strings")
        fallbacks = tuple(parse_model_ref(str(item)) for item in raw)
    else:
        fallbacks = base.fallbacks
    return StageConfig(name, primary, on_exhausted, fallbacks)


def _dataclass_from_table(cls: type, table: Mapping[str, Any], where: str) -> Any:
    instance = cls()
    _check_keys(table, instance.__dataclass_fields__, where)
    values: dict[str, Any] = {}
    for key, value in table.items():
        current = getattr(instance, key)
        if isinstance(current, bool):
            if not isinstance(value, bool):
                raise ConfigError(f"{where} {key} must be a boolean")
        elif isinstance(current, (int, float)):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ConfigError(f"{where} {key} must be a number")
            value = type(current)(value)
        elif isinstance(current, tuple):
            if not isinstance(value, list):
                raise ConfigError(f"{where} {key} must be a list")
            value = tuple(str(item) for item in value)
        values[key] = value
    return replace(instance, **values)


def _github_from_table(table: Mapping[str, Any]) -> GitHubConfig:
    _check_keys(table, GitHubConfig.__dataclass_fields__, "[github]")
    values: dict[str, Any] = {}
    for key in ("repo", "bot_login", "app_id", "installation_id"):
        if key in table:
            values[key] = str(table[key])
    if "allowed_admins" in table:
        values["allowed_admins"] = tuple(str(item) for item in table["allowed_admins"])
    if "enabled_since" in table:
        values["enabled_since"] = _parse_datetime(table["enabled_since"], "[github] enabled_since")
    if "private_key_path" in table:
        values["private_key_path"] = Path(str(table["private_key_path"])).expanduser()
    return GitHubConfig(**values)


def _apply_file(data: Mapping[str, Any]) -> dict[str, Any]:
    _check_keys(data, ("stages", "policy", "quota", "notify", "github", "loop"), "configuration")
    stages = dict(DEFAULT_STAGES)
    for name, table in (data.get("stages") or {}).items():
        if name not in STAGES:
            raise ConfigError(f"unknown stage [stages.{name}]; expected one of {STAGES}")
        stages[name] = _stage_from_table(name, table, stages[name])
    result: dict[str, Any] = {"stages": stages}
    if "policy" in data:
        result["policy"] = _dataclass_from_table(PolicyConfig, data["policy"], "[policy]")
    if "quota" in data:
        result["quota"] = _dataclass_from_table(QuotaConfig, data["quota"], "[quota]")
    if "notify" in data:
        result["notify"] = _dataclass_from_table(NotifyConfig, data["notify"], "[notify]")
    if "github" in data:
        result["github"] = _github_from_table(data["github"])
    loop = data.get("loop") or {}
    _check_keys(loop, ("paused", "state_dir", "env_passthrough"), "[loop]")
    if "paused" in loop:
        result["paused"] = bool(loop["paused"])
    if "state_dir" in loop:
        result["state_dir"] = Path(str(loop["state_dir"])).expanduser()
    if "env_passthrough" in loop:
        result["env_passthrough"] = tuple(str(item) for item in loop["env_passthrough"])
    return result


def _apply_environment(config: LoopConfig, environ: Mapping[str, str]) -> LoopConfig:
    stages = dict(config.stages)
    for name in STAGES:
        prefix = f"AGENT_LOOP_{name.upper()}_"
        engine = environ.get(prefix + "ENGINE")
        model = environ.get(prefix + "MODEL")
        effort = environ.get(prefix + "EFFORT")
        if engine is None and model is None and effort is None:
            continue
        current = stages[name].primary
        new_engine = engine or current.engine
        new_effort = effort or (current.effort if new_engine == current.engine else None)
        primary = parse_model_ref(f"{new_engine}:{model or current.model}", default_effort=new_effort)
        stages[name] = replace(stages[name], primary=primary)
    github = config.github
    github_env = {
        "repo": environ.get("AGENT_LOOP_REPO"),
        "bot_login": environ.get("AGENT_LOOP_BOT_LOGIN"),
        "app_id": environ.get("AGENT_LOOP_APP_ID"),
        "installation_id": environ.get("AGENT_LOOP_APP_INSTALLATION_ID"),
    }
    github = replace(github, **{key: value for key, value in github_env.items() if value})
    key_path = environ.get("AGENT_LOOP_APP_PRIVATE_KEY_PATH")
    if key_path:
        github = replace(github, private_key_path=Path(key_path).expanduser())
    paused = config.paused
    if "AGENT_LOOP_PAUSED" in environ:
        paused = _parse_bool(environ["AGENT_LOOP_PAUSED"], "AGENT_LOOP_PAUSED")
    state_dir = config.state_dir
    if environ.get("AGENT_LOOP_STATE_DIR"):
        state_dir = Path(environ["AGENT_LOOP_STATE_DIR"]).expanduser()
    return replace(config, stages=stages, github=github, paused=paused, state_dir=state_dir)


def _apply_overrides(config: LoopConfig, overrides: Iterable[str]) -> LoopConfig:
    stages = dict(config.stages)
    for override in overrides:
        name, sep, ref = override.partition("=")
        name = name.strip()
        if not sep or name not in STAGES:
            raise ConfigError(f"invalid --stage-model {override!r}; expected <stage>=<engine>:<model>[:<effort>]")
        current = stages[name].primary
        parsed = parse_model_ref(ref)
        if len(ref.split(":")) == 2 and parsed.engine == current.engine:
            parsed = replace(parsed, effort=current.effort)
        stages[name] = replace(stages[name], primary=parsed)
    return replace(config, stages=stages)


def validate(config: LoopConfig) -> None:
    """Enforce the policy rules that must hold before any stage runs."""
    errors: list[str] = []
    policy = config.policy
    if not policy.require_distinct_review_model:
        errors.append("[policy] require_distinct_review_model cannot be disabled")
    review = config.stages["review"].primary
    for name in AUTHOR_STAGES:
        author = config.stages[name].primary
        if author.key == review.key:
            errors.append(f"review model {review} must differ from the {name} model {author}")
        elif policy.require_distinct_review_vendor and author.vendor == review.vendor:
            errors.append(
                f"review model {review} must come from a different vendor than the {name} model {author} "
                "(set [policy] require_distinct_review_vendor = false to allow a different model of the same vendor)"
            )
    if not 0 < config.quota.low_threshold_percent <= 100:
        errors.append("[quota] low_threshold_percent must be between 0 and 100")
    if config.quota.max_stage_minutes <= 0:
        errors.append("[quota] max_stage_minutes must be positive")
    if policy.max_ai_review_rounds < 1:
        errors.append("[policy] max_ai_review_rounds must be at least 1")
    unknown_backends = sorted(set(config.notify.backends) - {"github"})
    if unknown_backends:
        errors.append(f"[notify] unsupported backend(s): {', '.join(unknown_backends)}")
    if config.github.repo is not None and config.github.repo.count("/") != 1:
        errors.append(f"[github] repo must be owner/name, got {config.github.repo!r}")
    if errors:
        raise ConfigError("; ".join(errors))


def load_config(
    path: Path | str | None = None,
    environ: Mapping[str, str] | None = None,
    stage_overrides: Iterable[str] = (),
) -> LoopConfig:
    """Load, merge, and validate the agent loop configuration."""
    environ = os.environ if environ is None else environ
    if path is None and environ.get("AGENT_LOOP_CONFIG"):
        path = environ["AGENT_LOOP_CONFIG"]
    source: Path | None = None
    values: dict[str, Any] = {"stages": dict(DEFAULT_STAGES)}
    if path is not None:
        source = Path(path)
        if not source.is_file():
            raise ConfigError(f"configuration file not found: {source}")
    elif DEFAULT_CONFIG_PATH.is_file():
        source = DEFAULT_CONFIG_PATH
    if source is not None:
        try:
            with source.open("rb") as handle:
                data = tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{source}: {exc}") from exc
        values.update(_apply_file(data))
    config = LoopConfig(**values, source=source)
    config = _apply_environment(config, environ)
    config = _apply_overrides(config, stage_overrides)
    validate(config)
    return config
