"""Tests for agent loop configuration precedence and model-separation validation."""

from pathlib import Path

import pytest

from agent_loop.config import ConfigError, ModelRef, load_config, parse_model_ref

REPO_CONFIG = Path(__file__).resolve().parents[3] / ".github" / "agent-loop.toml"


def write(tmp_path, text):
    path = tmp_path / "agent-loop.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_repository_config_is_valid_and_uses_medium_non_frontier_models():
    config = load_config(REPO_CONFIG, environ={})

    assert config.stage("analysis").primary == ModelRef("claude", "claude-opus-5-5", "medium")
    assert config.stage("implementation").primary == ModelRef("codex", "gpt-6.1-sol", "medium")
    assert config.stage("feedback").primary == ModelRef("codex", "gpt-6.1-sol", "medium")
    assert config.stage("review").primary == ModelRef("claude", "claude-sonnet-5-5", "medium")
    assert config.github.repo == "JCallico/imap-migration-tools"
    assert config.github.enabled_since is not None


def test_builtin_defaults_match_repository_config(tmp_path):
    defaults = load_config(environ={})
    repo = load_config(REPO_CONFIG, environ={})

    assert dict(defaults.stages) == dict(repo.stages)


def test_precedence_file_then_environment_then_command_line(tmp_path):
    path = write(tmp_path, '[stages.review]\nengine = "claude"\nmodel = "claude-from-file"\neffort = "low"\n')

    from_file = load_config(path, environ={})
    from_env = load_config(path, environ={"AGENT_LOOP_REVIEW_MODEL": "claude-from-env"})
    from_cli = load_config(
        path,
        environ={"AGENT_LOOP_REVIEW_MODEL": "claude-from-env"},
        stage_overrides=["review=claude:claude-from-cli"],
    )

    assert from_file.stage("review").primary == ModelRef("claude", "claude-from-file", "low")
    assert from_env.stage("review").primary == ModelRef("claude", "claude-from-env", "low")
    assert from_cli.stage("review").primary == ModelRef("claude", "claude-from-cli", "low")


def test_config_path_from_environment(tmp_path):
    path = write(tmp_path, '[notify]\nmention = ["someone"]\n')

    config = load_config(environ={"AGENT_LOOP_CONFIG": str(path)})

    assert config.notify.mention == ("someone",)
    assert config.source == path


def test_review_model_equal_to_implementation_model_is_rejected():
    with pytest.raises(ConfigError, match="must differ from the implementation model"):
        load_config(environ={}, stage_overrides=["review=codex:gpt-6.1-sol:medium"])


def test_review_vendor_must_differ_by_default():
    with pytest.raises(ConfigError, match="different vendor"):
        load_config(environ={}, stage_overrides=["review=codex:gpt-6-sol:medium"])


def test_same_vendor_different_model_allowed_when_vendor_rule_disabled(tmp_path):
    path = write(tmp_path, "[policy]\nrequire_distinct_review_vendor = false\n")

    config = load_config(path, environ={}, stage_overrides=["review=codex:gpt-6-sol:medium"])

    assert config.stage("review").primary.model == "gpt-6-sol"


def test_distinct_model_rule_cannot_be_disabled(tmp_path):
    path = write(tmp_path, "[policy]\nrequire_distinct_review_model = false\n")

    with pytest.raises(ConfigError, match="cannot be disabled"):
        load_config(path, environ={})


@pytest.mark.parametrize(
    "text, message",
    [
        ("[stages.reviewer]\nmodel = 'x'\n", "unknown stage"),
        ("[stages.review]\nmodle = 'x'\n", "unknown key"),
        ("[stages.review]\neffort = 'extreme'\n", "invalid effort"),
        ("[stages.review]\nengine = 'gemini'\n", "unknown engine"),
        ("[stages.review]\non_exhausted = 'retry'\n", "on_exhausted"),
        ("[quota]\nlow_threshold_percent = 150\n", "low_threshold_percent"),
        ("[notify]\nbackends = ['telegram']\n", "unsupported backend"),
        ("[github]\nrepo = 'no-slash'\n", "owner/name"),
        ("[github]\nenabled_since = 'yesterday'\n", "ISO 8601"),
    ],
)
def test_invalid_configuration_is_rejected(tmp_path, text, message):
    with pytest.raises(ConfigError, match=message):
        load_config(write(tmp_path, text), environ={})


def test_effort_is_validated_per_engine():
    assert parse_model_ref("claude:claude-opus-5-5:max").effort == "max"
    with pytest.raises(ConfigError):
        parse_model_ref("codex:gpt-6.1-sol:max")


def test_github_app_settings_come_from_environment(tmp_path):
    config = load_config(
        environ={
            "AGENT_LOOP_APP_ID": "123",
            "AGENT_LOOP_APP_INSTALLATION_ID": "456",
            "AGENT_LOOP_APP_PRIVATE_KEY_PATH": str(tmp_path / "app.pem"),
            "AGENT_LOOP_PAUSED": "true",
            "AGENT_LOOP_STATE_DIR": str(tmp_path / "state"),
        }
    )

    assert (config.github.app_id, config.github.installation_id) == ("123", "456")
    assert config.github.private_key_path == tmp_path / "app.pem"
    assert config.paused is True
    assert config.resolved_state_dir() == tmp_path / "state"


def test_fallbacks_only_used_when_on_exhausted_is_fallback(tmp_path):
    path = write(
        tmp_path,
        "[stages.analysis]\nfallbacks = ['codex:gpt-6.1-sol:medium']\n"
        "[stages.summarize]\non_exhausted = 'fallback'\nfallbacks = ['codex:gpt-6-luna:low']\n",
    )

    config = load_config(path, environ={})

    assert config.stage("analysis").candidates == (config.stage("analysis").primary,)
    assert len(config.stage("summarize").candidates) == 2
