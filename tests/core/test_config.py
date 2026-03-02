from defuse_monitor.core.config import AlertsConfig, Config


def test_ignored_login_types_defaults_to_empty():
    cfg = AlertsConfig()
    assert cfg.ignored_login_types == []


def test_ignored_login_types_can_be_set():
    cfg = AlertsConfig(ignored_login_types=["console", "other"])
    assert cfg.ignored_login_types == ["console", "other"]


def test_config_loads_ignored_login_types(tmp_path):
    toml_file = tmp_path / "defuse.toml"
    toml_file.write_text(
        "[alerts]\nignored_login_types = [\"console\", \"other\"]\n"
        "[alerts.discord]\nenabled = false\n"
    )
    config = Config.load(toml_file)
    assert config.alerts.ignored_login_types == ["console", "other"]
