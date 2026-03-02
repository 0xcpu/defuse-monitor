from defuse_monitor.monitors.auth_log import AuthLogMonitor


def make_monitor() -> AuthLogMonitor:
    return AuthLogMonitor("/dev/null")


def test_systemd_login_strips_trailing_dot():
    monitor = make_monitor()
    line = "Mar  1 07:43:46 host systemd-logind[123]: New session 5 of user ubuntu."
    event = monitor.parse_line(line)
    assert event is not None
    assert event.username == "ubuntu"


def test_systemd_login_without_trailing_dot():
    monitor = make_monitor()
    line = "Mar  1 07:43:46 host systemd-logind[123]: New session 5 of user ubuntu"
    event = monitor.parse_line(line)
    assert event is not None
    assert event.username == "ubuntu"


def test_ssh_login_username_unaffected():
    """Regression: SSH usernames should not be modified."""
    monitor = make_monitor()
    line = "Mar  1 07:43:46 host sshd[456]: Accepted publickey for alice from 1.2.3.4"
    event = monitor.parse_line(line)
    assert event is not None
    assert event.username == "alice"


def test_systemd_login_username_with_internal_dot():
    """Interior dots in usernames must not be stripped (e.g. LDAP user.name)."""
    monitor = make_monitor()
    line = "Mar  1 07:43:46 host systemd-logind[123]: New session 5 of user user.name."
    event = monitor.parse_line(line)
    assert event is not None
    assert event.username == "user.name"
