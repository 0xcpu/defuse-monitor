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


def test_su_util_linux_login():
    """Modern util-linux su logs '(to <target>) <user> on <tty>'."""
    monitor = make_monitor()
    line = "Mar  1 07:43:46 host su[2731]: (to root) cpu on pts/1"
    event = monitor.parse_line(line)
    assert event is not None
    assert event.username == "root"
    assert event.login_type == "su"


def test_read_new_content_resets_on_truncation(tmp_path):
    """copytruncate leaves a stale position larger than the file size."""
    log_file = tmp_path / "auth.log"
    line = "Mar  1 07:43:46 host sshd[456]: Accepted publickey for alice from 1.2.3.4\n"
    log_file.write_text(line)
    monitor = AuthLogMonitor(str(log_file))

    events, position, partial_line = monitor._read_new_content(99999, "")

    assert len(events) == 1
    assert events[0].username == "alice"
    assert position == len(line)
    assert partial_line == ""
