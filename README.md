[![CI](https://github.com/0xcpu/defuse-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/0xcpu/defuse-monitor/actions/workflows/ci.yml)

# Defuse Monitor

A Linux login monitoring system that watches for user logins and sends alerts unless you defuse them within a specified time frame.

## How it works

Example:
1. You SSH into your server
2. The monitor detects your login and starts a countdown timer
3. You create a defuse artifact file before the timer runs out
4. If you don't defuse in time, it sends an alert (i.e. Discord webhook)

This way, you get notified of unauthorized logins while avoiding alerts for your own logins.

## Quick Start

```bash
# Install uv if needed
curl -LsSf https://astral.sh/uv/install.sh | sh

uv sync
# update defuse.toml config file, if necessary
make run
```

## Configuration

Edit `defuse.toml`:

```toml
[monitoring]
auth_log_path = "/var/log/auth.log"
wtmp_path = "/var/log/wtmp"
utmp_path = "/var/run/utmp"

[deduplication]
enabled = true
window_seconds = 10

[defuse]
timeout_seconds = 60
artifact_directory = "/var/run/defuse"

[alerts]
enabled = true

[alerts.discord]
enabled = true
webhook_url = "https://discord.com/api/webhooks/..."
```

## Usage

### Development

Tests were generated using Claude Code.

```bash
make test
make check
make run
```

### Deployment (systemd service)
```bash
# copy defuse-monitor.service from defuse-monitor/defuse-monitor.service
sudo cp defuse-monitor.service /etc/systemd/system/
sudo systemctl enable defuse-monitor
sudo systemctl start defuse-monitor
```

### Defusing a login

When you login, the monitor prints:
```
Waiting for artifact at: /var/run/defuse/{session_id}.key
```

To defuse:
```bash
touch /var/run/defuse/{session_id}.key
```

## What it monitors

- `/var/log/auth.log` - SSH, console, su, systemd logins
- `/var/log/wtmp` - All login/logout records
- `/var/run/utmp` - Currently logged in users

The system deduplicates events, so you only get one alert per login even though multiple sources detect it.

## Requirements

- Python 3.13+
- Linux (uses inotify for file monitoring)
- Access to `/var/log/auth.log`, `/var/log/wtmp`, `/var/run/utmp`

## License

See [LICENSE file](LICENSE).
