"""Entry point for the defuse monitor application."""

import argparse
import asyncio
import logging
import secrets
import signal
import sys
from collections.abc import AsyncIterator, Awaitable, Callable
from enum import Enum
from pathlib import Path

from .alerts.dispatcher import AlertDispatcher
from .core.config import Config
from .core.deduplicator import EventDeduplicator
from .core.dispatcher import EventDispatcher
from .core.events import LoginEvent
from .defuse.handler import DefuseHandler
from .monitors.accounting import AccountingFilesMonitor
from .monitors.auth_log import AuthLogMonitor

logger = logging.getLogger(__name__)


class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


def _initialize_components(
    config: Config,
) -> tuple[EventDispatcher, EventDeduplicator | None, DefuseHandler, AlertDispatcher]:
    """Initialize all system components."""
    event_dispatcher = EventDispatcher()

    deduplicator = None
    if config.deduplication.enabled:
        deduplicator = EventDeduplicator(
            window_seconds=config.deduplication.window_seconds
        )
        logger.info(
            "Event deduplication enabled (window: %ss)",
            config.deduplication.window_seconds,
        )
    else:
        logger.info("Event deduplication disabled")

    secret = config.defuse.secret or secrets.token_hex(16)
    if not config.defuse.secret:
        logger.warning(
            "No defuse secret configured; generated an ephemeral per-run secret. "
            "The defuse artifact filename is logged when a login is detected."
        )
    defuse_handler = DefuseHandler(
        timeout_seconds=config.defuse.timeout_seconds,
        artifact_directory=config.defuse.artifact_directory,
        secret=secret,
    )
    alert_dispatcher = AlertDispatcher(
        discord_enabled=config.alerts.discord.enabled,
        webhook_url=config.alerts.discord.webhook_url,
    )
    return event_dispatcher, deduplicator, defuse_handler, alert_dispatcher


def _create_login_event_handler(
    defuse_handler: DefuseHandler, alert_dispatcher: AlertDispatcher, config: Config
) -> Callable[[LoginEvent], Awaitable[None]]:
    """Create the login event handler."""

    async def handle_login_event(event: LoginEvent):
        """Handle a detected login event."""
        if event.login_type in config.alerts.ignored_login_types:
            logger.debug(
                "Ignoring login type %s for user %s (filtered by config)",
                event.login_type,
                event.username,
            )
            return

        logger.info(
            "Login detected: %s via %s from %s",
            event.username,
            event.login_type,
            event.source_ip or "local",
        )

        defused = await defuse_handler.initiate_defuse(event)

        if not defused and config.alerts.enabled:
            await alert_dispatcher.send_alert(event)

    return handle_login_event


def _initialize_monitors(config: Config) -> list[tuple[str, AsyncIterator[LoginEvent]]]:
    """Initialize all monitoring components."""
    monitors = []

    if Path(config.monitoring.auth_log_path).exists():
        auth_monitor = AuthLogMonitor(config.monitoring.auth_log_path)
        monitors.append(("auth_log", auth_monitor.monitor()))
        logger.info("Auth log monitor initialized: %s", config.monitoring.auth_log_path)
    else:
        logger.warning("Auth log file not found: %s", config.monitoring.auth_log_path)

    if Path(config.monitoring.wtmp_path).exists():
        accounting_monitor = AccountingFilesMonitor(
            wtmp_path=config.monitoring.wtmp_path,
            utmp_path=config.monitoring.utmp_path,
        )
        monitors.append(("wtmp", accounting_monitor.monitor_wtmp()))
        logger.info("wtmp monitor initialized: %s", config.monitoring.wtmp_path)
    else:
        logger.warning("wtmp file not found: %s", config.monitoring.wtmp_path)

    if Path(config.monitoring.utmp_path).exists():
        # Reuse the same monitor instance if wtmp exists
        if not any(name == "wtmp" for name, _ in monitors):
            accounting_monitor = AccountingFilesMonitor(
                wtmp_path=config.monitoring.wtmp_path,
                utmp_path=config.monitoring.utmp_path,
            )
        monitors.append(("utmp", accounting_monitor.monitor_utmp()))
        logger.info("utmp monitor initialized: %s", config.monitoring.utmp_path)
    else:
        logger.warning("utmp file not found: %s", config.monitoring.utmp_path)

    return monitors


def _create_monitor_tasks(
    monitors,
    event_dispatcher,
    deduplicator: EventDeduplicator | None,
    ignored_login_types=None,
) -> list[asyncio.Task]:
    """Create monitoring tasks for all monitors."""
    tasks = []

    async def monitor_wrapper(name, async_gen):
        logger.info("Starting monitor: %s", name)
        dispatch_tasks: set[asyncio.Task] = set()
        try:
            async for event in async_gen:
                logger.debug("Monitor %s received event: %s", name, event)

                if ignored_login_types and event.login_type in ignored_login_types:
                    logger.debug(
                        "Ignoring login type %s for user %s (filtered by config)",
                        event.login_type,
                        event.username,
                    )
                    continue

                if deduplicator:
                    processed_event = await deduplicator.process_event(event)
                    if processed_event is None:
                        logger.debug("Skipped duplicate event from %s", name)
                        continue

                    event = processed_event

                task = asyncio.create_task(event_dispatcher.dispatch(event))
                dispatch_tasks.add(task)
                task.add_done_callback(dispatch_tasks.discard)

            logger.warning("Monitor %s stopped producing events", name)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("Monitor %s failed: %s", name, e, exc_info=True)
            logger.warning("Monitor %s will not be restarted automatically", name)
        finally:
            pending = list(dispatch_tasks)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

    for monitor_name, monitor_async_gen in monitors:
        task = asyncio.create_task(monitor_wrapper(monitor_name, monitor_async_gen))
        tasks.append(task)

    return tasks


def _setup_signal_handlers() -> asyncio.Event:
    """Setup signal handlers for graceful shutdown."""
    shutdown_event = asyncio.Event()

    def signal_handler():
        logger.info("Shutdown signal received")
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

    return shutdown_event


async def _shutdown_tasks(tasks: list[asyncio.Task]):
    """Shutdown all monitoring tasks gracefully."""
    logger.info("Shutting down monitors...")

    for task in tasks:
        task.cancel()

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    logger.info("Shutdown complete")


async def main_loop(config: Config):
    """Main monitoring loop."""
    logger.info("Starting Defuse Monitor main loop")

    (
        event_dispatcher,
        deduplicator,
        defuse_handler,
        alert_dispatcher,
    ) = _initialize_components(config)
    handle_login_event = _create_login_event_handler(
        defuse_handler, alert_dispatcher, config
    )
    event_dispatcher.register_handler(handle_login_event)

    monitors = _initialize_monitors(config)
    if not monitors:
        logger.error("No monitors could be initialized")
        return

    tasks = _create_monitor_tasks(
        monitors,
        event_dispatcher,
        deduplicator,
        config.alerts.ignored_login_types,
    )
    logger.info("Started %d monitoring tasks", len(tasks))

    shutdown_event = _setup_signal_handlers()
    try:
        await shutdown_event.wait()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    finally:
        await _shutdown_tasks(tasks)
        await alert_dispatcher.close()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Defuse Monitor - Linux Login Monitoring"
    )
    parser.add_argument(
        "--config", type=Path, default="defuse.toml", help="Path to configuration file"
    )
    parser.add_argument(
        "--log-level",
        choices=[level.value for level in LogLevel],
        default=None,
        help="Logging level (overrides the config file when provided)",
    )

    args = parser.parse_args()

    try:
        config = Config.load(args.config)

        level_name = args.log_level if args.log_level else config.logging.level
        log_level = getattr(logging, level_name)

        logging.basicConfig(
            level=log_level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )

        logger.info("Configuration loaded from: %s", args.config)
        logger.info("Logging level set to: %s", logging.getLevelName(log_level))

        asyncio.run(main_loop(config))

    except FileNotFoundError as e:
        logger.error("Configuration file not found: %s", e)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error("Fatal error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
