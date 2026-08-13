"""
Process-wide logging singleton.

Logging is a process-wide singleton, intentionally NOT part of ServerContext:
it must work before any context exists (early startup, arg parsing) and is
global to the process regardless of how many zones/contexts are served.
This is the bottom leaf of the import DAG: it imports nothing internal, so
every other adns.* module can depend on it.
"""

import sys
import syslog
import threading
import time


# Logging is a process-wide singleton, intentionally NOT part of ServerContext:
# it must work before any context exists (early startup, arg parsing) and is
# global to the process regardless of how many zones/contexts are served.
# _LOG_LOCK serializes concurrent foreground prints from worker threads. The
# defaults (foreground, LOG_INFO) apply until init_logging() reads the prefs;
# having them available at import time is what lets tests call log_message()
# without any setup.
_LOG_LOCK = threading.Lock()
_LOG_DAEMON = False
_LOG_PRI = syslog.LOG_INFO


def init_logging(prefs):
    """Configure the logging singleton from parsed preferences."""
    global _LOG_DAEMON, _LOG_PRI    # pylint: disable=global-statement
    _LOG_DAEMON = prefs.daemon
    _LOG_PRI = prefs.syslog_pri


def log_message(msg):
    """log informational message"""

    if _LOG_DAEMON:
        syslog.syslog(_LOG_PRI, msg)
    else:
        with _LOG_LOCK:
            print(msg)


def log_fatal(msg):
    """log fatal error message and bail out"""
    log_message(msg)
    sys.exit(1)


class RateLimitedLog:
    """Emit a message at most once per interval, with a suppressed-since count.

    Used for events that can recur at attacker-controlled rates (e.g. request
    shedding under the worker cap) so the log itself can't become an
    amplification/DoS vector."""

    def __init__(self, msg, interval=1.0):
        self.msg = msg
        self.interval = interval
        self.lock = threading.Lock()
        self.last = 0.0
        self.suppressed = 0

    def log(self):
        """Log now if the interval has elapsed, else just count the event."""
        with self.lock:
            now = time.monotonic()
            if now - self.last < self.interval:
                self.suppressed += 1
                return
            extra = f" ({self.suppressed} more since last message)" \
                if self.suppressed else ""
            self.last = now
            self.suppressed = 0
        log_message(f"warning: {self.msg}{extra}")
