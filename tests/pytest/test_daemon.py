"""
Daemon-mode lifecycle: daemonization, pidfile handling, the inherited-fd
close, and SIGTERM shutdown/cleanup.

The rest of the suite runs the server in the foreground (-f), so none of the
daemon path is otherwise exercised -- yet that path is exactly what produced
the pidfile bugs fixed in v0.7.5/0.7.6 and the fd-close rework in v0.7.7. These
tests cover it in three tiers:

  1. Pure functions (get_pid_file, remove_pidfile) imported directly.
  2. close_inherited_fds() driven in a subprocess (it closes fd 3+, which would
     clobber pytest's own descriptors if run in-process).
  3. A full launch-daemonize-query-SIGTERM lifecycle over a real subprocess.

Root is deliberately NOT required. The two privileged operations -- binding a
low port and dropping uid/gid -- are avoided by using an ephemeral loopback
port and omitting user/group from the config (so drop_privs() is never called).
drop_privs() itself is therefore not covered here; it genuinely needs root.
"""

import os
import signal
import socket
import subprocess
import sys
import textwrap
import time

import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..")))
import adns_server as adns   # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
SERVER = os.path.join(REPO_ROOT, "adns_server.py")
ZONE_DIR = os.path.join(HERE, "test_zones")


# --------------------------------------------------------------------------
# Tier 1: pure functions
# --------------------------------------------------------------------------

def test_get_pid_file_explicit():
    """An explicit pidfile preference wins over everything else."""
    prefs = adns.Preferences()
    prefs.pidfile = "/var/run/custom.pid"
    prefs.workdir = "/some/workdir"
    assert adns.get_pid_file(prefs) == "/var/run/custom.pid"


def test_get_pid_file_workdir():
    """With no explicit pidfile, it lands in the working directory."""
    prefs = adns.Preferences()
    prefs.pidfile = None
    prefs.workdir = "/some/workdir"
    assert adns.get_pid_file(prefs) == os.path.join("/some/workdir",
                                                    "daemon.pid")


def test_get_pid_file_fallback():
    """With neither pidfile nor workdir set, it falls back to /tmp."""
    prefs = adns.Preferences()
    prefs.pidfile = None
    prefs.workdir = None
    assert adns.get_pid_file(prefs) == f"/tmp/{adns.PROGNAME}.pid"


def test_remove_pidfile_removes_existing(tmp_path):
    """remove_pidfile unlinks a file that is present."""
    pidfile = tmp_path / "daemon.pid"
    pidfile.write_text("12345\n")
    adns.remove_pidfile(str(pidfile))
    assert not pidfile.exists()


def test_remove_pidfile_missing_is_silent(tmp_path):
    """A missing pidfile is tolerated (FileNotFoundError swallowed)."""
    adns.remove_pidfile(str(tmp_path / "does-not-exist.pid"))  # must not raise


def test_remove_pidfile_logs_other_errors(tmp_path, monkeypatch):
    """A non-ENOENT OSError is logged, not swallowed and not raised.

    This is the exact silent-swallow that hid the v0.7.6 privilege-drop
    unlink failure. We simulate an EACCES by making os.remove raise it and
    assert the message reaches log_message rather than propagating."""
    logged = []
    monkeypatch.setattr(adns, "log_message", logged.append)

    def _boom(_path):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(adns.os, "remove", _boom)

    adns.remove_pidfile(str(tmp_path / "daemon.pid"))   # must not raise
    assert logged and "could not remove pidfile" in logged[0]


# --------------------------------------------------------------------------
# Tier 2: close_inherited_fds() in a subprocess
# --------------------------------------------------------------------------

def test_close_inherited_fds_subprocess():
    """close_inherited_fds() closes fd 3+ but leaves 0/1/2 usable.

    Run in a child process: closing fd 3+ in-process would break pytest's own
    descriptors. The child opens an extra fd (>=3), calls the helper, and
    reports via exit code whether that fd is now closed and 0/1/2 still valid.
    """
    child = textwrap.dedent(f"""
        import os, sys
        sys.path.insert(0, {REPO_ROOT!r})
        import adns_server as adns

        # Open a real fd we know is >= 3.
        fd = os.open(os.devnull, os.O_RDWR)
        assert fd >= 3, fd

        adns.close_inherited_fds()

        # The extra fd must now be closed.
        try:
            os.fstat(fd)
            sys.exit(10)          # still open -> failure
        except OSError:
            pass

        # 0/1/2 must still be valid descriptors (the caller reopens them to
        # /dev/null; here we just confirm the helper did not close them).
        for std in (0, 1, 2):
            try:
                os.fstat(std)
            except OSError:
                sys.exit(20 + std)
        sys.exit(0)
    """)
    result = subprocess.run([sys.executable, "-c", child],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, (
        f"child failed rc={result.returncode}\n"
        f"stdout={result.stdout}\nstderr={result.stderr}")


# --------------------------------------------------------------------------
# Tier 3: full daemon lifecycle
# --------------------------------------------------------------------------

def _free_port():
    """Return an unused UDP port on the loopback interface."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def _write_daemon_config(tmp_path, port, pidfile):
    """Write a minimal daemon-mode config (no user/group -> no drop_privs).

    Reuses the existing unsigned.test zone (no signing overhead). Launched with
    cwd=ZONE_DIR so the relative zone path resolves as in the main suite."""
    config = tmp_path / "daemon.yaml"
    config.write_text(textwrap.dedent(f"""\
        config:
          port: {port}
          pidfile: "{pidfile}"
          minimal_any: false
        zones:
          - name: "unsigned.test"
            file: "unsigned.test/zonefile"
            dnssec: false
    """))
    return config


def _pid_alive(pid):
    """True if the process is still alive (signal 0 probe)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True          # exists but not ours (won't happen here)
    return True


def _wait_for(predicate, timeout=10.0, interval=0.05):
    """Poll predicate() until truthy or timeout; return its final value."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return predicate()


def _query_soa(port):
    """Send a UDP SOA query for unsigned.test; return the response or None."""
    msg = dns.message.make_query(dns.name.from_text("unsigned.test."),
                                 dns.rdatatype.SOA)
    try:
        return dns.query.udp(msg, "127.0.0.1", port=port, timeout=1.0)
    except (dns.exception.Timeout, OSError):
        return None


def test_daemon_lifecycle(tmp_path):
    """Launch in daemon mode; verify pidfile, service, and SIGTERM cleanup.

    The launched process double-forks and its first-fork parent exits 0, so the
    Popen child is NOT the daemon -- we recover the daemon's pid from the
    pidfile and drive it with signals.
    """
    port = _free_port()
    pidfile = tmp_path / "daemon.pid"
    config = _write_daemon_config(tmp_path, port, str(pidfile))

    # No -f: the server daemonizes. -d for verbose logging (goes to syslog once
    # daemonized, so we don't capture it here).
    with subprocess.Popen(
            [sys.executable, SERVER, "-c", str(config),
             "-s", "127.0.0.1", "-p", str(port), "-d"],
            cwd=ZONE_DIR, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL) as proc:
        # The launcher (first-fork parent) detaches and exits 0 promptly.
        assert proc.wait(timeout=10) == 0

    try:
        _drive_daemon_lifecycle(port, pidfile)
    finally:
        # Best-effort cleanup if an assertion left the daemon running.
        if pidfile.exists():
            try:
                os.kill(int(pidfile.read_text().strip()), signal.SIGKILL)
            except (OSError, ValueError):
                pass


def _drive_daemon_lifecycle(port, pidfile):
    """Assert the daemon writes its pidfile, serves, and cleans up on SIGTERM."""
    # The daemon writes the pidfile after the second fork.
    assert _wait_for(pidfile.exists), "pidfile was not created"
    pid = int(pidfile.read_text().strip())
    assert _pid_alive(pid), "daemon pid is not alive"

    # It must actually be serving -- sockets are opened AFTER the fd-close and
    # /dev/null reopen, so a good answer proves that sequence worked.
    resp = _wait_for(lambda: _query_soa(port))
    assert resp is not None, "daemon did not answer a query"
    assert resp.rcode() == dns.rcode.NOERROR

    # SIGTERM -> clean exit AND pidfile removal (the v0.7.5/0.7.6 fixes).
    os.kill(pid, signal.SIGTERM)
    assert _wait_for(lambda: not _pid_alive(pid)), \
        "daemon did not exit on SIGTERM"
    assert _wait_for(lambda: not pidfile.exists()), \
        "pidfile was not removed on exit"


def test_daemon_pidfile_guard(tmp_path):
    """A pre-existing pidfile makes startup refuse (exit 1) before forking."""
    port = _free_port()
    pidfile = tmp_path / "daemon.pid"
    pidfile.write_text("99999\n")            # stale pidfile present
    config = _write_daemon_config(tmp_path, port, str(pidfile))

    with subprocess.Popen(
            [sys.executable, SERVER, "-c", str(config),
             "-s", "127.0.0.1", "-p", str(port), "-d"],
            cwd=ZONE_DIR, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL) as proc:
        # The existence check runs before the first fork, so this is the real
        # process exit code, not a detached launcher's.
        assert proc.wait(timeout=10) == 1
    # The pre-existing pidfile must be left untouched.
    assert pidfile.read_text().strip() == "99999"
