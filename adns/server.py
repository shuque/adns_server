"""
Network / runtime / daemon layer.

Owns the socket setup and select()-based event loop, worker-thread dispatch,
daemonization (double-fork, pidfile, descriptor cleanup), privilege dropping,
and signal handling (SIGTERM/SIGHUP). See Design.md section 10 (specifically
the §10.2 module-layout table and its `adns/server.py` status paragraph).
"""

import os
import sys
import pwd
import grp
import resource
import syslog
import struct
import socket
import atexit
import select
import threading
import signal
import time
import random
import binascii
import traceback

import dns.message
import dns.rcode

from adns import __version__
from adns.log import log_message, log_fatal, RateLimitedLog
from adns.crypto import sign_rrset
from adns.response import DNSquery, DNSresponse
from adns.config import PROGNAME, init_config


def handle_sigterm(signum, frame):
    """handle SIGTERM - exit program"""
    _, _ = signum, frame
    log_message('control: caught SIGTERM .. exiting.')
    sys.exit(0)


def install_signal_handlers(ctx):
    """Install handlers for HUP and TERM signals.

    signal.signal() invokes handlers with a fixed (signum, frame) signature, so
    there is no parameter slot to pass ctx in. handle_sighup therefore closes
    over ctx from this enclosing scope to reach ctx.prefs/ctx.zonedict for the
    config/zone re-read. SIGTERM needs no such state, so it stays a plain
    module-level function."""

    def handle_sighup(signum, frame):
        _, _ = signum, frame
        log_message('control: caught SIGHUP .. re-reading config and zones.')
        sign_rrset.cache.clear()
        init_config(ctx.prefs, ctx.zonedict)

    signal.signal(signal.SIGTERM, handle_sigterm)
    signal.signal(signal.SIGHUP, handle_sighup)


def get_pid_file(prefs):
    """Get name of PID file to create"""

    if prefs.pidfile:
        return prefs.pidfile
    if prefs.workdir:
        return os.path.join(prefs.workdir, 'daemon.pid')
    return f'/tmp/{PROGNAME}.pid'


def remove_pidfile(pidfile):
    """atexit cleanup: remove the pidfile, tolerating its absence."""
    try:
        os.remove(pidfile)
    except FileNotFoundError:
        pass
    except OSError as exc_info:
        log_message(f"warning: could not remove pidfile {pidfile}: {exc_info}")


def close_inherited_fds():
    """Close inherited descriptors (fd 3+) so the daemon starts clean.

    Prefer os.close_range() (a single syscall) when the interpreter exposes it;
    fall back to os.closerange() (C-level loop) otherwise. Note os.close_range
    is only present when CPython's build-time configure detected the syscall, so
    many interpreters take the fallback even on kernels that have close_range.
    fds 0/1/2 are reopened to /dev/null by the caller, so they are deliberately
    not closed here (leaving them closed lets a later open() reuse 0/1/2 and
    silently wire a data file to something a later write treats as stderr)."""
    limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    if limit == resource.RLIM_INFINITY:
        limit = os.sysconf("SC_OPEN_MAX")
    if hasattr(os, "close_range"):
        os.close_range(3, limit - 1)      # inclusive upper bound
    else:
        os.closerange(3, limit)           # exclusive upper bound


def daemon(prefs, dirname=None, syslog_fac=syslog.LOG_DAEMON):
    """Turn into daemon"""

    pidfile = get_pid_file(prefs)
    if os.path.exists(pidfile):
        print(f"File {pidfile} already exists.")
        sys.exit(1)

    umask_value = 0o022

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as einfo:
        print(f"fork() #1 failed: {einfo:s}")
        sys.exit(1)

    if dirname:
        os.chdir(dirname)

    os.umask(umask_value)
    os.setsid()

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as einfo:
        print(f"fork() #2 failed: {einfo:s}")
        sys.exit(1)

    with open(pidfile, 'w', encoding="utf-8") as pid_f:
        pid_f.write(f'{os.getpid()}\n')
    atexit.register(remove_pidfile, pidfile)

    close_inherited_fds()
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
    if devnull > 2:
        os.close(devnull)

    syslog.openlog(PROGNAME, syslog.LOG_PID, syslog_fac)


def drop_privs(uname, gname):
    """If run as root, drop privileges to specified uid and gid"""

    if os.geteuid() != 0:
        log_message("warning: Program didn't start as root. Can't change id.")
    else:
        os.setgroups([])
        if gname:
            gid = grp.getgrnam(gname).gr_gid
            os.setgid(gid)
            os.setegid(gid)
        if uname:
            uid = pwd.getpwnam(uname).pw_uid
            os.setuid(uid)
            os.seteuid(uid)


def udp4socket(host, port):
    """Create IPv4 UDP server socket"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    return sock


def udp6socket(host, port):
    """Create IPv6 UDP server socket"""
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((host, port))
    return sock


def tcp4socket(host, port):
    """Create IPv4 TCP server socket"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    return sock


def tcp6socket(host, port):
    """Create IPv6 TCP server socket"""
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    return sock


def send_socket(sock, message):
    """Send message on a connected socket"""
    try:
        octets_sent = 0
        while octets_sent < len(message):
            sentn = sock.send(message[octets_sent:])
            if sentn == 0:
                log_message("error: send() returned 0 bytes")
                raise ValueError("send() returned 0 bytes")
            octets_sent += sentn
    except OSError as diag:
        log_message(f"error: sendSocket() exception: {diag}")
        return False
    return True


def recv_socket(sock, num_octets, deadline=None):
    """Read and return exactly num_octets of data from a connected socket.

    TCP is a byte stream, so a single recv() may return fewer octets than
    requested (and may split the 2-octet length prefix from the message
    body across segments). Loop until num_octets have been read. Returns
    None if the peer closes the connection before that many octets arrive.

    If deadline (a time.monotonic() value) is given, the whole read must
    complete by then: the socket timeout is reset before each recv() to the
    remaining budget, so a slow client that dribbles data can't reset the
    clock and hold the connection open indefinitely. socket.timeout is raised
    (as OSError) once the deadline passes."""
    data = bytearray()
    while len(data) < num_octets:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("read deadline exceeded")
            sock.settimeout(remaining)
        chunk = sock.recv(num_octets - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


def handle_query(query, sock, ctx):
    """Handle incoming query"""

    if not query.message:
        return

    response = DNSresponse(query, ctx)
    if not response.response:
        return

    if query.tcp:
        send_socket(sock, response.to_wire())
    else:
        sock.sendto(response.to_wire(),
                    (query.cliaddr, query.cliport))


def send_servfail(query, sock):
    """Best-effort SERVFAIL reply after an unhandled handler exception.

    Built directly from the query (not via DNSresponse, which is what failed)
    and guarded so it can never itself raise out of the exception handler.
    A no-op if the query never parsed (no question to respond to)."""
    if query is None or not query.message:
        return
    try:
        resp = dns.message.make_response(query.message)
        resp.set_rcode(dns.rcode.SERVFAIL)
        wire = resp.to_wire()
        if query.tcp:
            send_socket(sock, struct.pack('!H', len(wire)) + wire)
        else:
            sock.sendto(wire, (query.cliaddr, query.cliport))
    except Exception as exc_info:      # pylint: disable=broad-exception-caught
        log_message(f"error: failed to send SERVFAIL: {exc_info}")


def handle_connection_udp(sock, ctx, rbufsize=2048):
    """Handle UDP connection"""

    query = None
    try:
        data, addrport = sock.recvfrom(rbufsize)
        cliaddr, cliport = addrport[0:2]
        if ctx.prefs.debug:
            log_message(f"connect: UDP from ({cliaddr}, {cliport}) "
                        f"msgsize={len(data)}")
        query = DNSquery(data, cliaddr=cliaddr, cliport=cliport)
        handle_query(query, sock, ctx)
    except Exception as exc_info:      # pylint: disable=broad-exception-caught
        log_message(f"error: unhandled exception in UDP handler: "
                    f"{exc_info}\n{traceback.format_exc()}")
        send_servfail(query, sock)


def handle_connection_tcp(sock, addr, ctx):
    """Handle TCP connection

    Read one length-prefixed DNS message (RFC 1035 4.2.2): a 2-octet length
    field followed by that many octets of message. Persistent connections
    (multiple queries per connection, RFC 7766) are not yet supported -- we
    read one message and close."""

    query = None
    try:  # pylint: disable=too-many-try-statements
        cliaddr, cliport = addr[0:2]
        # Whole-transaction deadline: reading the length prefix plus the message
        # body must complete within tcp_timeout, so a stalled or dribbling
        # client can't tie up this worker thread indefinitely (RFC 7766 §8).
        deadline = time.monotonic() + ctx.prefs.tcp_timeout
        prefix = recv_socket(sock, 2, deadline)
        if prefix is None:
            return
        msg_len, = struct.unpack('!H', prefix)
        body = recv_socket(sock, msg_len, deadline)
        if body is None:
            log_message(f"error: TCP from ({cliaddr}, {cliport}): connection "
                        f"closed mid-message (expected {msg_len} octets)")
            return
        if ctx.prefs.debug:
            log_message(f"connect: TCP from ({cliaddr}, {cliport}) "
                        f"msgsize={msg_len}")
        query = DNSquery(prefix + body, cliaddr=cliaddr, cliport=cliport,
                         tcp=True)
        handle_query(query, sock, ctx)
    except socket.timeout:
        # Slow/stuck client hit the read deadline. Just drop the connection;
        # sending SERVFAIL to a peer that isn't reading is pointless.
        log_message(f"error: TCP from ({cliaddr}, {cliport}): read timed out "
                    f"after {ctx.prefs.tcp_timeout}s")
    except Exception as exc_info:      # pylint: disable=broad-exception-caught
        log_message(f"error: unhandled exception in TCP handler: "
                    f"{exc_info}\n{traceback.format_exc()}")
        send_servfail(query, sock)
    finally:
        sock.close()


def setup_sockets(family, server, port):
    """Setup sockets for connection types and address families we handle.

    Returns a dispatch dict keyed by each socket's fileno -> (sock, handler,
    is_tcp). Keying on the fileno lets the event loop look a ready descriptor
    up directly (select() returns filenos), and lets select() consume the
    dict's keys as its read list."""

    dispatch = {}   # dict: fileno -> (sock, handler, is_tcp)

    def register(sock, handler, is_tcp):
        dispatch[sock.fileno()] = (sock, handler, is_tcp)

    if family is None or family == 'IPv4':
        register(udp4socket(server, port), handle_connection_udp, False)
        register(tcp4socket(server, port), handle_connection_tcp, True)

    if family is None or family == 'IPv6':
        register(udp6socket(server, port), handle_connection_udp, False)
        register(tcp6socket(server, port), handle_connection_tcp, True)

    return dispatch


def setup_server(ctx):
    """Setup server: derive runtime state and open listening sockets.

    Populates ctx.cookie_secret and ctx.dispatch (the fileno -> handler map)."""

    prefs = ctx.prefs
    ctx.cookie_secret = binascii.hexlify(random.randbytes(8))

    if prefs.daemon:
        daemon(prefs, dirname=prefs.workdir, syslog_fac=prefs.syslog_fac)
    install_signal_handlers(ctx)
    log_message(f"info: {PROGNAME} version {__version__}: running")

    try:
        ctx.dispatch = setup_sockets(prefs.server_af, prefs.server, prefs.port)
    except PermissionError as exc_info:
        log_fatal(f"Error setting up sockets: {exc_info}")

    if prefs.username or prefs.groupname:
        drop_privs(prefs.username, prefs.groupname)

    log_message(f"info: Listening on UDP and TCP port {prefs.port}")


def spawn_worker(semaphore, handler, args):
    """Start a daemon worker thread that releases the concurrency slot on exit.

    daemon=True so a worker still running at shutdown (e.g. a TCP thread blocked
    in recv() on a client that hasn't finished its message) doesn't hold up
    interpreter exit. Non-daemon threads are joined by threading._shutdown()
    before the process exits, which otherwise makes SIGTERM hang until a second
    signal and prevents the atexit pidfile cleanup from ever running.

    The caller has already acquired one semaphore slot; the wrapper releases it
    in a finally so the slot is returned however the handler exits."""
    def run():
        try:
            handler(*args)
        finally:
            semaphore.release()
    threading.Thread(target=run, daemon=True).start()


def run_event_loop(ctx):
    """Run main event loop ...

    A BoundedSemaphore caps the number of concurrent worker threads
    (prefs.max_workers). When the cap is hit we shed the pending event rather
    than block the accept loop: for UDP we read and drop the datagram, for TCP
    we accept and immediately close. Both consume the readable event so select()
    doesn't just re-report the same fd and spin. This bounds resource use under
    a flood regardless of source -- it is NOT a defense against spoofed-source /
    DDoS / amplification attacks (out of scope for a prototype server)."""

    dispatch = ctx.dispatch
    workers = threading.BoundedSemaphore(ctx.prefs.max_workers)
    shed = RateLimitedLog("worker cap reached; shedding requests")
    while True:
        try:
            (ready_r, _, _) = select.select(dispatch, [], [], 5)
        except OSError as exc_info:
            log_fatal(f"error: from select(): {exc_info}")
        if not ready_r:
            continue

        for file_desc in ready_r:
            sock, handler, is_tcp = dispatch[file_desc]
            # Not a `with`: the slot is released from the worker thread (or the
            # shed path just below), so acquire/release don't nest in a block.
            got_slot = workers.acquire(  # pylint: disable=consider-using-with
                blocking=False)
            if is_tcp:
                conn, addr = sock.accept()
                if got_slot:
                    spawn_worker(workers, handler, (conn, addr, ctx))
                    continue
                conn.close()                # shed: drain the accept queue
            elif got_slot:
                spawn_worker(workers, handler, (sock, ctx))
                continue
            else:
                # shed: drain the datagram so select() doesn't re-fire
                try:
                    sock.recvfrom(2048)
                except OSError:
                    pass
            shed.log()
