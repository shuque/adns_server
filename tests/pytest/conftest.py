"""
Pytest fixtures for the adns_server automated test suite.

The suite launches a private instance of adns_server.py on an ephemeral
loopback port, serving the purpose-built zones under test_zones/, and drives
it with real DNS queries via dnspython. Responses are asserted on
structurally (rcode, flags, sections, EDE) and, for signed zones,
cryptographically validated -- see dnsutil.py.

Set ADNS_TEST_KEEP_LOG=1 to print the server log on teardown (useful when a
launch fails).
"""

import os
import socket
import subprocess
import sys
import time

import pytest

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
SERVER = os.path.join(REPO_ROOT, "adns_server.py")
ZONE_DIR = os.path.join(HERE, "test_zones")
CONFIG = os.path.join(ZONE_DIR, "test.yaml")

DE_FLAG = 0x2000       # EDNS(0) DE (Delegation Extensions) flag
CO_FLAG = 0x4000       # EDNS(0) CO (Compact Answers OK) flag


def _free_port():
    """Return an unused UDP port on the loopback interface."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def _wait_until_ready(host, port, proc, timeout=10.0):
    """Poll the server with a probe query until it answers or times out."""
    probe = dns.message.make_query(dns.name.from_text("deleg.test."),
                                   dns.rdatatype.SOA)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            resp = dns.query.udp(probe, host, port=port, timeout=1.0)
            if resp.rcode() is not None:
                return True
        except (dns.exception.Timeout, OSError):
            time.sleep(0.1)
    return False


@pytest.fixture(scope="session")
def server():
    """
    Launch adns_server on an ephemeral loopback port for the whole session.

    Yields an (host, port) tuple. The server's working directory is the
    test_zones/ directory so the relative paths in test.yaml resolve.
    """
    host = "127.0.0.1"
    port = _free_port()
    logfile = open(os.path.join(HERE, ".server.log"), "w+", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, SERVER, "-c", CONFIG, "-s", host, "-p", str(port),
         "-f", "-d"],
        cwd=ZONE_DIR, stdout=logfile, stderr=subprocess.STDOUT)

    if not _wait_until_ready(host, port, proc):
        proc.terminate()
        logfile.seek(0)
        log = logfile.read()
        logfile.close()
        pytest.fail(f"adns_server failed to start on {host}:{port}\n{log}")

    yield (host, port)

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    logfile.seek(0)
    if os.environ.get("ADNS_TEST_KEEP_LOG"):
        print("\n--- server log ---\n" + logfile.read())
    logfile.close()


@pytest.fixture(scope="session")
def query(server):
    """
    Return a function that sends a query to the test server and returns the
    parsed response message.

        resp = query("www.deleg.test", "A", do=True, de=True)

    Keyword flags:
      do      -- set the DNSSEC OK bit (request signatures)
      de      -- set the Delegation Extensions (DE) EDNS flag
      co      -- set the Compact Answers OK EDNS flag
      cookie  -- bytes for an EDNS COOKIE option
      udpsize -- advertised EDNS UDP payload size
      tcp     -- use TCP instead of UDP
      case_randomize -- apply 0x20 mixed-case randomization to the qname
    """
    host, port = server

    def _query(qname, qtype="A", *, do=False, de=False, co=False,
               cookie=None, udpsize=1232, tcp=False, case_randomize=False,
               want_edns=True, timeout=5.0):
        if isinstance(qname, str):
            name = dns.name.from_text(qname)
        else:
            name = qname
        if case_randomize:
            name = _randomize_case(name)
        if isinstance(qtype, str):
            rdtype = dns.rdatatype.from_text(qtype)
        else:
            rdtype = qtype

        options = []
        if cookie is not None:
            options.append(dns.edns.GenericOption(dns.edns.COOKIE, cookie))

        # Build the query, then set EDNS flags explicitly. Passing ednsflags
        # directly to make_query() together with use_edns can drop the DO bit,
        # so we apply flags to the constructed message instead.
        use_edns = 0 if (want_edns or do or de or co or options) else False
        msg = dns.message.make_query(name, rdtype, use_edns=use_edns,
                                     payload=udpsize, options=options)
        if use_edns is not False:
            ednsflags = 0
            if do:
                ednsflags |= dns.flags.DO
            if de:
                ednsflags |= DE_FLAG
            if co:
                ednsflags |= CO_FLAG
            msg.ednsflags = ednsflags
        if tcp:
            return dns.query.tcp(msg, host, port=port, timeout=timeout)
        return dns.query.udp(msg, host, port=port, timeout=timeout)

    return _query


@pytest.fixture(scope="session")
def dnskey(server):
    """
    Return a function mapping a zone name to its DNSKEY RRset (cached), for
    use as the trust anchor in signature validation.
    """
    host, port = server
    cache = {}

    def _dnskey(zone):
        if isinstance(zone, str):
            zname = dns.name.from_text(zone)
        else:
            zname = zone
        if zname in cache:
            return cache[zname]
        msg = dns.message.make_query(zname, dns.rdatatype.DNSKEY,
                                     want_dnssec=True)
        resp = dns.query.udp(msg, host, port=port, timeout=5.0)
        rrset = resp.get_rrset(resp.answer, zname, dns.rdataclass.IN,
                               dns.rdatatype.DNSKEY)
        cache[zname] = rrset
        return rrset

    return _dnskey


def _randomize_case(name):
    """
    Return a copy of name with alphabetic octets given a fixed, deterministic
    mixed case (upper-case every other letter). Deterministic so failures are
    reproducible, while still differing from the canonical lower case.
    """
    new_labels = []
    toggle = True
    for label in name.labels:
        out = bytearray()
        for byte in label:
            char = chr(byte)
            if char.isalpha():
                out.append(ord(char.upper()) if toggle else ord(char.lower()))
                toggle = not toggle
            else:
                out.append(byte)
        new_labels.append(bytes(out))
    return dns.name.Name(new_labels)
