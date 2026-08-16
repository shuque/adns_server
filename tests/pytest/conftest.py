"""
Pytest fixtures for the adns_server automated test suite.

The suite launches a private instance of the adns server (`python3 -m adns`)
on an ephemeral loopback port, serving the purpose-built zones under
test_zones/, and drives
it with real DNS queries via dnspython. Responses are asserted on
structurally (rcode, flags, sections, EDE) and, for signed zones,
cryptographically validated -- see dnsutil.py.

Set ADNS_TEST_KEEP_LOG=1 to print the server log on teardown (useful when a
launch fails).
"""

import contextlib
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
ZONE_DIR = os.path.join(HERE, "test_zones")
CONFIG = os.path.join(ZONE_DIR, "test.yaml")
MINIMAL_ANY_CONFIG = os.path.join(ZONE_DIR, "test-minimal-any.yaml")

DE_FLAG = 0x2000       # EDNS(0) DE (Delegation Extensions) flag
CO_FLAG = 0x4000       # EDNS(0) CO (Compact Answers OK) flag

# The server is launched as `python3 -m adns`, a package import that a
# subprocess cannot resolve on its own -- the parent test process's
# sys.path.insert(0, REPO_ROOT) does not propagate to a child. Put the repo
# root on the child's PYTHONPATH explicitly.
SUBPROCESS_ENV = {**os.environ,
                  "PYTHONPATH": REPO_ROOT + os.pathsep +
                  os.environ.get("PYTHONPATH", "")}


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


@contextlib.contextmanager
def _launch_server(config, logname):
    """
    Launch adns_server on an ephemeral loopback port with the given config,
    yielding a (host, port) tuple. The working directory is test_zones/ so the
    relative paths in the config resolve.
    """
    host = "127.0.0.1"
    port = _free_port()
    logfile = open(os.path.join(HERE, logname), "w+", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-m", "adns", "-c", config, "-s", host, "-p",
         str(port), "-f", "-d"],
        cwd=ZONE_DIR, env=SUBPROCESS_ENV, stdout=logfile,
        stderr=subprocess.STDOUT)

    if not _wait_until_ready(host, port, proc):
        proc.terminate()
        logfile.seek(0)
        log = logfile.read()
        logfile.close()
        pytest.fail(f"adns_server failed to start on {host}:{port}\n{log}")

    try:
        yield (host, port)
    finally:
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
def server():
    """
    Launch adns_server on an ephemeral loopback port for the whole session,
    using test.yaml (conventional ANY: minimal_any=false).

    Yields an (host, port) tuple.
    """
    with _launch_server(CONFIG, ".server.log") as endpoint:
        yield endpoint


@pytest.fixture(scope="session")
def minimal_any_server():
    """
    A second server instance using test-minimal-any.yaml (minimal_any=true), to
    exercise the RFC 8482 minimal-ANY code path. Deployments typically enable
    this; the prototyping default (test.yaml) leaves it off.
    """
    with _launch_server(MINIMAL_ANY_CONFIG, ".server-minany.log") as endpoint:
        yield endpoint


@pytest.fixture(scope="session")
def mldsa_servers(tmp_path_factory):
    """
    Serve an offline pre-signed algorithm-18 (ML-DSA-44) zone under two EDNS
    ceilings.

    Generates an alg-18 CSK, offline-signs the committed mldsa.test fixture,
    and launches two static (dnssec: true, no dynamic_signing) server instances
    that differ only in their EDNS send-ceiling: "large" (edns: 4096, returns
    the big DNSKEY+RRSIG over UDP) and "capped" (edns: 1432, truncates). Online
    alg-18 signing does not exist yet (phase 3), so the zone must be pre-signed.

    Yields {"large": (host, port), "capped": (host, port), "pub": <raw 1312
    octets of the ML-DSA public key>}.
    """
    import shutil
    import dns.rdata

    tmp = tmp_path_factory.mktemp("mldsa")
    keydir = tmp / "keys"
    keydir.mkdir()

    # 1. Generate the alg-18 CSK.
    subprocess.run(
        [sys.executable, "-m", "adns.keygen", "mldsa.test", "-a", "18",
         "-f", "257", "-K", str(keydir)],
        capture_output=True, text=True, check=True, env=SUBPROCESS_ENV)
    dnskey_file = list(keydir.glob("mldsa.test+018+*.dnskey"))[0]

    # 2. Copy the committed unsigned zone in and inject the apex DNSKEY line.
    zonefile = tmp / "zonefile"
    shutil.copy(os.path.join(ZONE_DIR, "mldsa.test", "zonefile"), zonefile)
    with open(zonefile, "a", encoding="utf-8") as fobj:
        fobj.write(dnskey_file.read_text())

    # 3. Offline-sign with a fixed far-future expiration.
    signed = tmp / "zonefile.signed"
    subprocess.run(
        [sys.executable, "-m", "adns.signer", "mldsa.test", str(zonefile),
         "-K", str(keydir), "-o", str(signed), "-e", "+3650d"],
        capture_output=True, text=True, check=True, env=SUBPROCESS_ENV)

    # 4. Extract the raw public key from the generated DNSKEY (last field is the
    #    base64 key; dnspython's rdata.key gives the decoded bytes).
    dnskey_line = dnskey_file.read_text().split("DNSKEY", 1)[1].strip()
    dnskey_rdata = dns.rdata.from_text(dns.rdataclass.IN,
                                       dns.rdatatype.DNSKEY, dnskey_line)
    pub = dnskey_rdata.key

    # 5. Write two static configs, absolute file path, differing only in edns.
    def _write_config(name, edns):
        path = tmp / name
        path.write_text(
            "config:\n"
            f"  edns: {edns}\n"
            "zones:\n"
            '  - name: "mldsa.test"\n'
            f'    file: "{signed}"\n'
            "    dnssec: true\n")
        return str(path)

    large_cfg = _write_config("large.yaml", 4096)
    capped_cfg = _write_config("capped.yaml", 1432)

    # 6. Launch both servers for the session.
    with contextlib.ExitStack() as stack:
        large = stack.enter_context(
            _launch_server(large_cfg, ".server-mldsa-large.log"))
        capped = stack.enter_context(
            _launch_server(capped_cfg, ".server-mldsa-capped.log"))
        yield {"large": large, "capped": capped, "pub": pub}


@pytest.fixture(scope="session")
def mldsa_online_server(tmp_path_factory):
    """
    Serve an algorithm-18 (ML-DSA-44) zone with ONLINE (dynamic) signing.

    Generates an alg-18 CSK and launches one dynamic_signing server over the
    committed mldsa-online.test fixture, so the server signs every answered
    RRset live with the shared alg-18 RRSIG builder (phase 3). No offline sign
    step -- contrast the mldsa_servers fixture, which pre-signs.

    Yields {"endpoint": (host, port), "pub": <raw 1312 octets of the ML-DSA
    public key>}.
    """
    import shutil
    import dns.rdata

    tmp = tmp_path_factory.mktemp("mldsa_online")
    keydir = tmp / "keys"
    keydir.mkdir()

    # 1. Generate the alg-18 CSK.
    subprocess.run(
        [sys.executable, "-m", "adns.keygen", "mldsa-online.test", "-a", "18",
         "-f", "257", "-K", str(keydir)],
        capture_output=True, text=True, check=True, env=SUBPROCESS_ENV)
    dnskey_file = list(keydir.glob("mldsa-online.test+018+*.dnskey"))[0]
    pem_file = list(keydir.glob("mldsa-online.test+018+*.pem"))[0]

    # 2. Copy the committed unsigned zone in and inject the apex DNSKEY line.
    zonefile = tmp / "zonefile"
    shutil.copy(os.path.join(ZONE_DIR, "mldsa-online.test", "zonefile"),
                zonefile)
    with open(zonefile, "a", encoding="utf-8") as fobj:
        fobj.write(dnskey_file.read_text())

    # 3. Extract the raw public key (base64 field of the DNSKEY presentation).
    dnskey_line = dnskey_file.read_text().split("DNSKEY", 1)[1].strip()
    dnskey_rdata = dns.rdata.from_text(dns.rdataclass.IN,
                                       dns.rdatatype.DNSKEY, dnskey_line)
    pub = dnskey_rdata.key

    # 4. Write a dynamic_signing config (absolute file + key paths).
    config = tmp / "online.yaml"
    config.write_text(
        "config:\n"
        "  edns: 4096\n"
        "zones:\n"
        '  - name: "mldsa-online.test"\n'
        f'    file: "{zonefile}"\n'
        "    dnssec: true\n"
        "    dynamic_signing: true\n"
        f'    private_key: "{pem_file}"\n')

    # 5. Launch the server for the session.
    with _launch_server(str(config), ".server-mldsa-online.log") as endpoint:
        yield {"endpoint": endpoint, "pub": pub}


def _make_query_fn(endpoint):
    """Build a query function bound to a given (host, port) endpoint."""
    host, port = endpoint

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
    return _make_query_fn(server)


@pytest.fixture(scope="session")
def minimal_any_query(minimal_any_server):
    """Like `query`, but bound to the minimal_any=true server instance."""
    return _make_query_fn(minimal_any_server)


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
