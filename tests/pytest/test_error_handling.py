"""
Worker-thread error handling: unhandled exceptions in a connection handler
are logged (with traceback) and answered with a best-effort SERVFAIL rather
than silently dropped, and TCP sockets are always closed.

Unlike the rest of the suite (which drives a live subprocess server over the
wire), these tests import adns_server directly and inject faults with fake
sockets and monkeypatching -- the response path has to be made to raise, which
can't be provoked from a normal client query.
"""

# The ctx fixture is defined and consumed in this module; a test taking it as
# an argument necessarily shadows the fixture name (standard pytest pattern).
# pylint: disable=redefined-outer-name

import os
import struct
import sys

import pytest

import dns.message
import dns.name
import dns.rcode
import dns.rdatatype

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                 "..", "..")))
import adns_server as adns   # noqa: E402


@pytest.fixture
def ctx():
    """A minimal ServerContext for the handlers under test (no zones needed;
    these tests fault the response path before zone lookup)."""
    return adns.ServerContext(prefs=adns.Preferences(),
                              zonedict=adns.ZoneDict())


# --------------------------------------------------------------------------
# Fake sockets
# --------------------------------------------------------------------------

class FakeUDPSocket:
    """Minimal datagram socket: records sendto() payloads."""

    def __init__(self, recv_data=b"", peer=("192.0.2.1", 12345)):
        self._recv_data = recv_data
        self._peer = peer
        self.sent = []

    def recvfrom(self, _bufsize):
        return self._recv_data, self._peer

    def sendto(self, data, addr):
        self.sent.append((data, addr))


class FakeTCPSocket:
    """Minimal stream socket: serves recv_data in order, records sends,
    tracks close()."""

    def __init__(self, recv_data=b""):
        self._recv_buf = bytearray(recv_data)
        self.sent = bytearray()
        self.closed = False

    def recv(self, num_octets):
        chunk = bytes(self._recv_buf[:num_octets])
        del self._recv_buf[:num_octets]
        return chunk

    def send(self, data):
        self.sent.extend(data)
        return len(data)

    def close(self):
        self.closed = True


def _query_wire(qname="www.deleg.test.", qtype="A"):
    """Return the wire form of a simple query message."""
    msg = dns.message.make_query(dns.name.from_text(qname),
                                 dns.rdatatype.from_text(qtype))
    return msg.to_wire()


def _tcp_frame(wire):
    """Prefix a message with its 2-octet TCP length."""
    return struct.pack("!H", len(wire)) + wire


def _boom(*_args, **_kwargs):
    raise RuntimeError("injected handler failure")


# --------------------------------------------------------------------------
# send_servfail()
# --------------------------------------------------------------------------

def test_send_servfail_udp():
    sock = FakeUDPSocket()
    query = adns.DNSquery(_query_wire(), cliaddr="192.0.2.1", cliport=12345)
    adns.send_servfail(query, sock)
    assert len(sock.sent) == 1
    data, addr = sock.sent[0]
    resp = dns.message.from_wire(data)
    assert resp.rcode() == dns.rcode.SERVFAIL
    assert addr == ("192.0.2.1", 12345)


def test_send_servfail_tcp():
    sock = FakeTCPSocket()
    wire = _query_wire()
    query = adns.DNSquery(_tcp_frame(wire), cliaddr="192.0.2.1",
                          cliport=12345, tcp=True)
    adns.send_servfail(query, sock)
    # Reply is length-prefixed.
    msg_len, = struct.unpack("!H", bytes(sock.sent[:2]))
    resp = dns.message.from_wire(bytes(sock.sent[2:2 + msg_len]))
    assert resp.rcode() == dns.rcode.SERVFAIL


def test_send_servfail_noop_when_query_none():
    sock = FakeUDPSocket()
    adns.send_servfail(None, sock)
    assert not sock.sent


def test_send_servfail_noop_when_unparsed():
    """A query whose message never parsed has nothing to respond to."""
    sock = FakeUDPSocket()
    query = adns.DNSquery(b"\x00\x01\x02garbage", cliaddr="192.0.2.1",
                          cliport=12345)
    assert query.message is None      # confirm the precondition
    adns.send_servfail(query, sock)
    assert not sock.sent


# --------------------------------------------------------------------------
# handle_connection_udp / _tcp exception paths
# --------------------------------------------------------------------------

def test_udp_handler_exception_sends_servfail(monkeypatch, capsys, ctx):
    monkeypatch.setattr(adns, "handle_query", _boom)
    sock = FakeUDPSocket(recv_data=_query_wire())
    # Must not raise out of the thread body.
    adns.handle_connection_udp(sock, ctx)
    assert len(sock.sent) == 1
    resp = dns.message.from_wire(sock.sent[0][0])
    assert resp.rcode() == dns.rcode.SERVFAIL
    # Logged with a traceback.
    err = capsys.readouterr().out
    assert "unhandled exception in UDP handler" in err
    assert "Traceback" in err


def test_tcp_handler_exception_sends_servfail_and_closes(monkeypatch, capsys,
                                                         ctx):
    monkeypatch.setattr(adns, "handle_query", _boom)
    sock = FakeTCPSocket(recv_data=_tcp_frame(_query_wire()))
    adns.handle_connection_tcp(sock, ("192.0.2.1", 12345), ctx)
    # SERVFAIL sent.
    msg_len, = struct.unpack("!H", bytes(sock.sent[:2]))
    resp = dns.message.from_wire(bytes(sock.sent[2:2 + msg_len]))
    assert resp.rcode() == dns.rcode.SERVFAIL
    # Socket closed via finally.
    assert sock.closed
    err = capsys.readouterr().out
    assert "unhandled exception in TCP handler" in err
    assert "Traceback" in err


def test_tcp_socket_closed_on_normal_path(monkeypatch, ctx):
    """The finally clause closes the socket on the success path too."""
    monkeypatch.setattr(adns, "handle_query", lambda *a, **k: None)
    sock = FakeTCPSocket(recv_data=_tcp_frame(_query_wire()))
    adns.handle_connection_tcp(sock, ("192.0.2.1", 12345), ctx)
    assert sock.closed


def test_tcp_socket_closed_on_empty_read(ctx):
    """A peer that closes before sending is handled and the fd is released."""
    sock = FakeTCPSocket(recv_data=b"")   # recv() returns b'' immediately
    adns.handle_connection_tcp(sock, ("192.0.2.1", 12345), ctx)
    assert sock.closed
    assert not sock.sent
