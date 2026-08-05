"""
TCP transport: length-prefixed framing and segment reassembly.

The server reads one length-prefixed DNS message per TCP connection (RFC 1035
4.2.2). These tests confirm the framed read works via dnspython (which writes
the whole frame in one call) and, crucially, that a message whose 2-octet
length prefix and body arrive in *separate* TCP segments is reassembled
correctly -- the case the earlier single-recv() implementation truncated.
"""

import socket
import struct
import time

import dns.message
import dns.name
import dns.rdatatype

import dnsutil as du


def test_tcp_positive_answer(query, dnskey):
    """A basic query over TCP returns the same answer as UDP."""
    r = query("www.deleg.test", "A", do=True, tcp=True)
    assert du.rcode(r) == "NOERROR"
    assert du.has_flag(r, "AA")
    a = du.rrsets_of_type(r.answer, "A")
    assert a and a[0][0].to_text() == "192.0.2.10"
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")


def _tcp_query_split(host, port, msg, split_delay=0.1):
    """
    Send a DNS message over TCP with the 2-octet length prefix and the message
    body written as two separate segments (with a small delay to make distinct
    TCP segments likely), then read and parse the length-prefixed response.
    """
    wire = msg.to_wire()
    prefix = struct.pack("!H", len(wire))
    sock = socket.create_connection((host, port), timeout=5.0)
    try:
        # Two separate sends: length prefix first, then the body after a pause.
        sock.sendall(prefix)
        time.sleep(split_delay)
        sock.sendall(wire)
        # Read the length-prefixed reply.
        rbuf = b""
        while len(rbuf) < 2:
            rbuf += sock.recv(2 - len(rbuf))
        resp_len, = struct.unpack("!H", rbuf)
        body = b""
        while len(body) < resp_len:
            chunk = sock.recv(resp_len - len(body))
            if not chunk:
                break
            body += chunk
        return dns.message.from_wire(body)
    finally:
        sock.close()


def test_tcp_split_prefix_and_body(server, dnskey):
    """
    A query whose length prefix and body arrive in separate segments is
    reassembled and answered correctly (regression for single-recv truncation).
    """
    host, port = server
    msg = dns.message.make_query(dns.name.from_text("www.deleg.test."),
                                 dns.rdatatype.A, want_dnssec=True)
    r = _tcp_query_split(host, port, msg)
    assert du.rcode(r) == "NOERROR"
    assert du.has_flag(r, "AA")
    a = du.rrsets_of_type(r.answer, "A")
    assert a and a[0][0].to_text() == "192.0.2.10"
    du.validate_all(r, dnskey("deleg.test"), "deleg.test")
