"""
Tests for deleg_rdata.py -- the DELEG/DELEGPARAM RFC 3597 generic-format
RDATA generator (draft-ietf-deleg Section 3).

Verifies wire encoding against hand-computed bytes, round-trips generated
records through dnspython's generic-rdata parser, exercises the DelegInfo
key registry and value codecs, and checks the Section 3.4/3.5 validators.
"""

import os
import socket
import struct
import sys

import pytest

import dns.name
import dns.rdata
import dns.rdataclass

# Import the tool from the repository root.
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")))
import deleg_rdata as dr   # noqa: E402


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def rdata_of(*pairs, origin=None, strict=False):
    """Build DelegInfos wire bytes for a set of key=value tokens."""
    org = dns.name.from_text(origin) if origin else dns.name.root
    parsed = dr.parse_pairs(list(pairs))
    dr.check_semantics(parsed, strict)
    return dr.build_deleginfos(parsed, org)


def deleginfos(wire):
    """Decode DelegInfos wire bytes into an ordered list of (key, value)."""
    out = []
    i = 0
    while i < len(wire):
        key, vlen = struct.unpack_from("!HH", wire, i)
        i += 4
        out.append((key, wire[i:i + vlen]))
        i += vlen
    return out


# --------------------------------------------------------------------------
# Wire encoding
# --------------------------------------------------------------------------

def test_ipv4_ipv6_encoding_matches_handcomputed():
    wire = rdata_of("server-ipv4=192.0.2.1", "server-ipv6=2001:db8::1")
    expected = (struct.pack("!HH", 1, 4)
                + socket.inet_pton(socket.AF_INET, "192.0.2.1")
                + struct.pack("!HH", 2, 16)
                + socket.inet_pton(socket.AF_INET6, "2001:db8::1"))
    assert wire == expected


def test_multiple_ipv4_concatenated():
    wire = rdata_of("server-ipv4=192.0.2.1,192.0.2.2")
    key, val = deleginfos(wire)[0]
    assert key == 1
    assert val == (socket.inet_pton(socket.AF_INET, "192.0.2.1")
                   + socket.inet_pton(socket.AF_INET, "192.0.2.2"))


def test_server_name_uncompressed_wire_names():
    wire = rdata_of("server-name=ns1.example.,ns2.example.")
    key, val = deleginfos(wire)[0]
    assert key == 3
    # two uncompressed names, each ending in the root label (0x00)
    expected = (dns.name.from_text("ns1.example.").to_wire()
                + dns.name.from_text("ns2.example.").to_wire())
    assert val == expected


def test_relative_names_resolved_against_origin():
    wire = rdata_of("server-name=ns1,ns2", origin="example.")
    _, val = deleginfos(wire)[0]
    expected = (dns.name.from_text("ns1.example.").to_wire()
                + dns.name.from_text("ns2.example.").to_wire())
    assert val == expected


def test_keys_sorted_strictly_increasing():
    # Provide keys out of order; output must be sorted by key number.
    wire = rdata_of("server-ipv6=2001:db8::1", "server-ipv4=192.0.2.1")
    keys = [k for k, _ in deleginfos(wire)]
    assert keys == sorted(keys)
    assert keys == [1, 2]


def test_mandatory_key_numbers_sorted():
    wire = rdata_of("server-ipv4=192.0.2.1", "server-ipv6=2001:db8::1",
                    "mandatory=server-ipv6,server-ipv4")
    # mandatory is key 0, so first in the sorted DelegInfos
    key, val = deleginfos(wire)[0]
    assert key == 0
    assert val == struct.pack("!HH", 1, 2)   # keys 1 and 2, increasing


def test_unknown_key_generic():
    wire = rdata_of("key99=hello")
    key, val = deleginfos(wire)[0]
    assert key == 99
    assert val == b"hello"


# --------------------------------------------------------------------------
# Round-trip through dnspython's RFC 3597 parser
# --------------------------------------------------------------------------

@pytest.mark.parametrize("pairs", [
    ("server-ipv4=192.0.2.1",),
    ("server-ipv4=192.0.2.1", "server-ipv6=2001:db8::1"),
    ("server-name=ns1.example.net.,ns2.example.org.",),
    ("include-delegparam=cfg.example.org.",),
])
def test_roundtrip_through_dnspython(pairs):
    wire = rdata_of(*pairs)
    line = dr.format_rr("x.example.", 61440, wire)
    generic = line.split("IN ", 1)[1].split(None, 1)[1]   # "\# len hex"
    rd = dns.rdata.from_text(dns.rdataclass.IN, 61440, generic)
    assert rd.to_wire() == wire


# --------------------------------------------------------------------------
# RR line formatting
# --------------------------------------------------------------------------

def test_format_rr_with_and_without_ttl():
    wire = rdata_of("server-ipv4=192.0.2.1")
    no_ttl = dr.format_rr("x.example.", 61440, wire)
    assert no_ttl.startswith("x.example. IN TYPE61440 \\# ")
    with_ttl = dr.format_rr("x.example.", 61440, wire, ttl=3600)
    assert with_ttl.startswith("x.example. 3600 IN TYPE61440 \\# ")


def test_delegparam_type_number():
    assert dr.rrtype_number("DELEGPARAM") == 65433
    assert dr.rrtype_number("DELEG") == 61440
    assert dr.rrtype_number("61440") == 61440


# --------------------------------------------------------------------------
# Validation (Section 3.4 / 3.5)
# --------------------------------------------------------------------------

def test_duplicate_key_is_error():
    with pytest.raises(dr.DelegError, match="duplicate"):
        rdata_of("server-ipv4=192.0.2.1", "server-ipv4=192.0.2.2")


def test_empty_value_is_error():
    with pytest.raises(dr.DelegError, match="non-empty"):
        rdata_of("server-ipv4=")


def test_bad_ipv4_is_error():
    with pytest.raises(dr.DelegError, match="invalid IPv4"):
        rdata_of("server-ipv4=999.0.0.1")


def test_multiple_server_shapes_strict_error():
    with pytest.raises(dr.DelegError, match="disallowed combination"):
        rdata_of("server-ipv4=192.0.2.1", "server-name=ns.example.",
                 strict=True)


def test_multiple_server_shapes_warns_but_builds():
    # Without strict, it warns (to stderr) but still produces RDATA.
    wire = rdata_of("server-ipv4=192.0.2.1", "server-name=ns.example.")
    keys = [k for k, _ in deleginfos(wire)]
    assert keys == [1, 3]


def test_ipv4_plus_ipv6_shape_allowed():
    # This combination is explicitly allowed; strict must not raise.
    rdata_of("server-ipv4=192.0.2.1", "server-ipv6=2001:db8::1",
             strict=True)


def test_mandatory_missing_key_strict_error():
    with pytest.raises(dr.DelegError, match="mandatory"):
        rdata_of("server-ipv4=192.0.2.1", "mandatory=server-ipv6",
                 strict=True)
