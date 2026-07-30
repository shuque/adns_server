"""
EDNS handling: DE-flag echo, unknown version, meta query types, header-only.
"""

import dns.flags
import dns.rcode

import dnsutil as du
from conftest import DE_FLAG


def test_de_flag_echoed(query):
    """A DELEG-enabled server echoes the DE flag when set (delext 5.1)."""
    r = query("deleg.test", "SOA", do=True, de=True)
    assert du.has_edns_flag(r, DE_FLAG)


def test_de_flag_not_echoed_when_unset(query):
    r = query("deleg.test", "SOA", do=True, de=False)
    assert not du.has_edns_flag(r, DE_FLAG)


def test_do_flag_echoed(query):
    r = query("deleg.test", "SOA", do=True)
    assert bool(r.ednsflags & dns.flags.DO)


def test_edns_version_zero(query):
    """Normal EDNS(0) queries are answered at version 0."""
    r = query("deleg.test", "SOA", do=False)
    assert r.edns == 0


def test_meta_qtype_refused(query):
    """A meta/query-only RR type (e.g. NXNAME=128) is a FORMERR."""
    r = query("deleg.test", "TYPE128", do=True)
    assert du.rcode(r) == "FORMERR"


def test_any_query_conventional(query):
    """
    Conventional ANY (minimal_any=false, the prototyping default) returns ALL
    RRsets at the owner. www.deleg.test has both A and AAAA, so both appear.
    """
    r = query("www.deleg.test", "ANY", do=True)
    assert du.rcode(r) == "NOERROR"
    assert du.has_flag(r, "AA")
    types = du.section_types(r.answer)
    assert "A" in types
    assert "AAAA" in types


def test_any_query_minimal(minimal_any_query):
    """
    Minimal ANY (RFC 8482, minimal_any=true) returns a single RRset at the
    owner even though www.deleg.test has both A and AAAA -- the amplification
    mitigation real deployments enable.
    """
    r = minimal_any_query("www.deleg.test", "ANY", do=True)
    assert du.rcode(r) == "NOERROR"
    assert du.has_flag(r, "AA")
    # Only one data RRset is returned (RRSIGs excepted).
    data_types = [t for t in du.section_types(r.answer) if t != "RRSIG"]
    assert len(data_types) == 1
    assert data_types[0] in ("A", "AAAA")
