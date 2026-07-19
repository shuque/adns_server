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


def test_any_query(query):
    """ANY returns the available data at the name."""
    r = query("www.deleg.test", "ANY", do=True)
    assert du.rcode(r) == "NOERROR"
    types = du.section_types(r.answer)
    assert "A" in types or "AAAA" in types
